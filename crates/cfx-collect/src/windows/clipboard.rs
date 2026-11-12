//! Clipboard listener and writer.
//!
//! `AddClipboardFormatListener` posts WM_CLIPBOARDUPDATE to a hidden window after every
//! change. The window that owns the clipboard (`GetClipboardOwner`) belongs to the process
//! that wrote it, which is how a browser copy is told apart from any other app.
//!
//! Browsers also attach the page the copy came from, as best-effort extra formats:
//! - Chromium (Chrome, Edge, Brave, Opera, Vivaldi): `Chromium internal source URL`
//! - Firefox: `text/x-moz-url-priv`
//! - any app that also writes HTML: the `SourceURL:` header of `HTML Format`

use super::util::{exe_name, hidden_window, process_image, wide, window_pid};
use crate::{ClipboardEvent, SourceApp};
use std::cell::RefCell;
use std::ptr::null_mut;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};
use windows_sys::Win32::Foundation::{GlobalFree, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::DataExchange::{
    AddClipboardFormatListener, CloseClipboard, EmptyClipboard, GetClipboardData,
    GetClipboardOwner, GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostQuitMessage, MSG,
    WM_CLIPBOARDUPDATE,
};

/// Clipboard sequence number of our own last block-mode write. The writer window is
/// destroyed right after writing, so the owner check alone can't recognise it.
static OWN_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Longest page URL read from a source-URL format.
const MAX_URL_BYTES: usize = 8 * 1024;

struct State {
    tx: Sender<ClipboardEvent>,
    hwnd: HWND,
    max_bytes: usize,
    last_seq: u32,
    url_formats: [u32; 2],
    html_format: u32,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_CLIPBOARDUPDATE {
        STATE.with(|s| {
            if let Some(st) = s.borrow_mut().as_mut() {
                on_update(st);
            }
        });
        return 0;
    }
    // SAFETY: default handling for every other message.
    unsafe { DefWindowProcW(hwnd, msg, w, l) }
}

pub fn watch(tx: Sender<ClipboardEvent>, max_bytes: usize) -> Result<(), String> {
    let hwnd = hidden_window("clickfixed_clipboard", Some(wndproc), true)?;
    let fmt = |name: &str| {
        let w = wide(name);
        // SAFETY: NUL-terminated name.
        unsafe { RegisterClipboardFormatW(w.as_ptr()) }
    };
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            tx,
            hwnd,
            max_bytes,
            last_seq: 0,
            url_formats: [
                fmt("Chromium internal source URL"),
                fmt("text/x-moz-url-priv"),
            ],
            html_format: fmt("HTML Format"),
        })
    });
    // SAFETY: hwnd is a live window owned by this thread.
    if unsafe { AddClipboardFormatListener(hwnd) } == 0 {
        return Err(format!(
            "AddClipboardFormatListener: {}",
            std::io::Error::last_os_error()
        ));
    }
    tracing::info!("windows clipboard listener running");
    // SAFETY: standard message loop on the thread that owns hwnd.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

fn on_update(st: &mut State) {
    // SAFETY: no preconditions.
    let seq = unsafe { GetClipboardSequenceNumber() };
    if seq == st.last_seq {
        return;
    }
    st.last_seq = seq;
    if seq == OWN_SEQ.load(std::sync::atomic::Ordering::SeqCst) {
        return; // our own block-mode replacement
    }
    // SAFETY: returns NULL when no window owns the clipboard.
    let owner = unsafe { GetClipboardOwner() };
    let pid = window_pid(owner);
    if pid == Some(std::process::id()) {
        return; // our own block-mode replacement
    }
    let exe = pid.and_then(process_image);
    let source = SourceApp {
        pid,
        name: exe.as_deref().map(exe_name),
        exe,
    };
    let Some(_guard) = open_clipboard(st.hwnd) else {
        tracing::warn!("clipboard busy; change skipped");
        return;
    };
    let Some((text, truncated)) = read_text(st.max_bytes) else {
        return;
    };
    let source_url = st
        .url_formats
        .iter()
        .find_map(|&f| read_bytes(f, MAX_URL_BYTES).and_then(|b| url_from(&b)))
        .or_else(|| read_bytes(st.html_format, 4096).and_then(|b| html_source_url(&b)));
    let ev = ClipboardEvent {
        text,
        source,
        source_url,
        truncated,
        timestamp: SystemTime::now(),
    };
    if st.tx.send(ev).is_err() {
        // SAFETY: ends this thread's message loop.
        unsafe { PostQuitMessage(0) };
    }
}

/// Closes the clipboard when dropped.
struct Open;
impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: only constructed after a successful OpenClipboard.
        unsafe { CloseClipboard() };
    }
}

/// Another process can hold the clipboard for a moment after writing; retry briefly.
fn open_clipboard(hwnd: HWND) -> Option<Open> {
    for _ in 0..20 {
        // SAFETY: hwnd is a live window.
        if unsafe { OpenClipboard(hwnd) } != 0 {
            return Some(Open);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

/// CF_UNICODETEXT, capped at `max_bytes` of UTF-8. Caller holds the clipboard open.
fn read_text(max_bytes: usize) -> Option<(String, bool)> {
    // SAFETY: the clipboard is open; the global memory is locked only while read.
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT as u32) == 0 {
            return None;
        }
        let h = GetClipboardData(CF_UNICODETEXT as u32);
        if h.is_null() {
            return None;
        }
        let p = GlobalLock(h) as *const u16;
        if p.is_null() {
            return None;
        }
        let units = GlobalSize(h) / 2;
        let slice = std::slice::from_raw_parts(p, units);
        let n = slice.iter().position(|&c| c == 0).unwrap_or(units);
        let mut text = String::from_utf16_lossy(&slice[..n]);
        GlobalUnlock(h);
        let truncated = text.len() > max_bytes;
        if truncated {
            let mut cut = max_bytes;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
        }
        (!text.is_empty()).then_some((text, truncated))
    }
}

/// Raw bytes of a registered format, if present. Caller holds the clipboard open.
fn read_bytes(format: u32, max: usize) -> Option<Vec<u8>> {
    if format == 0 {
        return None;
    }
    // SAFETY: as in read_text.
    unsafe {
        if IsClipboardFormatAvailable(format) == 0 {
            return None;
        }
        let h = GetClipboardData(format);
        if h.is_null() {
            return None;
        }
        let p = GlobalLock(h) as *const u8;
        if p.is_null() {
            return None;
        }
        let n = GlobalSize(h).min(max);
        let out = std::slice::from_raw_parts(p, n).to_vec();
        GlobalUnlock(h);
        Some(out)
    }
}

/// The URL in a source-URL format: UTF-16 or UTF-8, first line only.
fn url_from(bytes: &[u8]) -> Option<String> {
    let utf16 = bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0;
    let text = if utf16 {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        super::util::from_wide(&units)
    } else {
        String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_string()
    };
    let url = text.lines().next()?.trim();
    (url.starts_with("http://") || url.starts_with("https://")).then(|| url.to_string())
}

/// `SourceURL:https://...` from the CF_HTML header.
fn html_source_url(bytes: &[u8]) -> Option<String> {
    let head = String::from_utf8_lossy(bytes);
    head.lines()
        .take_while(|l| !l.starts_with('<'))
        .find_map(|l| l.strip_prefix("SourceURL:"))
        .map(|u| u.trim().to_string())
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
}

/// Replace the clipboard with `text` (block mode).
pub fn replace(text: &str) -> Result<(), String> {
    let hwnd = hidden_window("clickfixed_clipboard_writer", Some(DefWindowProcW), true)?;
    let result = (|| {
        let _open = open_clipboard(hwnd).ok_or("clipboard busy")?;
        let w = wide(text);
        // SAFETY: the clipboard is open and owned by hwnd. On success the system owns the
        // memory; on failure it is freed here.
        unsafe {
            EmptyClipboard();
            let h = GlobalAlloc(GMEM_MOVEABLE, w.len() * 2);
            if h.is_null() {
                return Err("GlobalAlloc failed".to_string());
            }
            let p = GlobalLock(h) as *mut u16;
            if p.is_null() {
                GlobalFree(h);
                return Err("GlobalLock failed".to_string());
            }
            std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
            GlobalUnlock(h);
            if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                GlobalFree(h);
                return Err(format!(
                    "SetClipboardData: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    })();
    if result.is_ok() {
        // SAFETY: no preconditions.
        let seq = unsafe { GetClipboardSequenceNumber() };
        OWN_SEQ.store(seq, std::sync::atomic::Ordering::SeqCst);
    }
    // SAFETY: the window belongs to this thread and is no longer used.
    unsafe { DestroyWindow(hwnd) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_urls() {
        let u16: Vec<u8> = "https://evil.invalid/verify\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            url_from(&u16).as_deref(),
            Some("https://evil.invalid/verify")
        );
        assert_eq!(
            url_from(b"https://a.invalid/x\nPage title\0").as_deref(),
            Some("https://a.invalid/x")
        );
        assert!(url_from(b"javascript:alert(1)").is_none());
        let html = b"Version:0.9\r\nStartHTML:00000097\r\nSourceURL:https://docs.invalid/install\r\n<html>";
        assert_eq!(
            html_source_url(html).as_deref(),
            Some("https://docs.invalid/install")
        );
    }
}
