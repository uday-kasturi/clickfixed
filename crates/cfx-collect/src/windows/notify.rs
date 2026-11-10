//! Notifications through a tray icon balloon, which Windows 10 and 11 show as a toast.
//!
//! One background thread owns a hidden window and the tray icon. Callers only send on a
//! channel, so a notification never blocks a signal thread.

use super::util::hidden_window;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_TIP, NIIF_ERROR, NIIF_WARNING, NIM_ADD, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{DefWindowProcW, LoadIconW, IDI_WARNING};

type Note = (String, String, bool);

static NOTIFIER: OnceLock<Mutex<Option<Sender<Note>>>> = OnceLock::new();

pub fn notify(title: &str, body: &str, urgent: bool) {
    let slot = NOTIFIER.get_or_init(|| {
        let (tx, rx) = channel::<Note>();
        let started = std::thread::Builder::new()
            .name("cfx-win-notify".into())
            .spawn(move || run(rx))
            .is_ok();
        Mutex::new(started.then_some(tx))
    });
    if let Some(tx) = slot.lock().unwrap().as_ref() {
        let _ = tx.send((title.to_string(), body.to_string(), urgent));
    }
}

fn copy_into(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

fn run(rx: std::sync::mpsc::Receiver<Note>) {
    let hwnd = match hidden_window("clickfixed_notify", Some(DefWindowProcW), false) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "notifications disabled");
            return;
        }
    };
    // SAFETY: NOTIFYICONDATAW is plain data; cbSize marks the full struct version.
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_TIP;
    // SAFETY: a stock system icon; no module handle needed.
    nid.hIcon = unsafe { LoadIconW(std::ptr::null_mut(), IDI_WARNING) };
    copy_into(&mut nid.szTip, "clickfixed");
    // SAFETY: nid is fully initialised and hwnd is live.
    if unsafe { Shell_NotifyIconW(NIM_ADD, &nid) } == 0 {
        tracing::error!("tray icon could not be added; notifications disabled");
        return;
    }
    for (title, body, urgent) in rx {
        nid.uFlags = NIF_INFO;
        copy_into(&mut nid.szInfoTitle, &title);
        copy_into(&mut nid.szInfo, &body);
        nid.dwInfoFlags = if urgent { NIIF_ERROR } else { NIIF_WARNING };
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
    }
}
