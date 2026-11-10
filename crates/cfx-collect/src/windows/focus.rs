//! Paste-target watcher: a WinEvent hook on foreground changes.
//!
//! A ClickFix page copies the command, then tells the user to press Win+R (or open a
//! terminal) and Ctrl+V. The copy alone doesn't say where it will be pasted; the window
//! that comes to the front next does. Reported here:
//! - the Run dialog: explorer.exe's `#32770` dialog with the Run combo box (control 12298)
//!   or the title "Run"
//! - terminals: Windows Terminal, console windows, PowerShell, cmd, and common emulators

use super::util::{class_name, exe_name, process_image, window_pid, window_text};
use crate::{PasteTarget, PasteTargetKind};
use std::cell::RefCell;
use std::ptr::null_mut;
use std::sync::mpsc::Sender;
use std::time::SystemTime;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetDlgItem, GetMessageW, PostQuitMessage, EVENT_SYSTEM_FOREGROUND, MSG,
    WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS,
};

/// The Run dialog's command combo box.
const RUN_COMBO_ID: i32 = 12298;

struct State {
    tx: Sender<PasteTarget>,
    last: HWND,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

unsafe extern "system" fn on_event(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    _id_child: i32,
    _thread: u32,
    _time: u32,
) {
    if event != EVENT_SYSTEM_FOREGROUND || id_object != 0 || hwnd.is_null() {
        return;
    }
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let Some(st) = s.as_mut() else { return };
        if st.last == hwnd {
            return;
        }
        st.last = hwnd;
        if let Some(t) = classify(hwnd) {
            if st.tx.send(t).is_err() {
                // SAFETY: ends this thread's message loop.
                unsafe { PostQuitMessage(0) };
            }
        }
    });
}

pub fn watch(tx: Sender<PasteTarget>) -> Result<(), String> {
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            tx,
            last: null_mut(),
        })
    });
    // SAFETY: out-of-context hook; callbacks arrive on this thread's message loop.
    unsafe {
        let hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            null_mut(),
            Some(on_event),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );
        if hook.is_null() {
            return Err(format!(
                "SetWinEventHook: {}",
                std::io::Error::last_os_error()
            ));
        }
        tracing::info!("windows paste-target watcher running");
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
        UnhookWinEvent(hook);
    }
    Ok(())
}

fn classify(hwnd: HWND) -> Option<PasteTarget> {
    let pid = window_pid(hwnd);
    let app = pid.and_then(process_image).map(|p| exe_name(&p));
    let class = class_name(hwnd);
    let kind = target_kind(&class, app.as_deref(), || is_run_dialog(hwnd))?;
    Some(PasteTarget {
        kind,
        pid,
        app,
        timestamp: SystemTime::now(),
    })
}

fn is_run_dialog(hwnd: HWND) -> bool {
    // SAFETY: GetDlgItem returns NULL for a stale window or a missing control.
    let combo = unsafe { GetDlgItem(hwnd, RUN_COMBO_ID) };
    !combo.is_null() || window_text(hwnd) == "Run"
}

/// Pure classification, separated from the Win32 calls for testing.
fn target_kind(
    class: &str,
    app: Option<&str>,
    run_dialog: impl FnOnce() -> bool,
) -> Option<PasteTargetKind> {
    if class == "#32770" && app == Some("explorer") && run_dialog() {
        return Some(PasteTargetKind::RunDialog);
    }
    let shell = match (class, app) {
        (_, Some("powershell" | "pwsh" | "powershell_ise")) => "powershell",
        (_, Some("cmd")) => "cmd",
        ("CASCADIA_HOSTING_WINDOW_CLASS", _) | (_, Some("windowsterminal" | "openconsole")) => {
            "windows_terminal"
        }
        ("ConsoleWindowClass", _) => "console",
        (
            _,
            Some("wsl" | "bash" | "mintty" | "alacritty" | "wezterm-gui" | "conemu64" | "conemu"),
        ) => "terminal",
        _ => return None,
    };
    Some(PasteTargetKind::Terminal {
        shell: shell.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paste_targets() {
        assert_eq!(
            target_kind("#32770", Some("explorer"), || true),
            Some(PasteTargetKind::RunDialog)
        );
        // Other explorer dialogs (file properties) are not the Run dialog.
        assert_eq!(target_kind("#32770", Some("explorer"), || false), None);
        assert_eq!(
            target_kind(
                "CASCADIA_HOSTING_WINDOW_CLASS",
                Some("windowsterminal"),
                || false
            ),
            Some(PasteTargetKind::Terminal {
                shell: "windows_terminal".into()
            })
        );
        assert_eq!(
            target_kind("ConsoleWindowClass", Some("powershell"), || false),
            Some(PasteTargetKind::Terminal {
                shell: "powershell".into()
            })
        );
        assert_eq!(
            target_kind("Chrome_WidgetWin_1", Some("chrome"), || false),
            None
        );
    }
}
