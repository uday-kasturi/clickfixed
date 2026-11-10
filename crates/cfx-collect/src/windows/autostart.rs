//! Start clickfixed at login through `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//!
//! A Windows service runs in session 0, which has no access to the user's clipboard or
//! foreground window, so clickfixed runs as the user instead. No administrator rights
//! are needed.

use super::util::{read_user_string, wide};
use std::ptr::null_mut;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_SET_VALUE, REG_SZ,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE: &str = "clickfixed";

fn with_key<T>(f: impl FnOnce(HKEY) -> Result<T, String>) -> Result<T, String> {
    let sk = wide(RUN_KEY);
    let mut key: HKEY = null_mut();
    // SAFETY: the key is closed after use.
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sk.as_ptr(), 0, KEY_SET_VALUE, &mut key) };
    if rc != 0 {
        return Err(format!("open HKCU\\{RUN_KEY}: error {rc}"));
    }
    let out = f(key);
    // SAFETY: key is open.
    unsafe { RegCloseKey(key) };
    out
}

/// Register `command` to run at login, replacing any earlier entry.
pub fn enable(command: &str) -> Result<(), String> {
    let (name, data) = (wide(VALUE), wide(command));
    with_key(|key| {
        // SAFETY: data is NUL-terminated UTF-16 and its byte length includes the NUL.
        let rc = unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("write autostart entry: error {rc}"))
        }
    })
}

pub fn disable() -> Result<(), String> {
    let name = wide(VALUE);
    with_key(|key| {
        // SAFETY: name is NUL-terminated.
        let rc = unsafe { RegDeleteValueW(key, name.as_ptr()) };
        // 2 = ERROR_FILE_NOT_FOUND: already disabled.
        if rc == 0 || rc == 2 {
            Ok(())
        } else {
            Err(format!("remove autostart entry: error {rc}"))
        }
    })
}

/// The registered command, if autostart is on.
pub fn status() -> Option<String> {
    read_user_string(RUN_KEY, VALUE)
}
