//! Small Win32 helpers shared by the collectors.

use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, HWND};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_READ, REG_SZ,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, RegisterClassW,
    HWND_MESSAGE, WNDCLASSW, WNDPROC,
};

/// NUL-terminated UTF-16 for a Win32 string parameter.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// UTF-16 up to the first NUL.
pub fn from_wide(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

/// `C:\Program Files\...\msedge.exe` -> `msedge`. Lowercase, so config lists match.
pub fn exe_name(path: &str) -> String {
    let base = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

/// Full image path of a process, or `None` if it exited or is protected.
pub fn process_image(pid: u32) -> Option<String> {
    // SAFETY: the handle is checked before use and closed on every path.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut n = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
    }
}

pub fn window_pid(hwnd: HWND) -> Option<u32> {
    if hwnd.is_null() {
        return None;
    }
    let mut pid = 0u32;
    // SAFETY: hwnd may be stale; the call then fails and leaves pid at 0.
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    (pid != 0).then_some(pid)
}

pub fn class_name(hwnd: HWND) -> String {
    let mut buf = [0u16; 256];
    // SAFETY: the buffer length is passed; a stale hwnd returns 0.
    let n = unsafe { GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

pub fn window_text(hwnd: HWND) -> String {
    let mut buf = [0u16; 256];
    // SAFETY: as above.
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

/// A hidden window for receiving messages. `message_only` windows (HWND_MESSAGE) get
/// clipboard notifications but no broadcasts; the tray icon needs an ordinary hidden one.
pub fn hidden_window(class: &str, proc: WNDPROC, message_only: bool) -> Result<HWND, String> {
    let cls = wide(class);
    // SAFETY: the class name outlives both calls; registering an existing class fails
    // harmlessly and CreateWindowExW then uses the earlier registration.
    unsafe {
        let hinst = GetModuleHandleW(null());
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = proc;
        wc.hInstance = hinst;
        wc.lpszClassName = cls.as_ptr();
        RegisterClassW(&wc);
        let parent = if message_only {
            HWND_MESSAGE
        } else {
            null_mut()
        };
        let hwnd = CreateWindowExW(
            0,
            cls.as_ptr(),
            cls.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            parent,
            null_mut(),
            hinst,
            null(),
        );
        if hwnd.is_null() {
            Err(format!(
                "CreateWindowExW({class}): {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(hwnd)
        }
    }
}

/// Last-write time of a key under HKEY_CURRENT_USER (FILETIME as u64). Changes whenever
/// any value in the key is written, even with identical data.
pub fn user_key_write_time(subkey: &str) -> Option<u64> {
    let sk = wide(subkey);
    // SAFETY: only the FILETIME out-pointer is used; the key is closed on every path.
    unsafe {
        let mut key: HKEY = null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, sk.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let mut ft: windows_sys::Win32::Foundation::FILETIME = std::mem::zeroed();
        let rc = RegQueryInfoKeyW(
            key,
            null_mut(),
            null_mut(),
            null(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut ft,
        );
        RegCloseKey(key);
        (rc == 0).then_some(((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64)
    }
}

/// A REG_SZ value under HKEY_CURRENT_USER.
pub fn read_user_string(subkey: &str, value: &str) -> Option<String> {
    let (sk, v) = (wide(subkey), wide(value));
    // SAFETY: sizes come from the first query; the key is closed on every path.
    unsafe {
        let mut key: HKEY = null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, sk.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let mut ty = 0u32;
        let mut size = 0u32;
        let mut out = None;
        if RegQueryValueExW(key, v.as_ptr(), null(), &mut ty, null_mut(), &mut size) == 0
            && ty == REG_SZ
            && size > 0
        {
            let mut buf = vec![0u16; size as usize / 2 + 1];
            let mut size2 = (buf.len() * 2) as u32;
            if RegQueryValueExW(
                key,
                v.as_ptr(),
                null(),
                &mut ty,
                buf.as_mut_ptr().cast(),
                &mut size2,
            ) == 0
            {
                out = Some(from_wide(&buf));
            }
        }
        RegCloseKey(key);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_strings() {
        assert_eq!(
            exe_name(r"C:\Program Files\Google\Chrome\chrome.exe"),
            "chrome"
        );
        assert_eq!(exe_name("KeePassXC.exe"), "keepassxc");
        assert_eq!(from_wide(&wide("héllo")), "héllo");
    }
}
