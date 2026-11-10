//! Put text on the clipboard (and on X11, serve it for a few seconds). Demo/testing aid.
//!   cargo run -p cfx-collect --example set_clipboard -- "git status" 3
use cfx_collect::ClipboardControl;

fn main() {
    let mut args = std::env::args().skip(1);
    let text = args.next().expect("usage: set_clipboard <text> [seconds]");
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    #[cfg(target_os = "linux")]
    let control = cfx_collect::linux::LinuxCollector::default();
    #[cfg(windows)]
    let control = cfx_collect::windows::WindowsCollector::default();
    control.replace_clipboard(text).expect("own clipboard");
    std::thread::sleep(std::time::Duration::from_secs(secs));
}
