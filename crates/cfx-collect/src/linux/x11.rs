//! X11 clipboard watcher (XFixes) and owner (for block mode).

use super::procfs::proc_info;
use crate::{ClipboardEvent, SourceApp};
use std::collections::VecDeque;
use std::error::Error;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime};
use x11rb::connection::Connection;
use x11rb::protocol::res::{ClientIdMask, ClientIdSpec, ConnectionExt as _};
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    self, Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, Window,
    WindowClass,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::COPY_DEPTH_FROM_PARENT;

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

struct Atoms {
    clipboard: Atom,
    utf8: Atom,
    targets: Atom,
    incr: Atom,
    prop: Atom,
    chromium_url: Atom,
    moz_url: Atom,
}

fn intern(conn: &RustConnection, name: &str) -> Res<Atom> {
    Ok(conn.intern_atom(false, name.as_bytes())?.reply()?.atom)
}

fn atoms(conn: &RustConnection) -> Res<Atoms> {
    Ok(Atoms {
        clipboard: intern(conn, "CLIPBOARD")?,
        utf8: intern(conn, "UTF8_STRING")?,
        targets: intern(conn, "TARGETS")?,
        incr: intern(conn, "INCR")?,
        prop: intern(conn, "CFX_SELECTION")?,
        chromium_url: intern(conn, "chromium/x-source-url")?,
        moz_url: intern(conn, "text/x-moz-url-priv")?,
    })
}

fn hidden_window(conn: &RustConnection, screen: usize) -> Res<Window> {
    let root = conn.setup().roots[screen].root;
    let win = conn.generate_id()?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        win,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )?;
    Ok(win)
}

/// PID of the X client owning `window`, via the X-Resource extension. Reliable for local
/// clients; does not depend on the app setting _NET_WM_PID on a hidden selection window.
fn owner_pid(conn: &RustConnection, window: Window) -> Option<u32> {
    let reply = conn
        .res_query_client_ids(&[ClientIdSpec {
            client: window,
            mask: ClientIdMask::LOCAL_CLIENT_PID,
        }])
        .ok()?
        .reply()
        .ok()?;
    reply.ids.iter().find_map(|id| id.value.first().copied())
}

pub fn watch(tx: Sender<ClipboardEvent>, max_bytes: usize) -> Res<()> {
    let (conn, screen) = x11rb::connect(None)?;
    conn.xfixes_query_version(5, 0)?.reply()?;
    conn.res_query_version(1, 2)?.reply()?;
    let a = atoms(&conn)?;
    let win = hidden_window(&conn, screen)?;
    conn.xfixes_select_selection_input(win, a.clipboard, SelectionEventMask::SET_SELECTION_OWNER)?;
    conn.flush()?;
    tracing::info!("x11 clipboard watcher running");
    let me = std::process::id();
    let mut pending: VecDeque<Event> = VecDeque::new();

    loop {
        let ev = match pending.pop_front() {
            Some(e) => e,
            None => conn.wait_for_event()?,
        };
        let Event::XfixesSelectionNotify(n) = ev else {
            continue;
        };
        if n.owner == x11rb::NONE {
            continue;
        }
        let pid = owner_pid(&conn, n.owner);
        if pid == Some(me) {
            continue; // our own block-mode replacement
        }
        let source = match pid {
            Some(p) => {
                let (name, exe) = proc_info(p);
                SourceApp {
                    pid: Some(p),
                    name,
                    exe,
                }
            }
            None => SourceApp::default(),
        };
        let Some((bytes, truncated)) =
            fetch(&conn, win, &a, a.utf8, n.timestamp, max_bytes, &mut pending)?
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let url = [a.chromium_url, a.moz_url].iter().find_map(|t| {
            fetch(&conn, win, &a, *t, n.timestamp, 4096, &mut pending)
                .ok()
                .flatten()
                .map(|(b, _)| {
                    String::from_utf8_lossy(&b)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                })
                .filter(|s| s.starts_with("http"))
        });
        let ev = ClipboardEvent {
            text,
            source,
            source_url: url,
            truncated,
            timestamp: SystemTime::now(),
        };
        if tx.send(ev).is_err() {
            return Ok(());
        }
    }
}

/// Request the selection in `target` form and wait (bounded) for the reply. Other events
/// that arrive meanwhile are queued, not dropped.
fn fetch(
    conn: &RustConnection,
    win: Window,
    a: &Atoms,
    target: Atom,
    time: u32,
    max_bytes: usize,
    pending: &mut VecDeque<Event>,
) -> Res<Option<(Vec<u8>, bool)>> {
    conn.convert_selection(win, a.clipboard, target, a.prop, time)?;
    conn.flush()?;
    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        match conn.poll_for_event()? {
            Some(Event::SelectionNotify(s)) if s.requestor == win => {
                if s.property == x11rb::NONE {
                    return Ok(None);
                }
                let words = (max_bytes / 4 + 1) as u32;
                let reply = conn
                    .get_property(true, win, a.prop, AtomEnum::ANY, 0, words)?
                    .reply()?;
                if reply.type_ == a.incr {
                    tracing::debug!("clipboard uses INCR transfer; skipped (too large)");
                    return Ok(None);
                }
                let truncated = reply.bytes_after > 0;
                let mut v = reply.value;
                v.truncate(max_bytes);
                return Ok(Some((v, truncated)));
            }
            Some(other) => pending.push_back(other),
            None => {
                if Instant::now() > deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

/// Take ownership of CLIPBOARD and serve `text` until another client takes it back.
/// Runs on its own thread and connection; returns once ownership is confirmed.
pub fn own_clipboard(text: String) -> Res<()> {
    let (conn, screen) = x11rb::connect(None)?;
    let a = atoms(&conn)?;
    let win = hidden_window(&conn, screen)?;
    conn.set_selection_owner(win, a.clipboard, x11rb::CURRENT_TIME)?;
    let owner = conn.get_selection_owner(a.clipboard)?.reply()?.owner;
    if owner != win {
        return Err("could not take clipboard ownership".into());
    }
    conn.flush()?;
    std::thread::Builder::new()
        .name("cfx-clipboard-owner".into())
        .spawn(move || {
            let string = AtomEnum::STRING.into();
            loop {
                let Ok(ev) = conn.wait_for_event() else {
                    return;
                };
                match ev {
                    Event::SelectionRequest(req) => {
                        let prop = if req.property == x11rb::NONE {
                            req.target
                        } else {
                            req.property
                        };
                        let ok = if req.target == a.targets {
                            let list = [a.targets, a.utf8, string];
                            conn.change_property32(
                                PropMode::REPLACE,
                                req.requestor,
                                prop,
                                AtomEnum::ATOM,
                                &list,
                            )
                            .is_ok()
                        } else if req.target == a.utf8 || req.target == string {
                            conn.change_property8(
                                PropMode::REPLACE,
                                req.requestor,
                                prop,
                                req.target,
                                text.as_bytes(),
                            )
                            .is_ok()
                        } else {
                            false
                        };
                        let notify = xproto::SelectionNotifyEvent {
                            response_type: xproto::SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: req.time,
                            requestor: req.requestor,
                            selection: req.selection,
                            target: req.target,
                            property: if ok { prop } else { x11rb::NONE },
                        };
                        let _ = conn.send_event(false, req.requestor, EventMask::NO_EVENT, notify);
                        let _ = conn.flush();
                    }
                    Event::SelectionClear(_) => return,
                    _ => {}
                }
            }
        })?;
    Ok(())
}
