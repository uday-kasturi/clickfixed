//! Syslog in CEF (ArcSight Common Event Format), over the local socket, UDP or TCP.

use super::Output;
use crate::config::{facility_code, SyslogConfig, SyslogFormat, SyslogTransport};
use crate::schema::Alert;
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

const MAX_MSG: usize = 1024;
const MAX_DATAGRAM: usize = 8192;

enum Transport {
    Unix(String),
    Udp(UdpSocket),
    Tcp(String, Option<TcpStream>),
}

pub struct Syslog {
    transport: Transport,
    format: SyslogFormat,
    facility: u8,
    host: String,
}

impl Syslog {
    pub fn new(cfg: &SyslogConfig, host: &str) -> Result<Self, String> {
        let facility = facility_code(&cfg.facility).ok_or_else(|| {
            format!(
                "outputs.syslog.facility: unknown facility {:?}",
                cfg.facility
            )
        })?;
        let transport = match cfg.transport {
            SyslogTransport::Unix => Transport::Unix(cfg.address.clone()),
            SyslogTransport::Udp => {
                let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("syslog udp: {e}"))?;
                s.connect(&cfg.address)
                    .map_err(|e| format!("outputs.syslog.address {}: {e}", cfg.address))?;
                Transport::Udp(s)
            }
            SyslogTransport::Tcp => Transport::Tcp(cfg.address.clone(), None),
        };
        let format = cfg.format.unwrap_or(match cfg.transport {
            SyslogTransport::Unix => SyslogFormat::Rfc3164,
            _ => SyslogFormat::Rfc5424,
        });
        Ok(Self {
            transport,
            format,
            facility,
            host: host.to_string(),
        })
    }

    fn frame(&self, alert: &Alert) -> String {
        let pri = self.facility as u16 * 8 + alert.clickfixed.severity.syslog as u16;
        let pid = std::process::id();
        let cef = cef(alert);
        match (&self.format, &self.transport) {
            // Local socket: the daemon (rsyslog/journald) adds the hostname itself.
            (SyslogFormat::Rfc3164, Transport::Unix(_)) => {
                format!("<{pri}>{} clickfixed[{pid}]: {cef}", bsd_time(alert))
            }
            (SyslogFormat::Rfc3164, _) => {
                format!(
                    "<{pri}>{} {} clickfixed[{pid}]: {cef}",
                    bsd_time(alert),
                    self.host
                )
            }
            (SyslogFormat::Rfc5424, _) => format!(
                "<{pri}>1 {} {} clickfixed {pid} {} - {cef}",
                alert.timestamp,
                self.host,
                alert.event.action.as_str()
            ),
        }
    }
}

fn bsd_time(alert: &Alert) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(alert.epoch_ms / 1000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    t.format(time::macros::format_description!(
        "[month repr:short] [day padding:space] [hour]:[minute]:[second]"
    ))
    .unwrap_or_default()
}

impl Output for Syslog {
    fn name(&self) -> &str {
        "syslog"
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let mut msg = self.frame(alert);
        match &mut self.transport {
            Transport::Unix(path) => {
                truncate(&mut msg, MAX_DATAGRAM);
                let s = UnixDatagram::unbound().map_err(|e| format!("syslog: {e}"))?;
                s.send_to(msg.as_bytes(), &*path)
                    .map(|_| ())
                    .map_err(|e| format!("syslog {path}: {e}"))
            }
            Transport::Udp(s) => {
                truncate(&mut msg, MAX_DATAGRAM);
                s.send(msg.as_bytes())
                    .map(|_| ())
                    .map_err(|e| format!("syslog udp: {e}"))
            }
            Transport::Tcp(addr, conn) => {
                msg.push('\n'); // newline framing; CEF escapes embedded newlines
                for attempt in 0..2 {
                    if conn.is_none() {
                        let s = TcpStream::connect(&*addr)
                            .map_err(|e| format!("syslog tcp {addr}: {e}"))?;
                        s.set_write_timeout(Some(Duration::from_secs(5))).ok();
                        *conn = Some(s);
                    }
                    match conn.as_mut().unwrap().write_all(msg.as_bytes()) {
                        Ok(()) => return Ok(()),
                        Err(e) if attempt == 1 => return Err(format!("syslog tcp {addr}: {e}")),
                        Err(_) => *conn = None,
                    }
                }
                unreachable!()
            }
        }
    }
}

fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn esc_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn esc_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension`
pub fn cef(alert: &Alert) -> String {
    let d = &alert.clickfixed;
    let action = alert.event.action.as_str();
    let mut ext: Vec<(&str, String)> = vec![
        ("rt", alert.epoch_ms.to_string()),
        ("externalId", alert.event.id.clone()),
        ("act", action.to_string()),
        ("cat", "T1204.004".into()),
        ("dvchost", alert.host.name.clone()),
        ("suser", alert.user.name.clone()),
        ("cfp1Label", "score".into()),
        ("cfp1", format!("{:.3}", d.score)),
        ("cs1Label", "commandSha256".into()),
        ("cs1", d.command.sha256.clone()),
        ("cs2Label", "dedupeKey".into()),
        ("cs2", d.dedupe_key.clone()),
        ("cs3Label", "features".into()),
        (
            "cs3",
            d.features
                .iter()
                .filter(|f| f.weight > 0.0)
                .map(|f| format!("{}:{:.2}", f.id, f.weight))
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("cs4Label", "dampenedBy".into()),
        (
            "cs4",
            d.dampened_by
                .iter()
                .map(|x| format!("{}:{}:-{:.2}", x.entry, x.feature, x.amount))
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("cs5Label", "analytic".into()),
        ("cs5", d.analytic.id.into()),
        ("cs6Label", "verdict".into()),
        ("cs6", format!("{}/{}", d.verdict.as_str(), d.severity.name)),
        ("flexString1Label", "originDomainClass".into()),
        ("flexString1", d.origin.domain_class.into()),
    ];
    if let Some(u) = &alert.url {
        ext.push(("request", u.full.clone()));
    }
    if let Some(app) = &d.origin.source_app {
        ext.push(("sourceServiceName", app.clone()));
    }
    if let Some(p) = &alert.process {
        ext.push(("spid", p.pid.to_string()));
        if let Some(n) = &p.name {
            ext.push(("sproc", n.clone()));
        }
    }
    if let Some(dec) = &d.command.decoded {
        let mut m = dec.clone();
        truncate(&mut m, MAX_MSG);
        ext.push(("msg", m));
    }
    let ext = ext
        .into_iter()
        .map(|(k, v)| format!("{k}={}", esc_ext(&v)))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "CEF:0|clickfixed|clickfixed|{}|{}|{}|{}|{ext}",
        esc_header(env!("CARGO_PKG_VERSION")),
        esc_header(&format!("clickfixed:{action}")),
        esc_header(&format!(
            "ClickFix {}: {}",
            d.verdict.as_str(),
            alert.rule.name
        )),
        d.severity.cef,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn escaping() {
        assert_eq!(super::esc_ext("a=b\\c\nd"), "a\\=b\\\\c\\nd");
        assert_eq!(super::esc_header("a|b"), "a\\|b");
    }
}
