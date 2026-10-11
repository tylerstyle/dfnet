//! dfnet actions in the dfnix audit log (dfcore). Logging failures are reported
//! but never stop an acquisition or a network change that already happened.

pub use dfcore::audit::Event;

pub const TOOL: &str = "dfnet";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Flags whose values are secrets (the hotspot WPA2 passphrase)
const SECRET_FLAGS: &[&str] = &["--password", "-p"];

pub fn event(action: &str) -> Event {
    Event::new(TOOL, VERSION, action).redact(SECRET_FLAGS)
}

/// Append a record; returns its hash.
pub fn record(event: Event) -> Option<String> {
    match dfcore::audit::append(event) {
        Ok(rec) => rec.hash,
        Err(e) => {
            eprintln!("[!] WARNING: audit log not written: {e:#}");
            None
        }
    }
}
