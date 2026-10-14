//! The native messaging host: this executable started by the browser, relaying frames to the
//! running companion.

use super::{allowed_caller, read_frame, write_frame, FIREFOX_EXTENSION_ID, MAX_IN_FRAME, MAX_OUT_FRAME};
use serde_json::json;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub fn socket_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("PHONEVAULT_BRIDGE_SOCKET") {
        return Some(PathBuf::from(p));
    }
    dirs::config_dir().map(|d| d.join("PhoneVault").join("bridge.sock"))
}

/// Chrome starts the host with the calling extension's origin as the first argument
/// ("chrome-extension://<id>/"); Firefox with the manifest path and then the add-on ID.
pub fn native_host_caller(args: &[String]) -> Option<String> {
    let a1 = args.get(1)?;
    if a1.starts_with("chrome-extension://") {
        return Some(a1.clone());
    }
    if a1.ends_with(".json") {
        if let Some(id) = args.get(2) {
            if id == FIREFOX_EXTENSION_ID {
                return Some(format!("firefox:{id}"));
            }
        }
    }
    None
}

/// Run as the native messaging host: relay frames between the browser (stdin/stdout) and the
/// running companion. Never parses or acts on requests itself.
pub fn native_host_main(caller: String) -> i32 {
    let mut out = std::io::stdout();
    if !allowed_caller(&caller) {
        let _ = write_frame(&mut out, br#"{"type":"hello","ok":false,"error":"wrong_extension","message":"This browser connection is installed for a different extension ID."}"#, MAX_OUT_FRAME);
        return 1;
    }
    let stream = socket_path().and_then(|p| UnixStream::connect(p).ok());
    let Some(mut sock) = stream else {
        let _ = write_frame(&mut out, br#"{"type":"hello","ok":false,"error":"companion_not_running","message":"Phone Vault Companion is not running. Open it on this Mac."}"#, MAX_OUT_FRAME);
        return 0;
    };
    let hello = json!({"type": "relay_hello", "caller": caller}).to_string();
    if write_frame(&mut sock, hello.as_bytes(), 4096).is_err() {
        return 1;
    }
    let mut from_app = match sock.try_clone() {
        Ok(s) => s,
        Err(_) => return 1,
    };
    std::thread::spawn(move || {
        let mut out = std::io::stdout();
        loop {
            match read_frame(&mut from_app, MAX_OUT_FRAME) {
                Ok(Some(b)) => {
                    if write_frame(&mut out, &b, MAX_OUT_FRAME).is_err() {
                        std::process::exit(0);
                    }
                }
                _ => std::process::exit(0),
            }
        }
    });
    let mut input = std::io::stdin();
    loop {
        match read_frame(&mut input, MAX_IN_FRAME) {
            Ok(Some(b)) => {
                if write_frame(&mut sock, &b, MAX_IN_FRAME).is_err() {
                    return 0;
                }
            }
            Ok(None) => return 0,
            Err(_) => return 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::CHROME_EXTENSION_ID;

    #[test]
    fn native_host_callers() {
        let a = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
        let chrome = format!("chrome-extension://{CHROME_EXTENSION_ID}/");
        assert_eq!(native_host_caller(&a(&["companion", &chrome])), Some(chrome.clone()));
        assert!(allowed_caller(&chrome));
        assert!(!allowed_caller("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"));
        assert_eq!(
            native_host_caller(&a(&["companion", "/x/dev.phonevault.json", FIREFOX_EXTENSION_ID])),
            Some(format!("firefox:{FIREFOX_EXTENSION_ID}"))
        );
        assert_eq!(native_host_caller(&a(&["companion", "/x/dev.phonevault.json", "evil@x"])), None);
        assert_eq!(native_host_caller(&a(&["companion"])), None);
        assert_eq!(native_host_caller(&a(&["companion", "--some-flag"])), None);
    }
}
