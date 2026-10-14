//! The companion's socket server: listens for relay connections and checks the peer and caller.

use super::*;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::Ordering;

impl Bridge {
    /// Listen on `path` (in a 0700 directory, socket 0600). Refuses to take over a socket another
    /// running companion still serves.
    pub fn serve(self: &Arc<Self>, path: &Path) -> Result<(), String> {
        let result = (|| {
            let dir = path.parent().ok_or("bad socket path")?;
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if !meta.file_type().is_socket() {
                    return Err(format!("{} exists and is not a socket", path.display()));
                }
                if UnixStream::connect(path).is_ok() {
                    return Err("another Phone Vault Companion is already serving the browser connection".into());
                }
                std::fs::remove_file(path).map_err(|e| e.to_string())?;
            }
            let listener = UnixListener::bind(path).map_err(|e| format!("could not open {}: {e}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
            Ok(listener)
        })();
        let listener = match result {
            Ok(l) => {
                let mut g = self.lock();
                g.listening = Some(path.to_path_buf());
                g.listen_error = None;
                l
            }
            Err(e) => {
                let mut g = self.lock();
                g.listening = None;
                g.listen_error = Some(e.clone());
                return Err(e);
            }
        };
        let me = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let me = me.clone();
                std::thread::spawn(move || me.handle_conn(stream));
            }
        });
        Ok(())
    }

    fn handle_conn(self: Arc<Self>, stream: UnixStream) {
        if peer_check(&stream).is_err() {
            return;
        }
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut reader = match stream.try_clone() {
            Ok(r) => r,
            Err(_) => return,
        };
        // First frame: the relay says which extension Chrome/Firefox started it for.
        let caller = match read_frame(&mut reader, 4096) {
            Ok(Some(b)) => serde_json::from_slice::<Value>(&b)
                .ok()
                .filter(|v| v["type"] == "relay_hello")
                .and_then(|v| v["caller"].as_str().map(str::to_string)),
            _ => None,
        };
        if !caller.is_some_and(|c| allowed_caller(&c)) {
            return;
        }
        let _ = reader.set_read_timeout(None);
        let id = self.next_conn.fetch_add(1, Ordering::SeqCst);
        self.lock().conns.insert(id, Conn { writer: Arc::new(Mutex::new(stream)) });
        (self.notify)();
        while let Ok(Some(body)) = read_frame(&mut reader, MAX_IN_FRAME) {
            if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                self.on_message(id, &v);
            }
        }
        {
            let mut g = self.lock();
            g.conns.remove(&id);
            g.pending.retain(|p| p.conn != id);
        }
        (self.notify)();
    }
}

/// Callers the relay may speak for: the pinned Chrome extension or the Firefox add-on.
pub fn allowed_caller(caller: &str) -> bool {
    caller == format!("chrome-extension://{CHROME_EXTENSION_ID}/")
        || caller == format!("firefox:{FIREFOX_EXTENSION_ID}")
}

/// The socket peer must be this user and this executable (the relay is this binary started by the
/// browser as the native host). Defence in depth: same-user code could still start the relay itself,
/// which is why nothing the bridge accepts can sign without the phone.
fn peer_check(stream: &UnixStream) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let (mut uid, mut gid) = (0, 0);
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != unsafe { libc::getuid() } {
            return Err("socket peer is another user".into());
        }
        let mut pid: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } != 0
        {
            return Err("no peer pid".into());
        }
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
        if n <= 0 {
            return Err("no peer path".into());
        }
        let peer = PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..n as usize]));
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        if !same_file(&peer, &me) {
            return Err(format!("socket peer {} is not this app", peer.display()));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        Ok(())
    }
}

pub fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}
