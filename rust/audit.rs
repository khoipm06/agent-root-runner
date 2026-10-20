use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

pub const PROD_AUDIT_PATH: &str = "/var/log/agent-root-runner/audit.log";

pub struct AuditLogger {
    file: Mutex<File>,
    #[cfg(test)]
    fail_next_event: AtomicBool,
    #[cfg(test)]
    fail_next_sync: AtomicBool,
}

impl AuditLogger {
    pub fn open(custom: Option<&str>, user_mode: bool) -> Result<Self, String> {
        let explicit_path =
            custom.is_some() || std::env::var_os("AGENT_ROOT_RUNNER_AUDIT_LOG").is_some();
        let path = if let Some(path) = custom {
            PathBuf::from(path)
        } else if let Ok(path) = std::env::var("AGENT_ROOT_RUNNER_AUDIT_LOG") {
            PathBuf::from(path)
        } else if unsafe { libc::geteuid() } == 0 && !user_mode {
            PathBuf::from(PROD_AUDIT_PATH)
        } else {
            let state_dir = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state")))
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            state_dir.join("agent-root-runner/audit.log")
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create audit directory {}: {e}", parent.display()))?;
            if user_mode && !explicit_path {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    format!("Cannot secure audit directory {}: {e}", parent.display())
                })?;
                if !private_dir_owned(parent) {
                    return Err(format!("Unsafe audit directory: {}", parent.display()));
                }
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| format!("Cannot open audit log {}: {e}", path.display()))?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err(format!(
                "Audit path is not a regular file: {}",
                path.display()
            ));
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(format!(
                "Cannot secure audit log {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            file: Mutex::new(file),
            #[cfg(test)]
            fail_next_event: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_sync: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_event_for_test(&self) {
        self.fail_next_event.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_sync_for_test(&self) {
        self.fail_next_sync.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn full_for_test() -> Self {
        let file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        Self {
            file: Mutex::new(file),
            fail_next_event: AtomicBool::new(false),
            fail_next_sync: AtomicBool::new(false),
        }
    }

    pub fn event(
        &self,
        event_type: &str,
        peer_pid: Option<i32>,
        peer_uid: Option<u32>,
        peer_gid: Option<u32>,
        peer_comm: Option<&str>,
        mut data: Map<String, Value>,
    ) -> Result<(), String> {
        #[cfg(test)]
        if self.fail_next_event.swap(false, Ordering::SeqCst) {
            return Err("injected audit write failure".into());
        }

        let pid = peer_pid.unwrap_or(std::process::id() as i32);
        let uid = peer_uid.unwrap_or_else(|| unsafe { libc::geteuid() });
        let gid = peer_gid.unwrap_or_else(|| unsafe { libc::getegid() });
        let comm = peer_comm.unwrap_or("[unknown]");
        let mut record = Map::new();
        record.insert(
            "timestamp".into(),
            json!(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)),
        );
        record.insert(
            "event_id".into(),
            json!(format!(
                "evt_{}",
                &Uuid::new_v4().simple().to_string()[..12]
            )),
        );
        record.insert("event_type".into(), json!(event_type));
        for name in ["pid", "peer_pid"] {
            record.insert(name.into(), json!(pid));
        }
        for name in ["uid", "peer_uid"] {
            record.insert(name.into(), json!(uid));
        }
        for name in ["gid", "peer_gid"] {
            record.insert(name.into(), json!(gid));
        }
        for name in ["comm", "peer_comm"] {
            record.insert(name.into(), json!(comm));
        }
        for (key, value) in std::mem::take(&mut data) {
            record.entry(key).or_insert(value);
        }
        let mut line = serde_json::to_vec(&Value::Object(record)).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| "audit mutex poisoned".to_string())?;
        file.write_all(&line)
            .map_err(|e| format!("audit write failed: {e}"))?;
        #[cfg(test)]
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            return Err("audit fdatasync failed: injected sync error".into());
        }
        file.sync_data()
            .map_err(|e| format!("audit fdatasync failed: {e}"))
    }
}

fn private_dir_owned(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(md) = fs::symlink_metadata(path) else {
        return false;
    };
    md.is_dir() && md.uid() == unsafe { libc::geteuid() } && md.permissions().mode() & 0o077 == 0
}

pub fn object(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}
