use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use uuid::Uuid;

pub const PROD_AUDIT_PATH: &str = "/var/log/agent-root-runner/audit.log";

pub struct AuditLogger {
    file: Mutex<File>,
    #[cfg(test)]
    fail_next_event: AtomicBool,
    #[cfg(test)]
    fail_next_sync: AtomicBool,
    #[cfg(test)]
    fail_after_bytes: AtomicUsize,
}

// Test-only Debug: regression tests unwrap_err() on AuditLogger::open.
#[cfg(test)]
impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger").finish_non_exhaustive()
    }
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
        // F3: reject non-regular files *before* opening. Opening a FIFO
        // with no reader blocks forever in open(2), so the post-open
        // regular-file check below would never get a chance to run and the
        // daemon would hang at startup with no diagnostic. A missing path
        // falls through: open(2) below creates it.
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.is_file() {
                return Err(format!(
                    "Audit path is not a regular file: {}",
                    path.display()
                ));
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .mode(0o600)
            // O_NONBLOCK is a no-op for regular files but keeps a FIFO
            // raced in between the stat above and this open from blocking.
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|e| format!("Cannot open audit log {}: {e}", path.display()))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() {
            return Err(format!(
                "Audit path is not a regular file: {}",
                path.display()
            ));
        }
        // F4: forcing mode 0600 is not enough — an attacker-owned file
        // keeps read/truncate/delete rights over the daemon's audit trail
        // even after the fchmod. The trail must belong to the effective
        // user (root for the production daemon) or to root itself.
        let euid = unsafe { libc::geteuid() };
        if !audit_owner_acceptable(metadata.uid(), euid) {
            return Err(format!(
                "Audit log {} is owned by uid {} but the daemon runs as uid {euid}; refusing an untrusted audit trail",
                path.display(),
                metadata.uid()
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
            #[cfg(test)]
            fail_after_bytes: AtomicUsize::new(0),
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

    /// F2 test hook: the next event writes only `bytes` bytes of its
    /// record before failing, reproducing a mid-record ENOSPC/EFBIG
    /// without touching the process-wide RLIMIT_FSIZE (which would make
    /// unrelated parallel tests flaky).
    #[cfg(test)]
    pub(crate) fn fail_after_bytes_for_test(&self, bytes: usize) {
        self.fail_after_bytes.store(bytes, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn full_for_test() -> Self {
        let file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        Self {
            file: Mutex::new(file),
            fail_next_event: AtomicBool::new(false),
            fail_next_sync: AtomicBool::new(false),
            fail_after_bytes: AtomicUsize::new(0),
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
        // F2: capture the pre-write length. If the write (or its sync)
        // fails partway, truncate back to this offset so the file never
        // ends mid-record — a restarted daemon appending after
        // unterminated bytes would glue two records onto one unparseable
        // line.
        let start_len = file
            .metadata()
            .map_err(|e| format!("audit stat failed: {e}"))?
            .len();
        #[cfg(test)]
        let inject_partial_bytes = self.fail_after_bytes.swap(0, Ordering::SeqCst);
        #[cfg(test)]
        let write_result = if inject_partial_bytes > 0 {
            let cut = inject_partial_bytes.min(line.len().saturating_sub(1));
            file.write_all(&line[..cut]).and_then(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "injected partial audit write failure",
                ))
            })
        } else {
            file.write_all(&line)
        };
        #[cfg(not(test))]
        let write_result = file.write_all(&line);
        if let Err(error) = write_result {
            // Best effort: on a full disk this may fail too, but the
            // common partial-write case leaves a clean tail.
            let _ = file.set_len(start_len);
            return Err(format!("audit write failed: {error}"));
        }
        #[cfg(test)]
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            // The record was fully written; keep it. The injected
            // sync-stage failure models "write succeeded, fdatasync
            // failed" with the record intact, which the existing
            // fail-closed regression coverage asserts on.
            return Err("audit fdatasync failed: injected sync error".into());
        }
        if let Err(error) = file.sync_data() {
            // Durability was never confirmed, so the record is not
            // acknowledged: roll it back too — a failed writeback could
            // otherwise leave a partial durable line.
            let _ = file.set_len(start_len);
            return Err(format!("audit fdatasync failed: {error}"));
        }
        Ok(())
    }
}

fn private_dir_owned(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(md) = fs::symlink_metadata(path) else {
        return false;
    };
    md.is_dir() && md.uid() == unsafe { libc::geteuid() } && md.permissions().mode() & 0o077 == 0
}

/// F4: the audit file must belong to the effective user (root for the
/// production daemon) or to root itself. Any other owner keeps
/// read/truncate/delete rights over the daemon's trail even after the
/// 0600 fchmod.
fn audit_owner_acceptable(owner_uid: u32, euid: u32) -> bool {
    owner_uid == euid || owner_uid == 0
}

pub fn object(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "arr-audit-{tag}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn partial_write_failure_rolls_back_to_a_complete_record_tail() {
        let dir = scratch_dir("rollback");
        let path = dir.join("audit.log");
        let logger = AuditLogger::open(Some(path.to_str().unwrap()), true).unwrap();
        logger
            .event("DAEMON_START", None, None, None, None, object(&[]))
            .unwrap();
        let durable_len = fs::metadata(&path).unwrap().len();
        assert!(durable_len > 0);

        // F2: a write that fails mid-record must not leave unterminated
        // bytes in the file.
        logger.fail_after_bytes_for_test(64);
        let error = logger
            .event(
                "EXEC_REJECTED",
                Some(1),
                Some(0),
                Some(0),
                Some("probe"),
                object(&[("command", json!("x".repeat(300)))]),
            )
            .unwrap_err();
        assert!(error.contains("audit write failed"), "{error}");
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            durable_len,
            "partial bytes from the failed record must be truncated back"
        );

        // The next durable record appends cleanly: every line parses.
        logger
            .event("DAEMON_STOP", None, None, None, None, object(&[]))
            .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let events: Vec<String> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .map(|v| v["event_type"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            events,
            ["DAEMON_START", "DAEMON_STOP"],
            "the log tail must be complete, parseable records: {text}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fifo_and_directory_audit_paths_are_rejected_without_opening() {
        let dir = scratch_dir("fifo");
        let fifo = dir.join("audit.log");
        let cpath = CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);

        // A FIFO with no reader must be refused instantly instead of
        // hanging the daemon at startup (F3).
        let error = AuditLogger::open(Some(fifo.to_str().unwrap()), true).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");

        let nested = dir.join("nested");
        fs::create_dir(&nested).unwrap();
        let error = AuditLogger::open(Some(nested.to_str().unwrap()), true).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn audit_file_ownership_policy_accepts_only_the_effective_user_or_root() {
        // Root daemon: an attacker-owned trail is refused.
        assert!(audit_owner_acceptable(0, 0));
        assert!(!audit_owner_acceptable(1000, 0));
        // User daemon: own files are fine, foreign users are not.
        assert!(audit_owner_acceptable(1000, 1000));
        assert!(!audit_owner_acceptable(1001, 1000));
        // A root-owned file for a user daemon is ownership-acceptable;
        // the 0600 fchmod still gates actual access.
        assert!(audit_owner_acceptable(0, 1000));
    }

    #[test]
    fn foreign_owned_audit_file_is_rejected_under_root() {
        if unsafe { libc::geteuid() } != 0 {
            // chown to another user requires root; the ownership
            // predicate itself is covered by the unit test above.
            return;
        }
        let dir = scratch_dir("owner");
        let path = dir.join("audit.log");
        fs::write(&path, "seed").unwrap();
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(cpath.as_ptr(), 1, 1) }, 0);

        let error = AuditLogger::open(Some(path.to_str().unwrap()), true).unwrap_err();
        assert!(error.contains("owned by uid"), "{error}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
