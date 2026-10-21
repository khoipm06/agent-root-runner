use crate::state::{Admission, StateMachine};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicI32, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;
pub enum ExecError {
    InvalidEnv(String),
    InvalidWorkdir(String),
    AdmissionInvalid(String),
    Internal(String),
}
pub struct ResolvedWorkdir {
    directory: fs::File,
    pub path: PathBuf,
}
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: f64,
    pub timed_out: bool,
    pub truncated: bool,
}
impl ExecResult {
    pub fn value(&self) -> Value {
        json!({"exit_code":self.exit_code,"stdout":self.stdout,"stderr":self.stderr,"duration_ms":self.duration_ms,"timed_out":self.timed_out,"truncated":self.truncated})
    }
}
pub struct Executor {
    pgid: Arc<AtomicI32>,
    state: Arc<StateMachine>,
    user_mode: bool,
}
impl Executor {
    pub fn new(pgid: Arc<AtomicI32>, state: Arc<StateMachine>, user_mode: bool) -> Self {
        Self {
            pgid,
            state,
            user_mode,
        }
    }
    fn environment(&self, input: Option<&Value>) -> Result<HashMap<String, String>, ExecError> {
        let mut e = HashMap::from([
            (
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            ),
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("USER".into(), "root".into()),
            ("HOME".into(), "/root".into()),
            ("SHELL".into(), "/bin/bash".into()),
            ("TERM".into(), "xterm-256color".into()),
        ]);
        if self.user_mode || unsafe { libc::geteuid() } != 0 {
            e.insert(
                "USER".into(),
                std::env::var("USER").unwrap_or_else(|_| "runner".into()),
            );
            e.insert(
                "HOME".into(),
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
            );
        }
        let Some(v) = input else { return Ok(e) };
        let Some(map) = v.as_object() else {
            return Err(ExecError::InvalidEnv(
                "Invalid params: 'env' must be an object of strings".into(),
            ));
        };
        for (k, v) in map {
            let Some(value) = v.as_str() else {
                return Err(ExecError::InvalidEnv(format!(
                    "Environment key and value must be strings: {k:?}"
                )));
            };
            let b = k.as_bytes();
            if b.is_empty()
                || !(b[0].is_ascii_alphabetic() || b[0] == b'_')
                || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                return Err(ExecError::InvalidEnv(format!(
                    "Malformed environment variable name: {k:?}"
                )));
            }
            if k.contains('\0') || value.contains('\0') {
                return Err(ExecError::InvalidEnv(format!(
                    "Null bytes forbidden in environment: {k:?}"
                )));
            }
            let exact = [
                "PATH",
                "SHELL",
                "BASH_ENV",
                "ENV",
                "ZDOTDIR",
                "ZSHENV",
                "SHELLOPTS",
                "BASHOPTS",
                "IFS",
                "PROMPT_COMMAND",
                "GLOBIGNORE",
                "SUDO_COMMAND",
                "SUDO_USER",
                "SUDO_UID",
                "SUDO_GID",
                "KRB5_CONFIG",
                "KRB5CCNAME",
                "RESOLV_CONF",
                "HOME",
                "USER",
                "GLIBC_TUNABLES",
                "GCONV_PATH",
                "LOCALDOMAIN",
            ];
            if exact.contains(&k.as_str())
                || [
                    "LD_",
                    "PYTHON",
                    "PERL",
                    "RUBY",
                    "NODE_",
                    "LUA_",
                    "BASH_FUNC_",
                ]
                .iter()
                .any(|p| k.starts_with(p))
            {
                return Err(ExecError::InvalidEnv(format!(
                    "Prohibited environment variable injection detected: {k}"
                )));
            }
            e.insert(k.clone(), value.into());
        }
        Ok(e)
    }
    pub fn resolve_workdir(&self, path: Option<&str>) -> Result<ResolvedWorkdir, ExecError> {
        let raw = path.filter(|s| !s.is_empty()).unwrap_or(
            if self.user_mode || unsafe { libc::geteuid() } != 0 {
                "/tmp"
            } else {
                "/root"
            },
        );
        if raw.contains('\0') {
            return Err(ExecError::InvalidWorkdir(
                "Null bytes forbidden in workdir path.".into(),
            ));
        }
        let c_path = CString::new(raw.as_bytes()).map_err(|_| {
            ExecError::InvalidWorkdir("Null bytes forbidden in workdir path.".into())
        })?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(ExecError::InvalidWorkdir(format!(
                "Working directory does not exist or is not accessible: {raw}"
            )));
        }
        let directory = unsafe { fs::File::from_raw_fd(fd) };
        if !directory
            .metadata()
            .map_err(|e| ExecError::InvalidWorkdir(format!("Cannot inspect workdir {raw}: {e}")))?
            .is_dir()
        {
            return Err(ExecError::InvalidWorkdir(format!(
                "Working directory is not a directory: {raw}"
            )));
        }
        let path = fs::read_link(format!("/proc/self/fd/{fd}")).map_err(|e| {
            ExecError::InvalidWorkdir(format!("Cannot resolve working directory {raw}: {e}"))
        })?;
        if !path.is_absolute() || path.to_string_lossy().ends_with(" (deleted)") {
            return Err(ExecError::InvalidWorkdir(format!(
                "Working directory changed or was removed during validation: {raw}"
            )));
        }
        Ok(ResolvedWorkdir { directory, path })
    }
    pub fn execute(
        &self,
        command: &str,
        timeout: f64,
        workdir: &ResolvedWorkdir,
        env: Option<&Value>,
        admission: &Admission,
    ) -> Result<ExecResult, ExecError> {
        if command.trim().is_empty() {
            return Ok(ExecResult {
                exit_code: 2,
                stdout: String::new(),
                stderr: "Error: Empty command string provided.".into(),
                duration_ms: 0.,
                timed_out: false,
                truncated: false,
            });
        }
        if command.contains('\0') {
            return Ok(ExecResult {
                exit_code: 2,
                stdout: String::new(),
                stderr: "Error: Command contains embedded null bytes.".into(),
                duration_ms: 0.,
                timed_out: false,
                truncated: false,
            });
        }
        let env = self.environment(env)?;
        let start = Instant::now();
        let mut cmd = Command::new("/bin/bash");
        cmd.arg("-c")
            .arg(command)
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            let cwd_fd = workdir.directory.as_raw_fd();
            let arm_deadline = admission.deadline;
            cmd.pre_exec(move || {
                if libc::fchdir(cwd_fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                set_limit(libc::RLIMIT_CORE, 0, 0);
                set_limit(libc::RLIMIT_NOFILE, 1024, 1024);
                if libc::geteuid() == 0 {
                    set_limit(libc::RLIMIT_NPROC, 256, 256);
                }
                set_limit(libc::RLIMIT_CPU, 60, 120);
                set_limit(libc::RLIMIT_FSIZE, 500 * 1024 * 1024, 500 * 1024 * 1024);
                if arm_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
                }
                Ok(())
            });
        }
        let spawn_permit = self
            .state
            .spawn_permit(admission)
            .map_err(ExecError::AdmissionInvalid)?;
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                drop(spawn_permit);
                if error.raw_os_error() == Some(libc::ETIMEDOUT) {
                    return Err(ExecError::AdmissionInvalid(
                        "ARM deadline expired before process start.".into(),
                    ));
                }
                return Err(ExecError::Internal(format!(
                    "could not start command: {error}"
                )));
            }
        };
        let pgid = child.id() as i32;
        self.pgid.store(pgid, Ordering::SeqCst);
        drop(spawn_permit);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExecError::Internal("stdout pipe unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ExecError::Internal("stderr pipe unavailable".into()))?;
        let ot = thread::spawn(move || drain(stdout));
        let et = thread::spawn(move || drain(stderr));
        let user_deadline = start + Duration::from_secs_f64(timeout);
        let deadline = admission
            .deadline
            .map(|arm_deadline| arm_deadline.min(user_deadline))
            .unwrap_or(user_deadline);
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    timed_out = true;
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    break child
                        .wait()
                        .map_err(|e| ExecError::Internal(format!("command wait failed: {e}")))?;
                }
                Ok(None) => {
                    let sleep_for = deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(5));
                    thread::sleep(sleep_for);
                }
                Err(e) => {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    return Err(ExecError::Internal(format!("command wait failed: {e}")));
                }
            }
        };
        let ms = (start.elapsed().as_secs_f64() * 1000. * 100.).round() / 100.;
        kill_process_tree(pgid);
        let (out, otrun) = ot.join().unwrap_or_default();
        let (err, etru) = et.join().unwrap_or_default();
        let _ = self
            .pgid
            .compare_exchange(pgid, 0, Ordering::SeqCst, Ordering::SeqCst);
        let mut out = String::from_utf8_lossy(&out).into_owned();
        let mut err = String::from_utf8_lossy(&err).into_owned();
        if otrun {
            out.push_str("\n[... stdout truncated at 10MB limit ...]\n")
        }
        if etru {
            err.push_str("\n[... stderr truncated at 10MB limit ...]\n")
        }
        let code = if timed_out {
            err = format!("Command execution timed out after {timeout:?} seconds.\n{err}");
            124
        } else if let Some(n) = status.code() {
            n
        } else {
            let sig = status.signal().unwrap_or(0);
            if sig == libc::SIGXFSZ {
                err = format!("Error: File size limit exceeded (RLIMIT_FSIZE violated).\n{err}")
            }
            if sig == libc::SIGXCPU {
                err = format!("Error: CPU time limit exceeded (RLIMIT_CPU violated).\n{err}")
            }
            128 + sig
        };
        Ok(ExecResult {
            exit_code: code,
            stdout: out,
            stderr: err,
            duration_ms: ms,
            timed_out,
            truncated: otrun || etru,
        })
    }
}

/// Make orphaned grandchildren reparent to this daemon instead of PID 1. This
/// allows cleanup to find descendants that deliberately escaped the command's
/// process group by calling setsid().
pub fn enable_child_subreaper() -> std::io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Kill the ordinary process group and descendants that moved into other
/// sessions. The daemon is configured as a Linux child subreaper, so detached
/// grandchildren become visible in its /proc children list and can be reaped.
pub fn kill_process_tree(root_pid: i32) {
    if root_pid <= 0 {
        return;
    }
    unsafe {
        libc::kill(-root_pid, libc::SIGKILL);
        libc::kill(root_pid, libc::SIGKILL);
    }

    let daemon_pid = unsafe { libc::getpid() };
    let mut empty_passes = 0;
    for _ in 0..100 {
        let mut victims = Vec::new();
        let mut visited = std::collections::HashSet::new();
        collect_descendants(root_pid, &mut visited, &mut victims);
        let mut adopted = process_children(daemon_pid);
        adopted.retain(|pid| *pid != root_pid);
        victims.extend(adopted);
        victims.sort_unstable();
        victims.dedup();

        for pid in victims.iter().rev() {
            unsafe {
                libc::kill(*pid, libc::SIGKILL);
            }
        }
        unsafe {
            libc::kill(-root_pid, libc::SIGKILL);
            libc::kill(root_pid, libc::SIGKILL);
        }
        for pid in &victims {
            let mut status = 0;
            unsafe {
                libc::waitpid(*pid, &mut status, libc::WNOHANG);
            }
        }

        if victims.is_empty() {
            empty_passes += 1;
            if empty_passes >= 3 {
                break;
            }
        } else {
            empty_passes = 0;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn collect_descendants(
    pid: i32,
    visited: &mut std::collections::HashSet<i32>,
    postorder: &mut Vec<i32>,
) {
    if !visited.insert(pid) {
        return;
    }
    for child in process_children(pid) {
        collect_descendants(child, visited, postorder);
        postorder.push(child);
    }
}

fn process_children(pid: i32) -> Vec<i32> {
    let task_dir = format!("/proc/{pid}/task");
    let Ok(tasks) = fs::read_dir(task_dir) else {
        return Vec::new();
    };
    let mut children = Vec::new();
    for task in tasks.flatten() {
        let path = task.path().join("children");
        if let Ok(contents) = fs::read_to_string(path) {
            children.extend(
                contents
                    .split_whitespace()
                    .filter_map(|value| value.parse::<i32>().ok()),
            );
        }
    }
    children.sort_unstable();
    children.dedup();
    children
}

fn drain<R: Read>(mut r: R) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 64 * 1024];
    let mut trunc = false;
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let k = n.min(MAX_OUTPUT_BYTES.saturating_sub(out.len()));
                out.extend_from_slice(&buf[..k]);
                if k < n {
                    trunc = true
                }
            }
        }
    }
    (out, trunc)
}
fn set_limit(resource: libc::__rlimit_resource_t, soft: libc::rlim_t, hard: libc::rlim_t) {
    let lim = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    unsafe {
        libc::setrlimit(resource, &lim);
    }
}
pub fn error(e: ExecError) -> (i64, String, Value) {
    match e {
        ExecError::InvalidEnv(s) | ExecError::InvalidWorkdir(s) => {
            (-32602, s, json!({"reason":"INVALID_PARAMS"}))
        }
        ExecError::AdmissionInvalid(s) => (-32001, s, json!({"reason":"DISARMED"})),
        ExecError::Internal(s) => (-32603, format!("Internal execution error: {s}"), json!({})),
    }
}
