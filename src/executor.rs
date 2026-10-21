use crate::state::{Admission, StateMachine};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI32, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;
/// How long `execute` waits, after the SIGKILL sweep, for the output reader
/// threads to hand over whatever they drained. This must be bounded: a reader
/// stuck on a pipe held open by an uninterruptible (D-state) descendant
/// would otherwise block this executor — and with it the daemon-wide exec
/// lock — forever.
const READER_HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);
/// Reader poll slice: bounds how long a reader can sit on an idle pipe
/// before re-checking the shutdown flag, so no reader thread can outlive
/// its execution by more than one slice.
const READER_POLL_SLICE_MS: libc::c_int = 100;
/// Fork-bomb headroom for a non-root child: the child may add at most this
/// many tasks beyond its uid's ambient count before fork() starts failing
/// with EAGAIN. RLIMIT_NPROC is enforced by the kernel against the uid's
/// system-wide task count (threads included), not against the command's
/// own tree, so the bound must always be relative to that ambient count —
/// a static absolute bound would EAGAIN every fork on a busy desktop uid.
const NPROC_FORK_MARGIN: libc::rlim_t = 256;

/// Environment variable names that may never be injected into a child
/// process. Matching is exact and case-sensitive: the loader and shells
/// only honor the exact spellings, so lowercase look-alikes are inert.
const PROHIBITED_ENV_EXACT: &[&str] = &[
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
    // Tool and interpreter configuration-file / exec-path hooks:
    "PAGER",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "LOCPATH",
    "NLSPATH",
    "CURL_HOME",
    "WGETRC",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "PERL5LIB",
    "RUBYOPT",
    "NODE_OPTIONS",
];
/// Environment variable name prefixes that may never be injected: any
/// `GIT_*` config/transport hook, dynamic-loader paths, language runtime
/// knobs, and bash exported-function encodings (`BASH_FUNC_*`).
const PROHIBITED_ENV_PREFIXES: &[&str] = &[
    "LD_",
    "PYTHON",
    "PERL",
    "RUBY",
    "NODE_",
    "LUA_",
    "BASH_FUNC_",
    "GIT_",
];

/// Exact-name and prefix blacklist check, applied case-sensitively before
/// the child is ever spawned.
fn prohibited_env_name(name: &str) -> bool {
    PROHIBITED_ENV_EXACT.contains(&name)
        || PROHIBITED_ENV_PREFIXES.iter().any(|p| name.starts_with(p))
}

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
            if prohibited_env_name(k) {
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
        // O_PATH performs no permission checks of its own, so a directory
        // this daemon cannot read/search (e.g. mode 000) would pass
        // validation here and only fail later at fchdir() inside the child
        // — surfacing as a misleading internal error after admission.
        // Probe usability with the effective uid now and reject with the
        // InvalidWorkdir error class (-32602) instead.
        let rc = unsafe {
            libc::faccessat(
                directory.as_raw_fd(),
                b".\0".as_ptr() as *const libc::c_char,
                libc::R_OK | libc::X_OK,
                libc::AT_EACCESS,
            )
        };
        if rc != 0 {
            let reason = std::io::Error::last_os_error();
            return Err(ExecError::InvalidWorkdir(format!(
                "Working directory is not readable/searchable by the daemon ({reason}): {raw}"
            )));
        }
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
        // The RPC layer clamps `timeout` to (0, 3600] and rejects
        // non-finite values, but `execute` is also a public API:
        // from_secs_f64 panics on negative/NaN input, and a panic aborts
        // this daemon — so clamp defensively here.
        let timeout = if timeout.is_finite() {
            timeout.clamp(0.0, 3600.0)
        } else {
            0.0
        };
        let user_deadline = start + Duration::from_secs_f64(timeout);
        let deadline = admission
            .deadline
            .map(|arm_deadline| arm_deadline.min(user_deadline))
            .unwrap_or(user_deadline);
        let (cpu_soft, cpu_hard) = cpu_rlimits_for(deadline.saturating_duration_since(start));
        // Fork-bomb bound for a non-root child, sampled before the spawn so
        // the limit can never sit below the uid's live task count (see
        // NPROC_FORK_MARGIN). Root children skip the limit entirely.
        let nproc_bound = if unsafe { libc::geteuid() } != 0 {
            Some(
                (uid_task_count(unsafe { libc::getuid() }) as libc::rlim_t)
                    .saturating_add(NPROC_FORK_MARGIN),
            )
        } else {
            None
        };
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
                set_limit("RLIMIT_CORE", libc::RLIMIT_CORE, 0, 0)?;
                set_limit("RLIMIT_NOFILE", libc::RLIMIT_NOFILE, 1024, 1024)?;
                // RLIMIT_NPROC binds only for a non-root child: the kernel
                // exempts UID 0 (and CAP_SYS_RESOURCE/CAP_SYS_ADMIN
                // holders) from fork() user-process accounting, so
                // applying it to a root child is a no-op. For a root child
                // the limit stays unset and its process count is bounded
                // by other means — the deployment's cgroup `pids` limit
                // (systemd TasksMax=) and this executor's post-run SIGKILL
                // process-tree sweep. For a non-root child the fork bomb
                // is bounded to NPROC_FORK_MARGIN tasks above its uid's
                // ambient count, sampled before the spawn.
                if libc::geteuid() != 0 {
                    if let Some(bound) = nproc_bound {
                        set_limit("RLIMIT_NPROC", libc::RLIMIT_NPROC, bound, bound)?;
                    }
                }
                set_limit("RLIMIT_CPU", libc::RLIMIT_CPU, cpu_soft, cpu_hard)?;
                set_limit(
                    "RLIMIT_FSIZE",
                    libc::RLIMIT_FSIZE,
                    500 * 1024 * 1024,
                    500 * 1024 * 1024,
                )?;
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
        // Reader threads must never block this executor forever: each
        // drains its pipe in poll slices while watching a shutdown flag and
        // reports through a channel that is collected with a bounded
        // timeout below. (Plain join()s here would wedge the daemon
        // whenever an uninterruptible descendant keeps a pipe open.)
        let (out_tx, out_rx) = mpsc::channel::<DrainedOutput>();
        let (err_tx, err_rx) = mpsc::channel::<DrainedOutput>();
        let readers_stop = Arc::new(AtomicBool::new(false));
        let stop_for_stdout = readers_stop.clone();
        thread::spawn(move || {
            let _ = out_tx.send(drain(stdout, &stop_for_stdout));
        });
        let stop_for_stderr = readers_stop.clone();
        thread::spawn(move || {
            let _ = err_tx.send(drain(stderr, &stop_for_stderr));
        });
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    timed_out = true;
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    break wait_after_kill(&mut child, &readers_stop)?;
                }
                Ok(None) => {
                    let sleep_for = deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(5));
                    thread::sleep(sleep_for);
                }
                Err(e) if wait_error_is_retryable(&e) => {
                    // try_wait surfaces EINTR when a handler without
                    // SA_RESTART fires (std implements it with a
                    // non-retrying cvt, unlike blocking wait()): retry
                    // instead of killing the whole process group. The
                    // deadline stays enforced so a pathological signal
                    // storm cannot spin this loop forever.
                    if Instant::now() >= deadline {
                        timed_out = true;
                        unsafe {
                            libc::kill(-pgid, libc::SIGKILL);
                        }
                        break wait_after_kill(&mut child, &readers_stop)?;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    // This executor is abandoning the execution: make sure
                    // the readers stop too instead of polling a pipe that
                    // an unkilled descendant might still hold open.
                    readers_stop.store(true, Ordering::Relaxed);
                    return Err(ExecError::Internal(format!("command wait failed: {e}")));
                }
            }
        };
        let ms = (start.elapsed().as_secs_f64() * 1000. * 100.).round() / 100.;
        // The direct child has been reaped: clear the published pgid
        // immediately — before any of the potentially slow cleanup below —
        // so a concurrent disarm/expiry can never signal a stale, possibly
        // recycled PID.
        let _ = self
            .pgid
            .compare_exchange(pgid, 0, Ordering::SeqCst, Ordering::SeqCst);
        kill_process_tree(pgid);
        // Tell the readers to stop, then take whatever they drained within
        // a bounded handoff window. On timeout the execution proceeds with
        // partial output flagged as truncated instead of wedging the
        // daemon (and the exec lock) forever.
        readers_stop.store(true, Ordering::Relaxed);
        let out_drained = collect_drained(&out_rx);
        let err_drained = collect_drained(&err_rx);
        let mut out = String::from_utf8_lossy(&out_drained.data).into_owned();
        let mut err = String::from_utf8_lossy(&err_drained.data).into_owned();
        if out_drained.capped {
            out.push_str("\n[... stdout truncated at 10MB limit ...]\n")
        }
        if out_drained.abandoned {
            out.push_str(
                "\n[... stdout incomplete: process cleanup did not finish; output may be missing ...]\n",
            )
        }
        if err_drained.capped {
            err.push_str("\n[... stderr truncated at 10MB limit ...]\n")
        }
        if err_drained.abandoned {
            err.push_str(
                "\n[... stderr incomplete: process cleanup did not finish; output may be missing ...]\n",
            )
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
            truncated: out_drained.capped
                || err_drained.capped
                || out_drained.abandoned
                || err_drained.abandoned,
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

/// What a reader thread managed to drain from one output pipe.
struct DrainedOutput {
    data: Vec<u8>,
    /// The 10 MB output cap was hit; the tail was discarded.
    capped: bool,
    /// The reader stopped before EOF on request (the pipe stayed open
    /// behind an unreapable process): the stream may be missing its tail.
    abandoned: bool,
}

/// Take a reader's result within [`READER_HANDOFF_TIMEOUT`]. If the reader
/// is wedged on a pipe whose write end is still held by an unkilled
/// descendant — or it died without reporting — proceed with nothing and
/// flag the stream as incomplete rather than blocking this executor.
fn collect_drained(rx: &mpsc::Receiver<DrainedOutput>) -> DrainedOutput {
    match rx.recv_timeout(READER_HANDOFF_TIMEOUT) {
        Ok(drained) => drained,
        Err(_) => DrainedOutput {
            data: Vec::new(),
            capped: false,
            abandoned: true,
        },
    }
}

/// Reap the direct child after the process group was SIGKILLed. Every
/// other exit path of `execute` must go through here so the readers can
/// never be left running unbounded on this executor's behalf.
fn wait_after_kill(
    child: &mut std::process::Child,
    readers_stop: &AtomicBool,
) -> Result<std::process::ExitStatus, ExecError> {
    match child.wait() {
        Ok(status) => Ok(status),
        Err(e) => {
            readers_stop.store(true, Ordering::Relaxed);
            Err(ExecError::Internal(format!("command wait failed: {e}")))
        }
    }
}

/// Drain one child output pipe without ever blocking its reader thread
/// unboundedly. The pipe is polled in short slices; the shutdown flag is
/// consulted only while the pipe is idle (so buffered output is always
/// consumed), and a final zero-timeout probe distinguishes an EOF that
/// arrived in the meantime from a pipe that is still held open.
fn drain<R: Read + AsRawFd>(mut r: R, shutdown: &AtomicBool) -> DrainedOutput {
    let mut out = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 64 * 1024];
    let mut capped = false;
    let mut abandoned = false;
    loop {
        let mut pfd = libc::pollfd {
            fd: r.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, READER_POLL_SLICE_MS) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 {
            // Idle pipe: the only moment the reader observes the shutdown
            // flag, so output buffered behind a still-writing process is
            // never dropped.
            if !shutdown.load(Ordering::Relaxed) {
                continue;
            }
            let mut probe = libc::pollfd {
                fd: r.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut probe, 1, 0) } > 0 && probe.revents != 0;
            if !ready {
                abandoned = true;
                break;
            }
        }
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let k = n.min(MAX_OUTPUT_BYTES.saturating_sub(out.len()));
                out.extend_from_slice(&buf[..k]);
                if k < n {
                    capped = true
                }
            }
        }
    }
    DrainedOutput {
        data: out,
        capped,
        abandoned,
    }
}

/// Count the schedulable tasks (processes and their threads) currently
/// owned by `uid`, via /proc directory ownership. Threads share their
/// process's credentials, so every task directory under an owned process
/// belongs to the same uid; this is the quantity the kernel compares
/// against RLIMIT_NPROC at fork time.
fn uid_task_count(uid: libc::uid_t) -> usize {
    let Ok(processes) = fs::read_dir("/proc") else {
        return 0;
    };
    let mut tasks = 0usize;
    for process in processes.flatten() {
        let file_name = process.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.parse::<u32>().is_err() {
            continue;
        }
        if process.metadata().is_ok_and(|meta| meta.uid() == uid) {
            match fs::read_dir(process.path().join("task")) {
                Ok(threads) => tasks += threads.flatten().count(),
                // The process died mid-scan; count it as one task.
                Err(_) => tasks += 1,
            }
        }
    }
    tasks
}

/// Derive the child's RLIMIT_CPU budget from the effective wall-clock
/// deadline (the user timeout clamped by the arm window). A legitimate
/// long command must not be killed by a fixed 60 s CPU cap, while a
/// runaway CPU burner stays bounded: SIGXCPU arrives one grace minute
/// after the deadline would have elapsed, capped at the RPC ceiling
/// (3600 s + 60 s); the hard limit adds one more minute before SIGKILL.
fn cpu_rlimits_for(effective: Duration) -> (libc::rlim_t, libc::rlim_t) {
    let secs = effective.as_secs_f64().max(0.0).ceil() as libc::rlim_t;
    let soft = secs.saturating_add(60).min(3660);
    (soft, soft.saturating_add(60))
}

/// `try_wait` can return EINTR (std implements it with a non-retrying
/// `cvt`, unlike blocking `wait()`): a signal handler installed without
/// SA_RESTART must not cause the executor to SIGKILL the whole process
/// group. Only a plain interruption is retried; anything else is fatal.
fn wait_error_is_retryable(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Interrupted
}

fn set_limit(
    name: &str,
    resource: libc::__rlimit_resource_t,
    soft: libc::rlim_t,
    hard: libc::rlim_t,
) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    let rc = unsafe { libc::setrlimit(resource, &lim) };
    if rc == 0 {
        return Ok(());
    }
    // Fail the spawn loudly instead of silently dropping a
    // security-relevant limit; the spawn-error path refunds the quota.
    Err(std::io::Error::other(format!(
        "setrlimit({name}) failed: {}",
        std::io::Error::last_os_error()
    )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogger;
    use crate::state::StateMachine;
    use serde_json::json;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// An `Executor` wired to a throwaway audit log; nothing here spawns
    /// the daemon or touches its production socket.
    fn test_executor() -> Executor {
        let audit = std::env::temp_dir().join(format!(
            "arr-executor-unit-{}-{}.log",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let logger = Arc::new(AuditLogger::open(audit.to_str(), true).unwrap());
        // The logger keeps an open fd, so the path can go away immediately.
        let _ = fs::remove_file(&audit);
        let pgid = Arc::new(AtomicI32::new(0));
        let state = Arc::new(StateMachine::new(logger, pgid.clone(), false));
        Executor::new(pgid, state, true)
    }

    #[test]
    fn env_blacklist_rejects_tool_and_interpreter_hooks() {
        let executor = test_executor();
        for name in [
            "PAGER",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "LOCPATH",
            "NLSPATH",
            "CURL_HOME",
            "WGETRC",
            "SSH_ASKPASS",
            "SUDO_ASKPASS",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "PERL5LIB",
            "RUBYOPT",
            "NODE_OPTIONS",
        ] {
            let env = json!({ name: "/tmp/controlled-by-client" });
            assert!(
                matches!(
                    executor.environment(Some(&env)),
                    Err(ExecError::InvalidEnv(_))
                ),
                "{name} must be rejected before the child is spawned"
            );
        }
    }

    #[test]
    fn env_blacklist_matches_git_and_bash_func_prefixes_case_sensitively() {
        let executor = test_executor();
        for name in [
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "BASH_FUNC_exec",
        ] {
            let env = json!({ name: "x" });
            assert!(
                matches!(
                    executor.environment(Some(&env)),
                    Err(ExecError::InvalidEnv(_))
                ),
                "prefix match must reject {name}"
            );
        }
        // Case-sensitivity: lowercase look-alikes are inert on Linux and
        // must keep flowing through to the child.
        for name in ["git_config_global", "bash_func_exec", "pager", "ld_preload"] {
            let env = json!({ name: "x" });
            assert!(
                executor.environment(Some(&env)).is_ok(),
                "{name} must not match the case-sensitive blacklist"
            );
        }
        // Exact names must not over-match neighboring spellings.
        let env = json!({"PAGERR":"x","MYGIT_VALUE":"x","XNODE_OPTIONS":"x"});
        assert!(executor.environment(Some(&env)).is_ok());
    }

    #[test]
    fn unusable_workdir_is_rejected_as_invalid_params_not_internal() {
        if unsafe { libc::geteuid() } == 0 {
            // Root bypasses DAC checks, so a mode-000 directory stays
            // usable for it and this probe cannot fail.
            return;
        }
        let base = std::env::temp_dir().join(format!(
            "arr-workdir-unit-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&base).unwrap();
        let locked = base.join("mode-000");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let executor = test_executor();
        let outcome = executor.resolve_workdir(locked.to_str());
        // Restore permissions before asserting so cleanup works even on failure.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        match outcome {
            Err(e @ ExecError::InvalidWorkdir(_)) => {
                let (code, _message, data) = error(e);
                assert_eq!(code, -32602);
                assert_eq!(data["reason"], "INVALID_PARAMS");
            }
            Err(ExecError::InvalidEnv(m))
            | Err(ExecError::AdmissionInvalid(m))
            | Err(ExecError::Internal(m)) => {
                panic!("expected InvalidWorkdir, got another error class: {m}")
            }
            Ok(_) => panic!("workdir validation accepted an unreadable directory"),
        }
        // A usable directory must keep resolving.
        assert!(executor.resolve_workdir(base.to_str()).is_ok());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn cpu_rlimits_track_the_effective_timeout() {
        // Sub-second budgets get at least the old 60 s grace...
        assert_eq!(cpu_rlimits_for(Duration::from_secs(0)), (60, 120));
        assert_eq!(cpu_rlimits_for(Duration::from_millis(500)), (61, 121));
        // ...while long commands are no longer killed at a fixed 60 s:
        assert_eq!(cpu_rlimits_for(Duration::from_secs(60)), (120, 180));
        assert_eq!(
            cpu_rlimits_for(Duration::from_secs(600)),
            (660, 720),
            "a 600 s command must not die at the old 60 s CPU cap"
        );
        // The RPC ceiling (3600 s) plus grace caps the budget.
        assert_eq!(cpu_rlimits_for(Duration::from_secs(3600)), (3660, 3720));
        assert_eq!(cpu_rlimits_for(Duration::from_secs(9000)), (3660, 3720));
    }

    #[test]
    fn wait_errors_are_retried_only_for_plain_interruption() {
        assert!(wait_error_is_retryable(&std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "EINTR from a handler without SA_RESTART"
        )));
        for fatal in [
            std::io::Error::from_raw_os_error(libc::ECHILD),
            std::io::Error::from_raw_os_error(libc::EINVAL),
        ] {
            assert!(
                !wait_error_is_retryable(&fatal),
                "non-EINTR wait errors must stay fatal"
            );
        }
    }

    #[test]
    fn uid_task_count_sees_this_test_runner_and_no_impossible_uid() {
        let uid = unsafe { libc::getuid() };
        let ambient = uid_task_count(uid);
        assert!(
            ambient >= 1,
            "the test process itself must be counted for its own uid"
        );
        assert_eq!(
            uid_task_count(libc::uid_t::MAX),
            0,
            "no live task can be owned by UID_MAX"
        );
    }

    fn pipe_pair() -> (fs::File, fs::File) {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        unsafe { (fs::File::from_raw_fd(fds[0]), fs::File::from_raw_fd(fds[1])) }
    }

    #[test]
    fn drain_keeps_buffered_data_but_gives_up_on_idle_shutdown() {
        // Data plus EOF are honored even when shutdown was already set.
        let (reader, writer) = pipe_pair();
        let mut writer = writer;
        writer.write_all(b"payload").unwrap();
        drop(writer);
        let shutdown = AtomicBool::new(true);
        let drained = drain(reader, &shutdown);
        assert_eq!(drained.data, b"payload".to_vec());
        assert!(!drained.capped);
        assert!(!drained.abandoned);

        // An idle pipe whose write end is still held open (the wedged
        // descendant case) makes the reader give up once shutdown is set.
        let (reader, writer) = pipe_pair();
        let shutdown = AtomicBool::new(true);
        let began = Instant::now();
        let drained = drain(reader, &shutdown);
        drop(writer);
        assert!(drained.abandoned, "reader must observe the shutdown flag");
        assert!(drained.data.is_empty());
        assert!(
            began.elapsed() <= Duration::from_secs(2),
            "reader took too long to give up: {:?}",
            began.elapsed()
        );

        // Data written before the shutdown request is preserved even
        // without EOF: the reader drains what is buffered and only then
        // declares the stream abandoned.
        let (reader, writer) = pipe_pair();
        let mut writer = writer;
        writer.write_all(b"partial").unwrap();
        let shutdown = AtomicBool::new(true);
        let drained = drain(reader, &shutdown);
        drop(writer);
        assert_eq!(drained.data, b"partial".to_vec());
        assert!(drained.abandoned);
    }
}
