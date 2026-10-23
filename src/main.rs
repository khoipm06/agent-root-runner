mod audit;
mod executor;
mod guardrails;
mod state;

use audit::{AuditLogger, object};
use clap::{Args, Parser, Subcommand};
use executor::Executor;
use serde_json::{Map, Value, json};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    flag,
};
use state::StateMachine;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_SOCKET: &str = "/run/agent-root-runner/runner.sock";
const MAX_BUFFER: usize = 10 * 1024 * 1024;
// A valid result can contain two 10 MiB streams, with JSON escaping expanding
// control bytes by up to 6x. Bound client-side response reads accordingly.
const MAX_RESPONSE: usize = 128 * 1024 * 1024;
const MAX_COMMAND: usize = 65_536;
// Bounded pool of concurrent client threads: idle or flooding peers must not
// be able to exhaust process fds / thread memory.
const MAX_CLIENTS: usize = 256;
// Per-socket idle reap window: a connected client that sends nothing for this
// long has its connection closed instead of pinning a thread forever.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Pause after a transient accept() error (fd exhaustion etc.) before retrying.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
// Cap for MCP stdio request lines; the daemon rejects anything above
// MAX_BUFFER anyway, so forwarding larger lines is pure waste.
const MAX_MCP_LINE: usize = 12 * 1024 * 1024;
const UNIT_TEXT: &str = include_str!("../systemd/agent-root-runner.service");

#[derive(Parser)]
#[command(
    name = "agent-root-runner",
    version,
    about = "Native privileged command runner with human-in-the-loop arming"
)]
struct Cli {
    #[arg(long, global = true, help = "Override the daemon Unix socket path")]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Status,
    Arm {
        #[arg(
            long,
            conflicts_with = "forever",
            help = "Arming duration in seconds (default: 900; maximum: 86400)"
        )]
        duration: Option<u64>,
        #[arg(
            long,
            conflicts_with = "duration",
            help = "Arm without a time limit; manual disarm, quota exhaustion, or daemon restart ends the session"
        )]
        forever: bool,
        #[arg(long, help = "Maximum admitted commands before automatic disarm")]
        quota: Option<u64>,
    },
    Disarm,
    Install,
    Uninstall,
    Daemon {
        #[arg(long, help = "Append-only audit log path")]
        audit_log: Option<PathBuf>,
        #[arg(
            long,
            help = "Development/test-only: allow local users to arm an unprivileged daemon"
        )]
        allow_user_arm: bool,
    },
    Exec(ExecArgs),
    Mcp,
}
#[derive(Args)]
struct ExecArgs {
    #[arg(
        long,
        default_value_t = 60,
        help = "Execution timeout in seconds (1..3600)"
    )]
    timeout: u64,
    #[arg(long, default_value = "/", help = "Working directory")]
    workdir: String,
    #[arg(long="env",action=clap::ArgAction::Append,help="Additional environment variable KEY=VALUE (repeatable)")]
    env: Vec<String>,
    #[arg(last=true,required=true,num_args=1..,allow_hyphen_values=true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    // The runtime starts with SIGPIPE ignored, which turns a broken downstream pipe
    // (`status | head`) into a print panic (exit 101). Restore the default
    // disposition so the process ends quietly on EPIPE instead (shells
    // report 128+13=141, matching POSIX tools).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    match run() {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("agent-root-runner: {e}");
            ExitCode::from(1)
        }
    }
}
fn run() -> Result<i32, String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Status => management(cli.socket.as_deref(), "status", Map::new()),
        Commands::Arm {
            duration,
            forever,
            quota,
        } => {
            let mut p = Map::new();
            p.insert("forever".into(), json!(forever));
            if !forever {
                p.insert("duration_seconds".into(), json!(duration.unwrap_or(900)));
            }
            if let Some(q) = quota {
                p.insert("quota".into(), json!(q));
            }
            management(cli.socket.as_deref(), "arm", p)
        }
        Commands::Disarm => management(cli.socket.as_deref(), "disarm", Map::new()),
        Commands::Install => install(),
        Commands::Uninstall => uninstall(),
        Commands::Daemon {
            audit_log,
            allow_user_arm,
        } => daemon(
            resolve_socket(cli.socket.as_deref()),
            audit_log.as_deref(),
            allow_user_arm,
        ),
        Commands::Exec(args) => exec_cli(cli.socket.as_deref(), args),
        Commands::Mcp => mcp(cli.socket.as_deref()),
    }
}

fn resolve_socket(override_path: Option<&Path>) -> PathBuf {
    if let Some(p) = override_path {
        return absolute(p);
    }
    if let Ok(p) = std::env::var("AGENT_ROOT_RUNNER_SOCKET") {
        return absolute(Path::new(&p));
    }
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from(DEFAULT_SOCKET);
    }
    let sys = Path::new(DEFAULT_SOCKET);
    if sys.exists() {
        return sys.into();
    }
    if let Ok(x) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(x).join("agent-root-runner/runner.sock");
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".local/state/agent-root-runner/runner.sock"))
        .unwrap_or_else(|| PathBuf::from("/tmp/agent-root-runner/runner.sock"))
}
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.into()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    }
}
fn rpc(
    socket: &Path,
    method: &str,
    params: Map<String, Value>,
    timeout: Duration,
) -> Result<Value, String> {
    let mut s = UnixStream::connect(socket).map_err(|e| {
        format!(
            "Cannot connect to daemon at {}. Is it running? ({e})",
            socket.display()
        )
    })?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    writeln!(s, "{req}").map_err(|e| format!("Daemon communication failed: {e}"))?;
    let mut line = Vec::new();
    BufReader::new(s)
        .take((MAX_RESPONSE + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if line.is_empty() {
        return Err("Daemon closed connection unexpectedly.".into());
    }
    if line.len() > MAX_RESPONSE {
        return Err("Response exceeded maximum output buffer limit".into());
    }
    serde_json::from_slice(&line).map_err(|e| format!("Malformed response from daemon: {e}"))
}
fn management(
    path: Option<&Path>,
    method: &str,
    params: Map<String, Value>,
) -> Result<i32, String> {
    let socket = resolve_socket(path);
    let resp = rpc(&socket, method, params, Duration::from_secs(10))?;
    if let Some(err) = resp.get("error") {
        let msg = err["message"].as_str().unwrap_or("Unknown daemon error");
        eprintln!(
            "Error: {msg}{}",
            if err["code"] == -32003 {
                " (run with sudo)"
            } else {
                ""
            }
        );
        return Ok(daemon_error_exit(err["code"].as_i64().unwrap_or(-32603)));
    }
    let result = resp.get("result").cloned().unwrap_or_else(|| json!({}));
    match method {
        "status" => {
            println!("State: {}", result["state"].as_str().unwrap_or("UNKNOWN"));
            println!(
                "Armed: {}",
                py_bool(result["is_armed"].as_bool().unwrap_or(false))
            );
            for (label, key) in [
                ("Session", "session_id"),
                ("Armed at", "armed_at"),
                ("Expires at", "expires_at"),
                ("Remaining", "remaining_seconds"),
                ("Timeout", "timeout_seconds"),
                ("Duration", "duration_seconds"),
                ("Forever", "forever"),
                ("Quota limit", "quota_limit"),
                ("Quota remaining", "quota_remaining"),
                ("Commands executed", "commands_executed"),
                ("Lifetime commands", "lifetime_commands"),
                ("Socket", "socket_path"),
                ("Daemon PID", "daemon_pid"),
            ] {
                if !result[key].is_null() {
                    let val = if key == "forever" {
                        py_bool(result[key].as_bool().unwrap_or(false)).to_string()
                    } else {
                        format_value(&result[key])
                    };
                    println!("{label}: {val}")
                }
            }
            if result["state"] == "DISARMED" {
                println!("Daemon is disarmed. Run 'agent-root-runner arm' to enable.")
            } else if result["forever"].as_bool() == Some(true) {
                println!(
                    "ARM has no time limit; disarm manually, exhaust quota, or restart the daemon."
                )
            }
        }
        "arm" => {
            println!(
                "Armed: {}",
                py_bool(result["is_armed"].as_bool().unwrap_or(false))
            );
            if let Some(x) = result["expires_at"].as_str() {
                println!("Expires at: {x}")
            } else if result["forever"].as_bool() == Some(true) {
                println!("Expires: Never (manual disarm, quota exhaustion, or daemon restart)")
            }
            if let Some(q) = result["quota"].as_u64() {
                println!("Quota: {q} commands")
            }
        }
        "disarm" => println!("Disarmed."),
        _ => (),
    };
    Ok(0)
}
fn py_bool(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}
fn format_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

/// Map a daemon JSON-RPC error code to the CLI exit status. Invalid params
/// (-32602) is a usage error and exits 2, not the generic internal-error 128.
fn daemon_error_exit(code: i64) -> i32 {
    match code {
        -32001 => 125,
        -32002 => 126,
        -32003 => 1,
        -32004 => 124,
        -32602 => 2,
        _ => 128,
    }
}

/// Re-join CLI argv for the daemon-side `bash -c` payload. Each element is
/// shell-quoted as one word so argv data can never be re-interpreted as
/// shell syntax (`exec -- printf '%s' 'a;b'` must not run a second command).
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|word| shell_quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}
/// Quote one argv element. Words made only of unexceptional characters are
/// passed through verbatim (keeping `VAR=x cmd` style assignments working);
/// anything containing shell metacharacters is single-quoted with `'\''`
/// escaping, which bash treats as pure data.
fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'-' | b'_' | b'/' | b':' | b'=' | b'%' | b'+' | b','
                )
        });
    if safe {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

fn exec_cli(path: Option<&Path>, args: ExecArgs) -> Result<i32, String> {
    if !(1..=3600).contains(&args.timeout) {
        return Err("--timeout must be in range 1..3600".into());
    }
    let command = shell_join(&args.command);
    let mut env = Map::new();
    for item in args.env {
        if let Some((k, v)) = item.split_once('=') {
            env.insert(k.into(), json!(v));
        } else {
            return Err(format!("--env must be KEY=VALUE: {item}"));
        }
    }
    let mut p = Map::new();
    p.insert("command".into(), json!(command));
    p.insert("timeout_seconds".into(), json!(args.timeout));
    p.insert("workdir".into(), json!(args.workdir));
    p.insert("env".into(), Value::Object(env));
    let response = rpc(
        &resolve_socket(path),
        "exec",
        p,
        Duration::from_secs(args.timeout + 10),
    )?;
    if let Some(err) = response.get("error") {
        eprintln!(
            "agent-root-runner exec: {}",
            err["message"].as_str().unwrap_or("daemon error")
        );
        return Ok(daemon_error_exit(err["code"].as_i64().unwrap_or(-32603)));
    }
    let res = &response["result"];
    let out = res["stdout"].as_str().unwrap_or("");
    let err = res["stderr"].as_str().unwrap_or("");
    if !out.is_empty() {
        print!("{out}");
        if !out.ends_with('\n') {
            println!()
        }
    }
    if !err.is_empty() {
        eprint!("{err}");
        if !err.ends_with('\n') {
            eprintln!()
        }
    }
    Ok(res["exit_code"]
        .as_i64()
        .filter(|n| (0..=255).contains(n))
        .unwrap_or(128) as i32)
}

#[derive(Clone)]
struct Peer {
    pid: i32,
    uid: u32,
    gid: u32,
    comm: String,
}
struct Daemon {
    socket: PathBuf,
    started: Instant,
    state: Arc<StateMachine>,
    executor: Arc<Executor>,
    exec_lock: Arc<Mutex<()>>,
}
fn daemon(socket: PathBuf, audit_path: Option<&Path>, allow_user_arm: bool) -> Result<i32, String> {
    let euid = unsafe { libc::geteuid() };
    if allow_user_arm && euid == 0 {
        return Err("--allow-user-arm is refused for a root daemon; run it unprivileged for local development".into());
    }
    executor::enable_child_subreaper()
        .map_err(|e| format!("Cannot enable descendant cleanup (child subreaper): {e}"))?;
    let audit = Arc::new(AuditLogger::open(
        audit_path.map(|p| p.to_string_lossy()).as_deref(),
        allow_user_arm || euid != 0,
    )?);
    prepare_socket(&socket)?;
    let listener = bind_socket(&socket)?;
    // Capture the identity (dev/ino) of the socket file this daemon just
    // bound: on shutdown we must unlink only if the path still refers to
    // *this* socket, so an orphaned instance can never delete a live
    // successor daemon's socket.
    let socket_ident = match socket_identity(&socket) {
        Ok(ident) => ident,
        Err(error) => {
            // Do not unlink blindly here: if the path was swapped between
            // bind and stat it may no longer be ours. A leftover stale
            // socket is cleaned up by the next start's prepare_socket().
            return Err(format!(
                "Cannot identify bound socket {}: {error}",
                socket.display()
            ));
        }
    };
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let active = Arc::new(AtomicI32::new(0));
    let state = Arc::new(StateMachine::new(
        audit.clone(),
        active.clone(),
        allow_user_arm,
    ));
    let executor = Arc::new(Executor::new(
        active,
        state.clone(),
        allow_user_arm || euid != 0,
    ));
    let app = Arc::new(Daemon {
        socket: socket.clone(),
        started: Instant::now(),
        state: state.clone(),
        executor,
        exec_lock: Arc::new(Mutex::new(())),
    });
    audit
        .event(
            "DAEMON_START",
            None,
            None,
            None,
            None,
            object(&[
                ("socket_path", json!(socket.to_string_lossy())),
                ("pid", json!(std::process::id())),
                ("allow_user_arm", json!(allow_user_arm)),
            ]),
        )
        .map_err(|e| format!("Cannot audit daemon start: {e}"))?;
    let limiter = Arc::new(ConnectionLimiter::new(MAX_CLIENTS));
    let stop = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, stop.clone()).map_err(|e| e.to_string())?;
    flag::register(SIGINT, stop.clone()).map_err(|e| e.to_string())?;
    let mut loop_error = None;
    let mut transient_errors: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        if let Err(error) = state.check_expiry() {
            loop_error = Some(error);
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                transient_errors = 0;
                // Reap idle clients instead of pinning a thread forever.
                let _ = stream.set_read_timeout(Some(CLIENT_IDLE_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CLIENT_IDLE_TIMEOUT));
                let Some(guard) = limiter.try_acquire() else {
                    // Over the concurrency cap: answer inline (bounded by the
                    // write timeout set above) and close; never allocate a
                    // thread for a connection we are refusing anyway.
                    let response = rpc_error(
                        Value::Null,
                        -32000,
                        format!(
                            "Server busy: more than {MAX_CLIENTS} concurrent connections; retry shortly"
                        ),
                        Some(json!({"reason":"CONNECTION_LIMIT_REACHED"})),
                    );
                    if serde_json::to_writer(&stream, &response).is_ok() {
                        let _ = stream.write_all(b"\n");
                    }
                    continue;
                };
                let app = app.clone();
                match thread::Builder::new()
                    .name("arr-client".into())
                    .spawn(move || {
                        let _ = app.client(stream);
                        drop(guard);
                    }) {
                    Ok(_) => {}
                    // Builder::spawn drops the closure (and thus the
                    // connection guard) on failure; the peer is dropped too.
                    Err(error) => {
                        eprintln!("agent-root-runner: cannot spawn client thread: {error}")
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(e) => match accept_error_policy(&e) {
                AcceptErrorPolicy::Continue => {
                    // Transient accept errors (EMFILE/ENFILE/ECONNABORTED/
                    // EINTR/...) must never terminate the daemon or remove
                    // its socket: back off briefly and keep serving.
                    transient_errors += 1;
                    if transient_errors == 1 || transient_errors.is_multiple_of(100) {
                        eprintln!(
                            "agent-root-runner: transient socket accept error \
                             (continuing, {transient_errors} in a row): {e}"
                        );
                    }
                    thread::sleep(ACCEPT_BACKOFF);
                }
                AcceptErrorPolicy::Fatal => {
                    let shutdown = state.shutdown();
                    remove_owned_socket(&socket, &socket_ident);
                    return match shutdown {
                        Ok(()) => Err(format!("Socket accept failed: {e}")),
                        Err(audit_error) => Err(format!(
                            "Socket accept failed: {e}; shutdown audit failed: {audit_error}"
                        )),
                    };
                }
            },
        }
    }
    let shutdown = state.shutdown();
    remove_owned_socket(&socket, &socket_ident);
    if let Some(error) = loop_error {
        return Err(error);
    }
    shutdown?;
    Ok(0)
}
fn prepare_socket(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("socket path has no parent directory")?;
    prepare_socket_parent(parent, unsafe { libc::geteuid() } == 0)?;
    match fs::symlink_metadata(path) {
        Ok(md) => {
            if !md.file_type().is_socket() {
                return Err(format!(
                    "Path {} exists and is not a socket file.",
                    path.display()
                ));
            }
            match UnixStream::connect(path) {
                Ok(_) => {
                    return Err(format!(
                        "Active daemon already listening on {}",
                        path.display()
                    ));
                }
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ECONNREFUSED) | Some(libc::ENOENT)
                    ) =>
                {
                    fs::remove_file(path).map_err(|e| {
                        format!("Cannot remove stale socket {}: {e}", path.display())
                    })?
                }
                Err(e) => {
                    return Err(format!(
                        "Cannot verify existing socket {}: {e}",
                        path.display()
                    ));
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "Cannot inspect socket path {}: {e}",
                path.display()
            ));
        }
    }
    Ok(())
}
fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    let umask = UmaskGuard::set(0o117);
    let listener =
        UnixListener::bind(path).map_err(|e| format!("Cannot bind {}: {e}", path.display()))?;
    drop(umask);
    Ok(listener)
}
struct UmaskGuard(libc::mode_t);
impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        Self(unsafe { libc::umask(mask) })
    }
}
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// Policy for a failed `accept()`. Resource exhaustion and interrupted /
/// aborted connections are transient: the daemon logs, backs off, and keeps
/// serving. Only genuinely broken listeners take the fatal shutdown path.
enum AcceptErrorPolicy {
    Continue,
    Fatal,
}
fn accept_error_policy(error: &io::Error) -> AcceptErrorPolicy {
    match error.raw_os_error() {
        Some(libc::EMFILE)
        | Some(libc::ENFILE)
        | Some(libc::ENOMEM)
        | Some(libc::ENOBUFS)
        | Some(libc::EAGAIN)
        | Some(libc::ECONNABORTED)
        | Some(libc::EINTR) => AcceptErrorPolicy::Continue,
        None => match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => AcceptErrorPolicy::Continue,
            _ => AcceptErrorPolicy::Fatal,
        },
        _ => AcceptErrorPolicy::Fatal,
    }
}

/// Bounded pool of concurrent client connections. Without it a flood of
/// idle connections exhausts fds (EMFILE) and thread memory.
struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}
impl ConnectionLimiter {
    fn new(max: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max,
        }
    }
    /// Acquire a slot, or `None` when the daemon is at its connection cap.
    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionGuard> {
        let previous = self.active.fetch_add(1, Ordering::SeqCst);
        if previous >= self.max {
            self.active.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(ConnectionGuard {
                limiter: self.clone(),
            })
        }
    }
}
struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// dev/ino identity of the socket file a daemon bound, so shutdown only
/// ever unlinks its own socket file.
#[derive(Debug, Clone, Copy, PartialEq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
}
fn socket_identity(path: &Path) -> io::Result<SocketIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a socket file",
        ));
    }
    Ok(SocketIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}
/// Unlink `path` only if it is still the exact socket file `ident` was
/// captured from. Returns whether the file was removed; a path that is
/// gone or was re-bound by another daemon is left untouched.
fn remove_owned_socket(path: &Path, ident: &SocketIdentity) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.dev() == ident.dev
                && metadata.ino() == ident.ino =>
        {
            fs::remove_file(path).is_ok()
        }
        _ => false,
    }
}
fn prepare_socket_parent(parent: &Path, root_daemon: bool) -> Result<(), String> {
    if root_daemon {
        validate_root_socket_parent(parent)
    } else {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create socket directory {}: {e}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Cannot secure socket directory {}: {e}", parent.display()))?;
        Ok(())
    }
}
fn validate_root_socket_parent(parent: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(parent).map_err(|e| {
        format!(
            "Root daemon requires an existing managed socket directory {}: {e}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "Root daemon socket parent must be a real directory: {}",
            parent.display()
        ));
    }
    if !root_socket_directory_is_safe(metadata.uid(), metadata.permissions().mode()) {
        return Err(format!(
            "Root daemon socket parent must be root-owned and not group/world writable: {}",
            parent.display()
        ));
    }
    let canonical = fs::canonicalize(parent)
        .map_err(|e| format!("Cannot resolve socket parent {}: {e}", parent.display()))?;
    if canonical != parent {
        return Err(format!(
            "Root daemon socket parent must not traverse symlinks or dot segments: {}",
            parent.display()
        ));
    }
    let mut ancestor = canonical.as_path();
    loop {
        let metadata = fs::symlink_metadata(ancestor).map_err(|e| {
            format!(
                "Cannot inspect socket parent ancestor {}: {e}",
                ancestor.display()
            )
        })?;
        let mode = metadata.permissions().mode();
        if !writable_socket_ancestor_is_safe(metadata.uid(), mode) {
            return Err(format!(
                "Root daemon socket path traverses an unsafe writable ancestor: {}",
                ancestor.display()
            ));
        }
        let Some(next) = ancestor.parent() else {
            break;
        };
        if next == ancestor {
            break;
        }
        ancestor = next;
    }
    Ok(())
}
fn root_socket_directory_is_safe(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}
fn writable_socket_ancestor_is_safe(uid: u32, mode: u32) -> bool {
    uid == 0 && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}
fn peer(stream: &UnixStream) -> Peer {
    let mut c = libc::ucred {
        pid: -1,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut c as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || (len as usize) < std::mem::size_of::<libc::ucred>() {
        return Peer {
            pid: -1,
            uid: u32::MAX,
            gid: u32::MAX,
            comm: "[unresolved]".into(),
        };
    }
    let comm = fs::read_to_string(format!("/proc/{}/comm", c.pid))
        .unwrap_or_else(|_| "[exited]".into())
        .trim()
        .to_string();
    Peer {
        pid: c.pid,
        uid: c.uid,
        gid: c.gid,
        comm,
    }
}

impl Daemon {
    fn client(&self, stream: UnixStream) -> io::Result<()> {
        let creds = peer(&stream);
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        loop {
            let line = match read_limited_line(&mut reader) {
                Ok(Some(x)) => x,
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    let resp = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":format!("Line length exceeded buffer limit ({MAX_BUFFER} bytes)")}});
                    serde_json::to_writer(&mut writer, &resp).ok();
                    writer.write_all(b"\n")?;
                    break;
                }
                Err(e) => return Err(e),
            };
            let txt = String::from_utf8_lossy(&line);
            if txt.trim().is_empty() {
                continue;
            }
            let response = self.dispatch(txt.trim(), &creds);
            serde_json::to_writer(&mut writer, &response).map_err(io::Error::other)?;
            writer.write_all(b"\n")?;
            writer.flush()?
        }
        Ok(())
    }
    fn dispatch(&self, line: &str, p: &Peer) -> Value {
        let request: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return rpc_error(Value::Null, -32700, "Parse error: Invalid JSON", None),
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        if !request.is_object() || request["jsonrpc"] != "2.0" || request.get("method").is_none() {
            return rpc_error(
                id,
                -32600,
                "Invalid Request: Malformed JSON-RPC 2.0 payload",
                None,
            );
        }
        let Some(method) = request["method"].as_str() else {
            return rpc_error(id, -32600, "Invalid Request: method must be a string", None);
        };
        let params = if request.get("params").is_none_or(Value::is_null) {
            Map::new()
        } else if let Some(m) = request["params"].as_object() {
            m.clone()
        } else {
            return rpc_error(
                id,
                -32602,
                "Invalid params: Parameters must be an object",
                None,
            );
        };
        match method {
            "ping" => rpc_result(
                id,
                json!({"status":"ok","version":VERSION,"uptime_sec":(self.started.elapsed().as_secs_f64()*100.).round()/100.,"daemon_pid":std::process::id()}),
            ),
            "status" => {
                let mut s = match self.state.status() {
                    Ok(status) => status,
                    Err(error) => {
                        return rpc_error(
                            id,
                            -32603,
                            format!("Internal audit/state error: {error}"),
                            Some(json!({"reason":"AUDIT_FAILURE"})),
                        );
                    }
                };
                if let Some(m) = s.as_object_mut() {
                    m.insert("socket_path".into(), json!(self.socket));
                    m.insert("daemon_pid".into(), json!(std::process::id()));
                }
                rpc_result(id, s)
            }
            "arm" => self.arm_rpc(id, params, p),
            "disarm" => match self.state.disarm(p.uid) {
                Ok(result) => rpc_result(id, result),
                Err(error) => rpc_error(
                    id,
                    -32603,
                    format!("Disarmed, but could not durably audit the transition: {error}"),
                    Some(json!({"reason":"AUDIT_FAILURE"})),
                ),
            },
            "exec" => self.exec_rpc(id, params, p),
            _ => rpc_error(id, -32601, format!("Method '{method}' not found"), None),
        }
    }
    fn arm_rpc(&self, id: Value, pms: Map<String, Value>, p: &Peer) -> Value {
        let forever = match pms.get("forever") {
            None => false,
            Some(Value::Bool(v)) => *v,
            _ => {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: forever must be a boolean",
                    Some(json!({"reason":"INVALID_PARAMS"})),
                );
            }
        };
        let explicit = pms.contains_key("duration_seconds") || pms.contains_key("timeout_seconds");
        if forever && explicit {
            return rpc_error(
                id,
                -32602,
                "Invalid params: 'forever' and a duration are mutually exclusive",
                Some(json!({"reason":"INVALID_PARAMS"})),
            );
        }
        let dval = pms
            .get("duration_seconds")
            .or_else(|| pms.get("timeout_seconds"));
        let duration = match dval {
            None => None,
            Some(Value::Number(n)) => n.as_u64(),
            _ => None,
        };
        if dval.is_some() && duration.is_none() {
            return rpc_error(
                id,
                -32602,
                "Invalid params: duration_seconds must be an integer",
                Some(json!({"reason":"INVALID_PARAMS"})),
            );
        }
        let quota = match pms.get("quota") {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) => n.as_u64(),
            _ => None,
        };
        if pms.get("quota").is_some_and(|v| !v.is_null()) && quota.is_none() {
            return rpc_error(
                id,
                -32602,
                "Invalid params: quota must be a positive integer",
                Some(json!({"reason":"INVALID_PARAMS"})),
            );
        }
        match self.state.arm(duration, quota, forever, p.uid, p.pid) {
            Ok(v) => rpc_result(id, v),
            Err(e) => rpc_error(id, e.code, e.message, e.reason.map(|r| json!({"reason":r}))),
        }
    }
    fn exec_rpc(&self, id: Value, params: Map<String, Value>, p: &Peer) -> Value {
        let command = match params.get("command").or_else(|| params.get("cmd")) {
            Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
            None => {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: 'command' is required",
                    Some(json!({"reason":"INVALID_PARAMS"})),
                );
            }
            Some(Value::String(_)) => {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: 'command' must not be blank",
                    Some(json!({"reason":"INVALID_PARAMS"})),
                );
            }
            _ => {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: 'command' must be a string",
                    Some(json!({"reason":"INVALID_PARAMS"})),
                );
            }
        };
        // Enforce the length cap before any state machine or audit
        // interaction: an oversized payload must not flood the audit log or
        // consume a quota slot, whether the daemon is armed or not.
        if command.chars().count() > MAX_COMMAND {
            return rpc_error(
                id,
                -32602,
                format!("Invalid params: 'command' exceeds the {MAX_COMMAND}-character limit"),
                Some(json!({"reason":"COMMAND_TOO_LONG"})),
            );
        }
        let raw = params
            .get("timeout_seconds")
            .or_else(|| params.get("timeout"));
        let timeout = match raw {
            None | Some(Value::Null) => 60.0,
            Some(Value::Number(n)) => n.as_f64().unwrap_or(-1.),
            _ => -1.,
        };
        if !timeout.is_finite() || timeout <= 0.0 {
            return rpc_error(
                id,
                -32602,
                "Invalid params: 'timeout_seconds' must be a positive number",
                Some(json!({"reason":"INVALID_PARAMS"})),
            );
        }
        let timeout = timeout.min(3600.);
        let workdir = match params.get("workdir") {
            None => Some("/"),
            Some(Value::String(s)) => Some(s.as_str()),
            Some(Value::Null) => None,
            _ => {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: 'workdir' must be a string",
                    Some(json!({"reason":"INVALID_PARAMS"})),
                );
            }
        };
        let env = params.get("env");
        let rejected = match self
            .state
            .reject_if_disarmed(p.pid, p.uid, p.gid, &p.comm, &command)
        {
            Ok(rejected) => rejected,
            Err(error) => {
                return rpc_error(
                    id,
                    -32603,
                    format!("Internal audit/state error: {error}"),
                    Some(json!({"reason":"AUDIT_FAILURE"})),
                );
            }
        };
        if let Some(message) = rejected {
            return admit_error(id, message);
        }
        let _exec = self.exec_lock.lock().unwrap_or_else(|e| e.into_inner());
        let rejected = match self
            .state
            .reject_if_disarmed(p.pid, p.uid, p.gid, &p.comm, &command)
        {
            Ok(rejected) => rejected,
            Err(error) => {
                return rpc_error(
                    id,
                    -32603,
                    format!("Internal audit/state error: {error}"),
                    Some(json!({"reason":"AUDIT_FAILURE"})),
                );
            }
        };
        if let Some(message) = rejected {
            return admit_error(id, message);
        }
        let resolved_workdir = match self.executor.resolve_workdir(workdir) {
            Ok(directory) => directory,
            Err(error) => {
                let (code, message, data) = executor::error(error);
                return rpc_error(id, code, message, Some(data));
            }
        };
        let verdict = guardrails::evaluate_at(&command, &resolved_workdir.path);
        if !verdict.allowed {
            let rule = verdict.rule.unwrap_or("RULE_GUARDRAIL");
            let reason = verdict.reason;
            let category = verdict.category;
            if let Err(error) = self.state.audit_event(
                "EXEC_BLOCKED",
                Some(p.pid),
                Some(p.uid),
                Some(p.gid),
                Some(&p.comm),
                object(&[
                    ("command", json!(command)),
                    ("decision", json!("GUARDRAIL_BLOCKED")),
                    ("rule", json!(rule)),
                    ("reason", json!(reason)),
                    ("exit_code", json!(126)),
                    (
                        "category",
                        category.map(|x| json!(x)).unwrap_or(Value::Null),
                    ),
                ]),
            ) {
                return rpc_error(
                    id,
                    -32603,
                    format!("Internal audit error: {error}"),
                    Some(json!({"reason":"AUDIT_FAILURE"})),
                );
            }
            return rpc_error(
                id,
                -32002,
                format!("Destabilization guardrail violation: {reason}"),
                Some(json!({"rule":rule,"reason":reason,"category":category})),
            );
        }
        let admission = match self.state.admit(p.pid, p.uid, p.gid, &p.comm, &command) {
            Ok(a) => a,
            Err(e) => return admit_error(id, e),
        };
        let effective = admission
            .remaining_seconds
            .filter(|x| *x > 0.)
            .map(|x| timeout.min(x))
            .unwrap_or(timeout);
        if let Err(error) = self.state.audit_event(
            "EXEC_START",
            Some(p.pid),
            Some(p.uid),
            Some(p.gid),
            Some(&p.comm),
            object(&[("command", json!(command)), ("decision", json!("ADMITTED"))]),
        ) {
            return rpc_error(
                id,
                -32603,
                format!("Internal audit error: {error}"),
                Some(json!({"reason":"AUDIT_FAILURE"})),
            );
        }
        match self
            .executor
            .execute(&command, effective, &resolved_workdir, env, &admission)
        {
            Err(e) => {
                if let Err(audit_error) = self.state.refund_quota() {
                    return rpc_error(
                        id,
                        -32603,
                        format!(
                            "Execution failed and quota refund could not be audited: {audit_error}"
                        ),
                        Some(json!({"reason":"AUDIT_FAILURE"})),
                    );
                }
                let (code, msg, data) = executor::error(e);
                rpc_error(id, code, msg, Some(data))
            }
            Ok(result) => {
                let val = result.value();
                let event_type = if result.timed_out {
                    "EXEC_TIMEOUT"
                } else {
                    "EXEC_ALLOWED"
                };
                let mut event_data = object(&[
                    ("command", json!(command)),
                    ("exit_code", json!(result.exit_code)),
                    ("duration_ms", json!(result.duration_ms)),
                    ("timed_out", json!(result.timed_out)),
                ]);
                if !result.timed_out {
                    event_data.insert("decision".into(), json!("ALLOWED"));
                }
                if let Err(error) = self
                    .state
                    .record_execution(event_type, p.pid, p.uid, p.gid, &p.comm, event_data)
                {
                    return rpc_error(
                        id,
                        -32603,
                        format!(
                            "Command completed but its result could not be durably audited: {error}"
                        ),
                        Some(json!({"reason":"AUDIT_FAILURE"})),
                    );
                }
                if result.timed_out {
                    rpc_error(
                        id,
                        -32004,
                        format!("Execution timed out after {effective:?}s"),
                        Some(val),
                    )
                } else {
                    rpc_result(id, val)
                }
            }
        }
    }
}
fn read_limited_line<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    read_limited_line_with(reader, MAX_BUFFER)
}
fn read_limited_line_with<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(buf.len());
        line.extend_from_slice(&buf[..n]);
        reader.consume(n);
        if line.len() > limit {
            // Oversized line. If its terminator was not part of the chunk
            // just consumed, discard the unread remainder so the next line
            // parses cleanly.
            if line.last() != Some(&b'\n') {
                let _ = discard_until_newline(reader);
            }
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}
/// Consume bytes up to and including the next newline without buffering
/// them, bounding memory while resynchronizing after an oversized line.
fn discard_until_newline<R: BufRead>(reader: &mut R) -> io::Result<()> {
    loop {
        let buf = reader.fill_buf()?;
        let (n, saw_newline) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        if n == 0 {
            return Ok(()); // EOF
        }
        reader.consume(n);
        if saw_newline {
            return Ok(());
        }
    }
}
fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
/// Classify a state-layer admission error. Audit-latch failures and malformed
/// parameters must not masquerade as "DISARMED": that mislabels a fail-closed
/// daemon as merely unarmed and hides a real integrity problem from the CLI.
fn admit_error(id: Value, message: String) -> Value {
    let (code, reason) = if message.contains("audit") || message.contains("Audit") {
        (-32603, "AUDIT_FAILURE")
    } else if message.contains("quota") {
        (-32001, "QUOTA_EXHAUSTED")
    } else if message.starts_with("Invalid params") {
        (-32602, "INVALID_PARAMS")
    } else {
        (-32001, "DISARMED")
    };
    rpc_error(id, code, message, Some(json!({"reason": reason})))
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>, data: Option<Value>) -> Value {
    let mut error = json!({"code":code,"message":message.into()});
    if let Some(d) = data {
        error["data"] = d
    }
    json!({"jsonrpc":"2.0","id":id,"error":error})
}

fn mcp(socket: Option<&Path>) -> Result<i32, String> {
    let path = resolve_socket(socket);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut input = stdin.lock();
    loop {
        let line = match read_limited_line_with(&mut input, MAX_MCP_LINE) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                // Oversized request: answer and keep serving the next
                // lines instead of dying. The reader has already discarded
                // the remainder of the offending line.
                let response = rpc_error(
                    Value::Null,
                    -32600,
                    format!("Invalid Request: Line length exceeded limit ({MAX_MCP_LINE} bytes)"),
                    None,
                );
                writeln!(output, "{response}").map_err(|e| e.to_string())?;
                output.flush().map_err(|e| e.to_string())?;
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        // Tolerate non-UTF-8 bytes instead of killing the bridge: the
        // lossy text fails JSON parsing and is answered with -32700, and
        // subsequent requests keep being served.
        let text = String::from_utf8_lossy(&line);
        if let Some(response) = mcp_handle_line(text.trim(), &path) {
            serde_json::to_writer(&mut output, &response).map_err(|e| e.to_string())?;
            output.write_all(b"\n").map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(0)
}
/// Handle one MCP stdio line, returning the JSON-RPC response to emit, or
/// `None` for blank lines and notifications (which are never answered).
fn mcp_handle_line(line: &str, socket: &Path) -> Option<Value> {
    if line.is_empty() {
        return None;
    }
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Some(rpc_error(Value::Null, -32700, "Parse error", None)),
    };
    let notification = req.get("id").is_none();
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req["method"].as_str() else {
        if !notification {
            return Some(rpc_error(
                id,
                -32600,
                "Invalid Request: missing method",
                None,
            ));
        }
        return None;
    };
    if method.starts_with("notifications/") {
        return None;
    }
    let params = match req.get("params") {
        None | Some(Value::Null) => Map::new(),
        Some(value) => match value.as_object() {
            Some(params) => params.clone(),
            None => {
                if !notification {
                    return Some(rpc_error(
                        id,
                        -32602,
                        "Invalid params: expected an object",
                        None,
                    ));
                }
                return None;
            }
        },
    };
    let response = match method {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            let protocol = if ["2024-11-05", "2025-03-26", "2025-06-18"].contains(&requested) {
                requested
            } else {
                "2024-11-05"
            };
            Some(rpc_result(
                id,
                json!({"protocolVersion":protocol,"capabilities":{"tools":{}},"serverInfo":{"name":"agent-root-runner","version":VERSION}}),
            ))
        }
        "tools/list" => Some(rpc_result(id, tools_schema())),
        "ping" => Some(rpc_result(id, json!({"pong":true}))),
        "tools/call" => Some(mcp_call(id, &params, socket)),
        _ => {
            if notification {
                None
            } else {
                Some(rpc_error(
                    id,
                    -32601,
                    format!("Method not found: {method}"),
                    None,
                ))
            }
        }
    };
    if notification {
        return None;
    }
    response
}
fn tools_schema() -> Value {
    json!({"tools":[{"name":"run_privileged_command","description":"Execute a shell command with root privileges via the agent-root-runner daemon. Requires the daemon to be armed (sudo agent-root-runner arm).","inputSchema":{"type":"object","properties":{"command":{"type":"string","description":"Shell command to execute (e.g. 'smartctl -a /dev/nvme0n1', 'systemctl restart nginx')"},"timeout":{"type":"integer","description":"Command timeout in seconds (default: 60)","default":60,"minimum":1,"maximum":3600},"workdir":{"type":"string","description":"Working directory (default: /)","default":"/"},"env":{"type":"object","description":"Additional environment variables","additionalProperties":{"type":"string"}}},"required":["command"]}}]})
}
fn mcp_call(id: Value, params: &Map<String, Value>, socket: &Path) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if name != "run_privileged_command" {
        return rpc_error(id, -32601, format!("Unknown tool: {name}"), None);
    }
    let args = params.get("arguments").and_then(Value::as_object);
    let Some(args) = args else {
        return rpc_error(
            id,
            -32602,
            "Invalid params: 'arguments' must be an object",
            None,
        );
    };
    let Some(command) = args
        .get("command")
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
    else {
        return rpc_error(
            id,
            -32602,
            "Missing or invalid required argument: command",
            None,
        );
    };
    let timeout = match args.get("timeout") {
        None => 60,
        Some(value) => match value.as_u64() {
            Some(value) if value > 0 => value,
            _ => {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid argument: 'timeout' must be a positive integer",
                    None,
                );
            }
        },
    };
    let workdir = match args.get("workdir") {
        None => "/",
        Some(Value::String(value)) => value.as_str(),
        _ => {
            return rpc_error(
                id,
                -32602,
                "Invalid argument: 'workdir' must be a string",
                None,
            );
        }
    };
    let env = args.get("env").cloned().unwrap_or_else(|| json!({}));
    let mut call = Map::new();
    call.insert("command".into(), json!(command));
    call.insert("timeout_seconds".into(), json!(timeout));
    call.insert("workdir".into(), json!(workdir));
    call.insert("env".into(), env);
    let response = match rpc(
        socket,
        "exec",
        call,
        Duration::from_secs(timeout.min(3600) + 10),
    ) {
        Ok(v) => v,
        Err(e) => {
            return rpc_error(
                id,
                -32000,
                format!("Daemon connection failed: {e}"),
                Some(json!({"reason":"DAEMON_ERROR"})),
            );
        }
    };
    if let Some(err) = response.get("error") {
        let code = err["code"].as_i64().unwrap_or(-32603);
        let reason = err["data"]["reason"].as_str().unwrap_or("");
        if (-32004..=-32001).contains(&code) {
            let text = err["message"].as_str().unwrap_or(reason);
            return rpc_result(
                id,
                json!({"content":[{"type":"text","text":text}],"isError":true,"_meta":{"daemon_code":code,"reason":reason,"stderr":err["data"]["stderr"]}}),
            );
        }
        return rpc_error(
            id,
            code,
            err["message"].as_str().unwrap_or("Daemon error"),
            Some(json!({"reason":reason})),
        );
    }
    let result = &response["result"];
    let stdout = result["stdout"].as_str().unwrap_or("");
    let stderr = result["stderr"].as_str().unwrap_or("");
    let code = result["exit_code"].as_i64().unwrap_or(0);
    let text = if code != 0 {
        if !stdout.is_empty() {
            format!("{stdout}\n{stderr}").trim().to_string()
        } else {
            stderr.into()
        }
    } else {
        stdout.into()
    };
    rpc_result(
        id,
        json!({"content":[{"type":"text","text":text}],"isError":code!=0,"_meta":{"exit_code":code,"stderr":stderr,"duration_ms":result["duration_ms"]}}),
    )
}

const UNIT_PATH: &str = "/etc/systemd/system/agent-root-runner.service";
const BIN_PATH: &str = "/usr/local/bin/agent-root-runner";
const MANIFEST_PATH: &str = "/etc/agent-root-runner/installed-files";
fn install() -> Result<i32, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("install requires root. Run with sudo.".into());
    }
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let dest = Path::new(BIN_PATH);
    // Write the unit and the manifest before copying the binary: a partial
    // failure can never leave an untracked binary behind, and `uninstall`
    // can always recover from the manifest.
    let unit = Path::new(UNIT_PATH);
    if let Some(parent) = unit.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?
    }
    let group = admin_group();
    write_secure(
        unit,
        unit_with_admin_group(group.as_deref()).as_bytes(),
        0o644,
    )?;
    match group.as_deref() {
        Some(group) => {
            println!("Installed systemd unit: {UNIT_PATH} (socket admin group: {group})")
        }
        None => println!(
            "Installed systemd unit: {UNIT_PATH} (no admin group found; socket is root-only)"
        ),
    }
    let mpath = Path::new(MANIFEST_PATH);
    if let Some(parent) = mpath.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    write_secure(
        mpath,
        format!("{BIN_PATH}\n{UNIT_PATH}\n").as_bytes(),
        0o600,
    )?;
    if source != dest {
        let tmp = Path::new("/usr/local/bin/.agent-root-runner.new");
        let _ = fs::remove_file(tmp);
        fs::copy(&source, tmp).map_err(|e| format!("Could not install executable: {e}"))?;
        fs::set_permissions(tmp, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        fs::rename(tmp, dest).map_err(|e| format!("Could not activate executable: {e}"))?;
        println!("Installed: {BIN_PATH}");
    } else {
        println!("Reinstalled in place: {BIN_PATH}");
    }
    let _ = systemctl(&["daemon-reload"]);
    let _ = systemctl(&["enable", "agent-root-runner.service"]);
    if systemctl(&["restart", "agent-root-runner.service"]) != 0 {
        let _ = systemctl(&["status", "agent-root-runner.service", "--no-pager"]);
        return Err("failed to start agent-root-runner.service".into());
    }
    thread::sleep(Duration::from_millis(500));
    if systemctl(&["is-active", "--quiet", "agent-root-runner.service"]) != 0 {
        let _ = systemctl(&["status", "agent-root-runner.service", "--no-pager"]);
        return Err("agent-root-runner.service is not active after start".into());
    }
    println!("agent-root-runner.service is active.");
    Ok(0)
}
/// First standard administrative group present on this host, in order of
/// preference. Keeps the documented "admin-group members may reach the
/// socket" model working on distros without `wheel` (Debian/Ubuntu use
/// `sudo`).
fn admin_group() -> Option<String> {
    ["wheel", "sudo", "adm"]
        .into_iter()
        .find(|name| group_exists(name))
        .map(str::to_string)
}
fn group_exists(name: &str) -> bool {
    match std::ffi::CString::new(name) {
        Ok(c) => unsafe { !libc::getgrnam(c.as_ptr()).is_null() },
        Err(_) => false,
    }
}
/// The checked-in unit intentionally carries no `Group=` line; the installer
/// appends one only when a portable admin group exists on the target host.
fn unit_with_admin_group(group: Option<&str>) -> String {
    match group {
        Some(group) => UNIT_TEXT.replace("User=root\n", &format!("User=root\nGroup={group}\n")),
        None => UNIT_TEXT.to_string(),
    }
}
fn uninstall() -> Result<i32, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("uninstall requires root. Run with sudo.".into());
    }
    let _ = systemctl(&["stop", "agent-root-runner.service"]);
    let _ = systemctl(&["disable", "agent-root-runner.service"]);
    let manifest = fs::read_to_string(MANIFEST_PATH).unwrap_or_default();
    // A missing/empty manifest means a partial install: treat everything as
    // tracked so uninstall recovers it instead of leaving it behind forever.
    let untracked = manifest.trim().is_empty();
    let mut incomplete = false;
    if untracked || manifest.lines().any(|x| x == UNIT_PATH) {
        match fs::remove_file(UNIT_PATH) {
            Ok(()) => println!("Removed: {UNIT_PATH}"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => {
                incomplete = true;
                eprintln!("Warning: could not remove {UNIT_PATH}: {e}");
            }
        }
    }
    let _ = systemctl(&["daemon-reload"]);
    let _ = systemctl(&["reset-failed", "agent-root-runner.service"]);
    if untracked || manifest.lines().any(|x| x == BIN_PATH) {
        // Remove the binary even when uninstall runs from the installed
        // path itself: unlinking a running ELF is allowed on Linux (the
        // process keeps its mapping), and skipping it silently made the
        // binary unremovable in practice.
        match fs::remove_file(BIN_PATH) {
            Ok(()) => println!("Removed: {BIN_PATH}"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => {
                incomplete = true;
                eprintln!("Warning: could not remove {BIN_PATH}: {e}");
            }
        }
    }
    if incomplete {
        // Keep the manifest so a retry can finish cleanup; deleting it now
        // would make the leftovers permanently unremovable.
        eprintln!("Note: {MANIFEST_PATH} kept so uninstall can be retried.");
    } else {
        let _ = fs::remove_file(MANIFEST_PATH);
        let _ = fs::remove_dir("/etc/agent-root-runner");
    }
    let _ = fs::remove_dir("/run/agent-root-runner");
    println!("Note: audit logs under /var/log/agent-root-runner are preserved.");
    Ok(0)
}
fn write_secure(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
}
fn systemctl(args: &[&str]) -> i32 {
    // Do not resolve a root management utility through a caller-controlled PATH.
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(args).env_remove("LD_PRELOAD");
    match c.status() {
        Ok(s) => s.code().unwrap_or(128),
        Err(e) => {
            eprintln!("Could not run systemctl: {e}");
            128
        }
    }
}

#[cfg(test)]
mod socket_parent_tests {
    use super::*;

    #[test]
    fn root_socket_parent_policy_rejects_shared_or_redirected_paths_without_mutation() {
        assert!(root_socket_directory_is_safe(0, 0o750));
        assert!(!root_socket_directory_is_safe(0, 0o1777));
        assert!(!root_socket_directory_is_safe(1000, 0o700));
        assert!(writable_socket_ancestor_is_safe(0, 0o755));
        assert!(writable_socket_ancestor_is_safe(0, 0o1777));
        assert!(!writable_socket_ancestor_is_safe(1000, 0o1777));
        assert!(!writable_socket_ancestor_is_safe(1000, 0o700));
        assert!(!writable_socket_ancestor_is_safe(0, 0o0777));

        let root = std::env::temp_dir().join(format!(
            "arr-socket-parent-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let direct = root.join("shared");
        fs::create_dir(&direct).unwrap();
        fs::set_permissions(&direct, fs::Permissions::from_mode(0o1777)).unwrap();
        let shared_mode_before = fs::metadata(&direct).unwrap().permissions().mode() & 0o7777;
        assert!(prepare_socket_parent(&direct, true).is_err());
        assert_eq!(
            fs::metadata(&direct).unwrap().permissions().mode() & 0o7777,
            shared_mode_before
        );

        let owner_writable = root.join("owner-writable");
        fs::create_dir(&owner_writable).unwrap();
        fs::set_permissions(&owner_writable, fs::Permissions::from_mode(0o700)).unwrap();
        let owner_mode_before =
            fs::metadata(&owner_writable).unwrap().permissions().mode() & 0o7777;
        assert!(prepare_socket_parent(&owner_writable, true).is_err());
        assert_eq!(
            fs::metadata(&owner_writable).unwrap().permissions().mode() & 0o7777,
            owner_mode_before
        );

        let redirected = root.join("redirected");
        std::os::unix::fs::symlink(&direct, &redirected).unwrap();
        assert!(prepare_socket_parent(&redirected, true).is_err());
        assert_eq!(
            fs::metadata(&direct).unwrap().permissions().mode() & 0o7777,
            shared_mode_before
        );
        let shared_before = fs::metadata("/tmp").unwrap();
        assert!(prepare_socket_parent(Path::new("/tmp"), true).is_err());
        let shared_after = fs::metadata("/tmp").unwrap();
        assert_eq!(shared_before.uid(), shared_after.uid());
        assert_eq!(
            shared_before.permissions().mode() & 0o7777,
            shared_after.permissions().mode() & 0o7777
        );
        fs::remove_dir_all(root).unwrap();
    }

    // ---- Regression tests: accept-error policy must never kill the daemon ----

    #[test]
    fn accept_error_policy_treats_resource_errors_as_transient() {
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::ENOBUFS,
            libc::EAGAIN,
            libc::ECONNABORTED,
            libc::EINTR,
        ] {
            assert!(
                matches!(
                    accept_error_policy(&io::Error::from_raw_os_error(errno)),
                    AcceptErrorPolicy::Continue
                ),
                "accept() errno {errno} must never terminate the daemon"
            );
        }
        assert!(matches!(
            accept_error_policy(&io::Error::from(io::ErrorKind::WouldBlock)),
            AcceptErrorPolicy::Continue
        ));
        assert!(matches!(
            accept_error_policy(&io::Error::from(io::ErrorKind::Interrupted)),
            AcceptErrorPolicy::Continue
        ));
        for errno in [libc::EACCES, libc::EINVAL, libc::EBADF] {
            assert!(
                matches!(
                    accept_error_policy(&io::Error::from_raw_os_error(errno)),
                    AcceptErrorPolicy::Fatal
                ),
                "accept() errno {errno} is a fatal listener defect"
            );
        }
    }

    #[test]
    fn connection_limiter_bounds_concurrent_clients() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let first = limiter.try_acquire().expect("first connection allowed");
        let _second = limiter.try_acquire().expect("second connection allowed");
        assert!(
            limiter.try_acquire().is_none(),
            "a third connection must be refused without allocating a thread"
        );
        drop(_second);
        let third = limiter.try_acquire().expect("freed slot is reusable");
        drop(first);
        drop(third);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn shutdown_unlinks_only_the_socket_this_daemon_bound() {
        let root = std::env::temp_dir().join(format!(
            "arr-socket-identity-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("runner.sock");
        let first = UnixListener::bind(&path).unwrap();
        let ident_first = socket_identity(&path).unwrap();
        // A successor daemon re-binds the path while the first still runs.
        fs::remove_file(&path).unwrap();
        let second = UnixListener::bind(&path).unwrap();
        let ident_second = socket_identity(&path).unwrap();
        assert_ne!(
            (ident_first.dev, ident_first.ino),
            (ident_second.dev, ident_second.ino)
        );
        // The orphaned daemon's shutdown must leave the live socket alone...
        assert!(!remove_owned_socket(&path, &ident_first));
        assert!(
            path.exists(),
            "orphan shutdown deleted a live daemon socket"
        );
        assert!(UnixStream::connect(&path).is_ok());
        // ...while its real owner still removes it.
        assert!(remove_owned_socket(&path, &ident_second));
        assert!(!path.exists());
        // A vanished or replaced path is a no-op, never an error.
        assert!(!remove_owned_socket(&path, &ident_second));
        drop(first);
        drop(second);
        fs::remove_dir_all(&root).unwrap();
    }

    // ---- Regression tests: exec admission order and audit safety ----

    fn exec_rpc_test_daemon(audit: &Path) -> (Daemon, Arc<StateMachine>) {
        let logger = Arc::new(AuditLogger::open(audit.to_str(), true).unwrap());
        let pgid = Arc::new(AtomicI32::new(0));
        let state = Arc::new(StateMachine::new(logger, pgid.clone(), false));
        let executor = Arc::new(Executor::new(pgid, state.clone(), true));
        let daemon = Daemon {
            socket: PathBuf::from("/nonexistent/runner.sock"),
            started: Instant::now(),
            state: state.clone(),
            executor,
            exec_lock: Arc::new(Mutex::new(())),
        };
        (daemon, state)
    }
    fn test_peer() -> Peer {
        Peer {
            pid: 1,
            uid: 0,
            gid: 0,
            comm: "test".into(),
        }
    }

    #[test]
    fn missing_or_blank_command_is_rejected_without_consuming_a_quota_slot() {
        let root = std::env::temp_dir().join(format!(
            "arr-exec-blank-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let audit = root.join("audit.log");
        let (daemon, state) = exec_rpc_test_daemon(&audit);
        state.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let peer = test_peer();

        for params in [Map::new(), {
            let mut p = Map::new();
            p.insert("command".into(), json!("   "));
            p
        }] {
            let response = daemon.exec_rpc(json!(1), params, &peer);
            assert_eq!(
                response["error"]["code"], -32602,
                "blank/missing command must be a usage error: {response}"
            );
        }

        let status = state.status().unwrap();
        assert_eq!(status["is_armed"], true, "blank exec must not disarm");
        assert_eq!(
            status["quota_remaining"], 1,
            "blank exec must not burn the last quota slot"
        );
        assert_eq!(status["commands_executed"], 0);
        let log = fs::read_to_string(&audit).unwrap();
        assert!(
            !log.contains("EXEC_START") && !log.contains("EXEC_ALLOWED"),
            "blank exec reached the audit log: {log}"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn over_length_command_is_rejected_before_any_audit_write() {
        let root = std::env::temp_dir().join(format!(
            "arr-exec-toolong-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let audit = root.join("audit.log");
        let (daemon, state) = exec_rpc_test_daemon(&audit);
        let peer = test_peer();
        let huge = "x".repeat(MAX_COMMAND + 1);
        let mut params = Map::new();
        params.insert("command".into(), json!(huge));

        // Disarmed: the old code audited the full command in EXEC_REJECTED.
        let before = fs::metadata(&audit).map(|m| m.len()).unwrap_or(0);
        let response = daemon.exec_rpc(json!(1), params.clone(), &peer);
        assert_eq!(
            response["error"]["code"], -32602,
            "over-length command must be a usage error: {response}"
        );
        assert_eq!(response["error"]["data"]["reason"], "COMMAND_TOO_LONG");
        assert_eq!(
            fs::metadata(&audit).map(|m| m.len()).unwrap_or(0),
            before,
            "over-length command reached the audit log"
        );
        assert!(
            !fs::read_to_string(&audit)
                .unwrap()
                .contains("EXEC_REJECTED")
        );

        // Armed: it must not consume the final quota slot either.
        state.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let response = daemon.exec_rpc(json!(2), params, &peer);
        assert_eq!(response["error"]["code"], -32602);
        let status = state.status().unwrap();
        assert_eq!(status["is_armed"], true);
        assert_eq!(status["quota_remaining"], 1);
        fs::remove_dir_all(&root).unwrap();
    }

    // ---- Regression tests: CLI argv must stay data, not shell code ----

    #[test]
    fn exec_cli_argv_is_shell_quoted_word_by_word() {
        assert_eq!(
            shell_join(&["printf".to_string(), "%s".to_string(), "a;b".to_string()]),
            "printf %s 'a;b'"
        );
        assert_eq!(
            shell_join(&["echo".to_string(), "it's".to_string(), "a b|c".to_string()]),
            "echo 'it'\\''s' 'a b|c'"
        );
        assert_eq!(shell_join(&[]), "");
        assert_eq!(shell_join(&["".to_string()]), "''");
        assert_eq!(
            shell_join(&[
                "systemctl".to_string(),
                "restart".to_string(),
                "nginx.service".to_string()
            ]),
            "systemctl restart nginx.service"
        );
        // `VAR=x cmd` style assignments keep working unquoted.
        assert_eq!(
            shell_join(&["FOO=bar".to_string(), "cmd".to_string()]),
            "FOO=bar cmd"
        );
    }

    #[test]
    fn quoted_argv_does_not_execute_a_second_command() {
        let joined = shell_join(&["printf".to_string(), "%s".to_string(), "a;b".to_string()]);
        let output = Command::new("bash")
            .arg("-c")
            .arg(&joined)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "argv data must not run as a second command: {joined}"
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), "a;b");
        assert!(String::from_utf8_lossy(&output.stderr).trim().is_empty());
    }

    // ---- Regression tests: MCP stdio robustness ----

    #[test]
    fn mcp_stdin_survives_bad_utf8_and_oversized_lines() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\xff\xfe not utf8, not json\n");
        data.extend_from_slice(&[b'a'; 200]);
        data.extend_from_slice(b"\n");
        data.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n");
        let mut reader = io::Cursor::new(data);
        let socket = Path::new("/nonexistent/runner.sock");

        // Non-UTF-8 line: answered with a parse error, never fatal.
        let line = read_limited_line_with(&mut reader, 128).unwrap().unwrap();
        let text = String::from_utf8_lossy(&line);
        let response = mcp_handle_line(text.trim(), socket).unwrap();
        assert_eq!(response["error"]["code"], -32700);

        // Oversized line: rejected without unbounded buffering, and the
        // reader has already resynchronized past its newline.
        let error = read_limited_line_with(&mut reader, 128).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        // The next valid request is still served.
        let line = read_limited_line_with(&mut reader, 128).unwrap().unwrap();
        let text = String::from_utf8_lossy(&line);
        let response = mcp_handle_line(text.trim(), socket).unwrap();
        assert_eq!(response["result"]["pong"], true);

        // Same oversized traffic delivered in small chunks: the limit trips
        // before the newline has been consumed, so the reader must
        // resynchronize internally or the following line would be corrupted.
        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(&[b'a'; 200]);
        chunk_data.extend_from_slice(b"\n");
        chunk_data.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n");
        let mut chunked = io::BufReader::with_capacity(16, io::Cursor::new(chunk_data));
        let error = read_limited_line_with(&mut chunked, 128).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let line = read_limited_line_with(&mut chunked, 128).unwrap().unwrap();
        let text = String::from_utf8_lossy(&line);
        let response = mcp_handle_line(text.trim(), socket).unwrap();
        assert_eq!(response["result"]["pong"], true);
    }

    // ---- Regression tests: exit-code mapping and portable unit rendering ----

    #[test]
    fn invalid_params_maps_to_usage_exit_code_two() {
        assert_eq!(daemon_error_exit(-32602), 2);
        assert_eq!(daemon_error_exit(-32001), 125);
        assert_eq!(daemon_error_exit(-32002), 126);
        assert_eq!(daemon_error_exit(-32003), 1);
        assert_eq!(daemon_error_exit(-32004), 124);
        assert_eq!(daemon_error_exit(-32603), 128);
        assert_eq!(daemon_error_exit(0), 128);
    }

    #[test]
    fn unit_render_uses_portable_admin_group_or_root_only() {
        let with = unit_with_admin_group(Some("sudo"));
        assert!(with.lines().any(|l| l == "Group=sudo"));
        assert!(!with.lines().any(|l| l.starts_with("Group=wheel")));

        let without = unit_with_admin_group(None);
        assert!(
            without.lines().all(|l| !l.starts_with("Group=")),
            "checked-in unit must not hardcode a distro-specific group"
        );
        assert!(without.contains("User=root"));

        // Detection only ever returns a group that exists on this host.
        match admin_group() {
            Some(group) => {
                assert!(["wheel", "sudo", "adm"].contains(&group.as_str()));
                assert!(group_exists(&group));
            }
            None => assert!(
                ["wheel", "sudo", "adm"].iter().all(|g| !group_exists(g)),
                "admin_group must not miss an existing admin group"
            ),
        }
    }

    #[test]
    fn admit_errors_are_classified_by_cause() {
        let id = json!(1);
        let audit = admit_error(
            id.clone(),
            "Audit logging previously failed; the daemon is fail-closed.".into(),
        );
        assert_eq!(audit["error"]["code"], -32603);
        assert_eq!(audit["error"]["data"]["reason"], "AUDIT_FAILURE");

        let quota = admit_error(
            id.clone(),
            "Execution quota exhausted. Re-arm with 'sudo agent-root-runner arm'.".into(),
        );
        assert_eq!(quota["error"]["code"], -32001);
        assert_eq!(quota["error"]["data"]["reason"], "QUOTA_EXHAUSTED");

        let invalid = admit_error(
            id.clone(),
            "Invalid params: 'command' must not be blank or contain null bytes.".into(),
        );
        assert_eq!(invalid["error"]["code"], -32602);
        assert_eq!(invalid["error"]["data"]["reason"], "INVALID_PARAMS");

        let disarmed = admit_error(
            id,
            "Service is DISARMED. Run 'sudo agent-root-runner arm' to enable.".into(),
        );
        assert_eq!(disarmed["error"]["code"], -32001);
        assert_eq!(disarmed["error"]["data"]["reason"], "DISARMED");
    }
}
