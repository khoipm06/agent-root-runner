use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_agent-root-runner");

struct Daemon {
    child: Child,
    directory: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    fn start() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "arr-release-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).unwrap();
        let socket = directory.join("runner.sock");
        let mut command = Command::new(BIN);
        command
            .arg("daemon")
            .arg("--socket")
            .arg(&socket)
            .arg("--audit-log")
            .arg(directory.join("audit.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if unsafe { libc::geteuid() } != 0 {
            command.arg("--allow-user-arm");
        }
        let child = command.spawn().unwrap();
        let mut daemon = Self {
            child,
            directory,
            socket,
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if daemon.child.try_wait().unwrap().is_some() {
                panic!("release daemon exited during startup");
            }
            if daemon.socket.exists() && request(&daemon.socket, "ping", json!({})).is_ok() {
                return daemon;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("release daemon did not become ready");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn request(socket: &Path, method: &str, params: Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    writeln!(
        stream,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
    )
    .map_err(|error| error.to_string())?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&response).map_err(|error| error.to_string())
}

#[test]
fn release_elf_starts_daemon_and_handles_a_safe_shell_parse_probe() {
    let binary = Path::new(BIN);
    assert!(fs::metadata(binary).unwrap().is_file());
    let bytes = fs::read(binary).unwrap();
    assert!(
        bytes.starts_with(b"\x7fELF"),
        "test executable is not an ELF"
    );
    assert!(
        Command::new(binary)
            .arg("--help")
            .status()
            .unwrap()
            .success()
    );

    let mut daemon = Daemon::start();
    let ping = request(&daemon.socket, "ping", json!({})).unwrap();
    assert_eq!(ping["result"]["status"], "ok");
    let arm = request(&daemon.socket, "arm", json!({"duration_seconds":30})).unwrap();
    assert!(
        arm.get("result").is_some(),
        "release daemon arm failed: {arm}"
    );
    let response = request(&daemon.socket, "exec", json!({"command":"echo `id -u`"})).unwrap();
    assert_eq!(response["result"]["exit_code"], 0, "{response}");
    assert!(
        !response["result"]["stdout"]
            .as_str()
            .unwrap()
            .trim()
            .is_empty()
    );
    assert!(daemon.child.try_wait().unwrap().is_none());
}
