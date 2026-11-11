use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ksni::blocking::TrayMethods;
use ksni::menu::*;
use ksni::{Category, Status, ToolTip};
use serde_json::Map;

pub struct TrayLock {
    _file: std::fs::File,
}

pub fn tray_lock_path_for_uid(uid: u32) -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("agent-root-runner-tray.lock")
    } else {
        let run_user = PathBuf::from(format!("/run/user/{uid}"));
        if run_user.exists() {
            run_user.join("agent-root-runner-tray.lock")
        } else {
            std::env::temp_dir().join(format!("agent-root-runner-tray-{uid}.lock"))
        }
    }
}

pub fn try_acquire_tray_lock() -> Result<Option<TrayLock>, String> {
    let uid = unsafe { libc::getuid() };
    let path = tray_lock_path_for_uid(uid);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("Cannot open lock file {}: {e}", path.display()))?;

    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(Some(TrayLock { _file: file }))
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            Ok(None)
        } else {
            Err(format!("Failed to lock {}: {err}", path.display()))
        }
    }
}

pub fn is_tray_running_for_uid(uid: u32) -> bool {
    let path = tray_lock_path_for_uid(uid);
    if !path.exists() {
        return false;
    }
    match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => {
            let fd = file.as_raw_fd();
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                unsafe { libc::flock(fd, libc::LOCK_UN) };
                false
            } else {
                true
            }
        }
        Err(_) => false,
    }
}

fn get_username_by_uid(uid: u32) -> Option<String> {
    unsafe {
        let passwd = libc::getpwuid(uid);
        if !passwd.is_null() && !(*passwd).pw_name.is_null() {
            Some(
                std::ffi::CStr::from_ptr((*passwd).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        }
    }
}

pub fn ensure_tray_running() {
    let (target_uid, target_user) = if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
        let uid: u32 = sudo_uid.parse().unwrap_or(0);
        let user = std::env::var("SUDO_USER")
            .ok()
            .or_else(|| get_username_by_uid(uid));
        (uid, user)
    } else if let Ok(pk_uid) = std::env::var("PKEXEC_UID") {
        let uid: u32 = pk_uid.parse().unwrap_or(0);
        let user = get_username_by_uid(uid);
        (uid, user)
    } else {
        (unsafe { libc::getuid() }, None)
    };

    if target_uid != 0 && is_tray_running_for_uid(target_uid) {
        return;
    }

    if let Some(user) = target_user {
        if let Err(e) = Command::new("su")
            .args([
                "-",
                &user,
                "-c",
                "nohup /usr/local/bin/agent-root-runner tray &",
            ])
            .spawn()
        {
            eprintln!("Warning: failed to spawn tray indicator: {e}");
        }
    } else {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-root-runner"));
        if let Err(e) = Command::new(exe).arg("tray").spawn() {
            eprintln!("Warning: failed to spawn tray indicator: {e}");
        }
    }
}

#[derive(Clone, Debug)]
pub struct RootRunnerTray {
    socket: PathBuf,
    available: bool,
    armed: bool,
    forever: bool,
    remaining_seconds: Option<u64>,
    quota_remaining: Option<u64>,
    commands_executed: u64,
}

impl RootRunnerTray {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            available: false,
            armed: false,
            forever: false,
            remaining_seconds: None,
            quota_remaining: None,
            commands_executed: 0,
        }
    }
}

impl ksni::Tray for RootRunnerTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "agent-root-runner-tray".into()
    }

    fn category(&self) -> Category {
        Category::SystemServices
    }

    fn title(&self) -> String {
        if !self.available {
            "Agent Root Runner (Offline)".into()
        } else if self.armed {
            if self.forever {
                "ARMED (Forever)".into()
            } else if let Some(rem) = self.remaining_seconds {
                format!("ARMED ({rem}s)")
            } else {
                "ARMED".into()
            }
        } else {
            "DISARMED".into()
        }
    }

    fn icon_name(&self) -> String {
        if self.armed {
            "security-high".into()
        } else {
            "security-low".into()
        }
    }

    fn status(&self) -> Status {
        Status::Active
    }

    fn tool_tip(&self) -> ToolTip {
        let description = if !self.available {
            "Daemon is unreachable".into()
        } else if self.armed {
            let time_str = if self.forever {
                "No time limit".into()
            } else {
                format!("{}s remaining", self.remaining_seconds.unwrap_or(0))
            };
            let quota_str = match self.quota_remaining {
                Some(q) => format!("{q} commands left"),
                None => "Unlimited quota".into(),
            };
            format!("Privileged execution enabled\n{time_str}\n{quota_str}")
        } else {
            "Privileged execution is disabled".into()
        };

        ToolTip {
            icon_name: self.icon_name(),
            icon_pixmap: Vec::new(),
            title: "Agent Root Runner".into(),
            description,
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = Vec::new();

        let status_label = if !self.available {
            "Status: Daemon Offline".to_string()
        } else if self.armed {
            if self.forever {
                "Status: ARMED (Forever)".to_string()
            } else {
                format!(
                    "Status: ARMED ({}s left)",
                    self.remaining_seconds.unwrap_or(0)
                )
            }
        } else {
            "Status: DISARMED".to_string()
        };

        items.push(
            StandardItem {
                label: status_label,
                enabled: false,
                ..Default::default()
            }
            .into(),
        );

        if self.armed {
            if let Some(quota) = self.quota_remaining {
                items.push(
                    StandardItem {
                        label: format!("Quota: {quota} remaining"),
                        enabled: false,
                        ..Default::default()
                    }
                    .into(),
                );
            }
        }

        items.push(MenuItem::Separator);

        if self.armed {
            let sock_5 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "Extend (+5 minutes)".into(),
                    icon_name: "document-revert".into(),
                    activate: Box::new(move |_| {
                        spawn_extend(&sock_5, &["--seconds", "300"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_15 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "Extend (+15 minutes)".into(),
                    icon_name: "document-revert".into(),
                    activate: Box::new(move |_| {
                        spawn_extend(&sock_15, &["--seconds", "900"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_q5 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "Extend (+5 commands)".into(),
                    icon_name: "list-add".into(),
                    activate: Box::new(move |_| {
                        spawn_extend(&sock_q5, &["--quota", "5"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_q10 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "Extend (+10 commands)".into(),
                    icon_name: "list-add".into(),
                    activate: Box::new(move |_| {
                        spawn_extend(&sock_q10, &["--quota", "10"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_ext_custom = self.socket.clone();
            items.push(
                StandardItem {
                    label: "Extend (Custom...)".into(),
                    icon_name: "configure".into(),
                    activate: Box::new(move |_| {
                        prompt_custom_extend(sock_ext_custom.clone());
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock = self.socket.clone();
            items.push(
                StandardItem {
                    label: "Disarm".into(),
                    icon_name: "security-low".into(),
                    activate: Box::new(move |_| {
                        let _ = crate::rpc(&sock, "disarm", Map::new(), Duration::from_secs(5));
                    }),
                    ..Default::default()
                }
                .into(),
            );
        } else {
            let sock_5 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "ARM (5 minutes)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(move |_| {
                        spawn_arm(&sock_5, &["--duration", "300"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_15 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "ARM (15 minutes)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(move |_| {
                        spawn_arm(&sock_15, &["--duration", "900"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_q5 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "ARM (5 commands)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(move |_| {
                        spawn_arm(&sock_q5, &["--forever", "--quota", "5"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_q10 = self.socket.clone();
            items.push(
                StandardItem {
                    label: "ARM (10 commands)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(move |_| {
                        spawn_arm(&sock_q10, &["--forever", "--quota", "10"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_forever = self.socket.clone();
            items.push(
                StandardItem {
                    label: "ARM (Forever)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(move |_| {
                        spawn_arm(&sock_forever, &["--forever"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let sock_custom = self.socket.clone();
            items.push(
                StandardItem {
                    label: "ARM (Custom...)".into(),
                    icon_name: "configure".into(),
                    activate: Box::new(move |_| {
                        prompt_custom_arm(sock_custom.clone());
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }

        items.push(MenuItem::Separator);

        items.push(
            StandardItem {
                label: "Quit Tray".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| {
                    std::process::exit(0);
                }),
                ..Default::default()
            }
            .into(),
        );

        items
    }
}

fn spawn_extend(socket: &Path, extra_args: &[&str]) {
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/agent-root-runner"));
    let mut args = vec![exe.to_string_lossy().into_owned()];
    if socket != Path::new("/run/agent-root-runner/runner.sock") {
        args.push("--socket".to_string());
        args.push(socket.to_string_lossy().into_owned());
    }
    args.push("extend".to_string());
    for arg in extra_args {
        args.push(arg.to_string());
    }
    let _ = Command::new("pkexec").args(&args).spawn();
}

fn prompt_custom_arm(socket: PathBuf) {
    std::thread::spawn(move || {
        if let Some((duration, quota)) = show_custom_dialog("Agent Root Runner - Custom ARM", true)
        {
            let mut args = Vec::new();
            if let Some(d) = duration {
                if d == 0 {
                    args.push("--forever".to_string());
                } else {
                    args.push("--duration".to_string());
                    args.push(d.to_string());
                }
            } else if let Some(q) = quota {
                args.push("--forever".to_string());
                args.push("--quota".to_string());
                args.push(q.to_string());
            } else {
                args.push("--forever".to_string());
            }
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            spawn_arm(&socket, &args_ref);
        }
    });
}

fn prompt_custom_extend(socket: PathBuf) {
    std::thread::spawn(move || {
        if let Some((seconds, quota)) = show_custom_dialog("Agent Root Runner - Extend ARM", false)
        {
            let mut args = Vec::new();
            if let Some(s) = seconds {
                if s > 0 {
                    args.push("--seconds".to_string());
                    args.push(s.to_string());
                }
            } else if let Some(q) = quota {
                if q > 0 {
                    args.push("--quota".to_string());
                    args.push(q.to_string());
                }
            }
            if !args.is_empty() {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                spawn_extend(&socket, &args_ref);
            }
        }
    });
}

fn show_custom_dialog(title: &str, is_arm: bool) -> Option<(Option<u64>, Option<u64>)> {
    if Path::new("/usr/bin/kdialog").exists() {
        let type_out = Command::new("kdialog")
            .args([
                "--title",
                title,
                "--radiolist",
                "Select limit type:",
                "time",
                "Duration (Minutes)",
                "on",
                "quota",
                "Command Quota (Count)",
                "off",
            ])
            .output()
            .ok()?;
        if !type_out.status.success() {
            return None;
        }
        let choice = String::from_utf8_lossy(&type_out.stdout).trim().to_string();

        if choice == "quota" {
            let prompt = if is_arm {
                "Command quota limit (number of commands):"
            } else {
                "Additional command quota to add:"
            };
            let out = Command::new("kdialog")
                .args([
                    "--title",
                    title,
                    "--inputbox",
                    prompt,
                    if is_arm { "10" } else { "5" },
                ])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let quota_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let quota = quota_str.parse::<u64>().ok().filter(|&q| q > 0);
            Some((None, quota))
        } else {
            let prompt = if is_arm {
                "Duration in minutes (0 or empty for forever):"
            } else {
                "Additional minutes to add:"
            };
            let out = Command::new("kdialog")
                .args([
                    "--title",
                    title,
                    "--inputbox",
                    prompt,
                    if is_arm { "15" } else { "10" },
                ])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let dur_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let duration = if dur_str.is_empty() || dur_str == "0" {
                if is_arm { Some(0) } else { None }
            } else if let Ok(mins) = dur_str.parse::<u64>() {
                Some(mins.saturating_mul(60))
            } else {
                None
            };
            Some((duration, None))
        }
    } else if Path::new("/usr/bin/zenity").exists() {
        let type_out = Command::new("zenity")
            .args([
                "--list",
                "--radiolist",
                &format!("--title={title}"),
                "--text=Select limit type:",
                "--column=",
                "--column=Type",
                "--column=ID",
                "--hide-column=3",
                "--print-column=3",
                "TRUE",
                "Duration (Minutes)",
                "time",
                "FALSE",
                "Command Quota (Count)",
                "quota",
            ])
            .output()
            .ok()?;
        if !type_out.status.success() {
            return None;
        }
        let choice = String::from_utf8_lossy(&type_out.stdout).trim().to_string();

        if choice == "quota" {
            let prompt = if is_arm {
                "Command quota limit (number of commands):"
            } else {
                "Additional command quota to add:"
            };
            let out = Command::new("zenity")
                .args([
                    "--entry",
                    &format!("--title={title}"),
                    &format!("--text={prompt}"),
                    &format!("--entry-text={}", if is_arm { "10" } else { "5" }),
                ])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let quota_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let quota = quota_str.parse::<u64>().ok().filter(|&q| q > 0);
            Some((None, quota))
        } else {
            let prompt = if is_arm {
                "Duration in minutes (0 or empty for forever):"
            } else {
                "Additional minutes to add:"
            };
            let out = Command::new("zenity")
                .args([
                    "--entry",
                    &format!("--title={title}"),
                    &format!("--text={prompt}"),
                    &format!("--entry-text={}", if is_arm { "15" } else { "10" }),
                ])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let dur_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let duration = if dur_str.is_empty() || dur_str == "0" {
                if is_arm { Some(0) } else { None }
            } else if let Ok(mins) = dur_str.parse::<u64>() {
                Some(mins.saturating_mul(60))
            } else {
                None
            };
            Some((duration, None))
        }
    } else {
        send_desktop_notification(
            title,
            "Please use 'sudo agent-root-runner arm' in terminal.",
            "normal",
        );
        None
    }
}

fn spawn_arm(socket: &Path, extra_args: &[&str]) {
    // pkexec resolves its command against root's secure PATH, not the desktop
    // session's, so a bare name can hit a stale /usr/local/bin binary that
    // predates `tray`/`arm`. Pin the running executable's absolute path.
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/agent-root-runner"));
    let mut args = vec![exe.to_string_lossy().into_owned()];
    if socket != Path::new("/run/agent-root-runner/runner.sock") {
        args.push("--socket".to_string());
        args.push(socket.to_string_lossy().into_owned());
    }
    args.push("arm".to_string());
    for arg in extra_args {
        args.push(arg.to_string());
    }
    let _ = Command::new("pkexec").args(&args).spawn();
}

fn send_desktop_notification(summary: &str, body: &str, urgency: &str) {
    let _ = Command::new("notify-send")
        .args([
            "-a",
            "Agent Root Runner",
            "-u",
            urgency,
            "-i",
            "security-high",
            summary,
            body,
        ])
        .spawn();
}

pub fn run_tray(socket: &Path) -> Result<i32, String> {
    let _lock = match try_acquire_tray_lock()? {
        Some(lock) => lock,
        None => {
            println!("Agent Root Runner tray indicator is already running.");
            return Ok(0);
        }
    };

    let tray = RootRunnerTray::new(socket.to_path_buf());

    let handle = tray
        .spawn()
        .map_err(|e| format!("Failed to spawn system tray indicator: {e}"))?;

    println!("Agent Root Runner system tray indicator started.");

    let mut notified_session_id: Option<String> = None;
    let mut notified_expiry = false;

    let sock = socket.to_path_buf();
    loop {
        if handle.is_closed() {
            break;
        }

        let resp = crate::rpc(&sock, "status", Map::new(), Duration::from_secs(2));

        if let Ok(v) = &resp {
            if let Some(res) = v.get("result") {
                let is_armed = res["is_armed"].as_bool().unwrap_or(false);
                let session_id = res["session_id"].as_str().map(|s| s.to_string());
                if session_id != notified_session_id {
                    notified_session_id = session_id;
                    notified_expiry = false;
                }

                if is_armed && !res["forever"].as_bool().unwrap_or(false) {
                    if let Some(rem) = res["remaining_seconds"].as_f64() {
                        if rem <= 60.0 && !notified_expiry {
                            send_desktop_notification(
                                "Agent Root Runner: ARM Expiring Soon",
                                "Privileged access will expire in less than 1 minute. Click tray to extend.",
                                "critical",
                            );
                            notified_expiry = true;
                        } else if rem > 60.0 {
                            notified_expiry = false;
                        }
                    }
                }
            }
        }

        let updated = handle.update(|tray| match resp {
            Ok(v) => {
                if let Some(res) = v.get("result") {
                    tray.available = true;
                    tray.armed = res["is_armed"].as_bool().unwrap_or(false);
                    tray.forever = res["forever"].as_bool().unwrap_or(false);
                    tray.remaining_seconds =
                        res["remaining_seconds"].as_f64().map(|v| v.round() as u64);
                    tray.quota_remaining = res["quota_remaining"].as_u64();
                    tray.commands_executed = res["commands_executed"].as_u64().unwrap_or(0);
                } else {
                    tray.available = false;
                    tray.armed = false;
                    tray.forever = false;
                    tray.remaining_seconds = None;
                    tray.quota_remaining = None;
                }
            }
            Err(_) => {
                tray.available = false;
                tray.armed = false;
                tray.forever = false;
                tray.remaining_seconds = None;
                tray.quota_remaining = None;
            }
        });

        if updated.is_none() {
            break;
        }

        std::thread::sleep(Duration::from_secs(2));
    }

    Ok(0)
}
