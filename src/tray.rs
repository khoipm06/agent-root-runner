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

pub fn ensure_tray_running() {
    let (target_uid, target_user) = if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
        let uid: u32 = sudo_uid.parse().unwrap_or(0);
        let user = std::env::var("SUDO_USER").ok();
        (uid, user)
    } else if let Ok(pk_uid) = std::env::var("PKEXEC_UID") {
        let uid: u32 = pk_uid.parse().unwrap_or(0);
        (uid, None)
    } else {
        (unsafe { libc::getuid() }, None)
    };

    if target_uid != 0 && is_tray_running_for_uid(target_uid) {
        return;
    }

    if let Some(user) = target_user {
        let _ = Command::new("su")
            .args([
                "-",
                &user,
                "-c",
                "nohup /usr/local/bin/agent-root-runner tray >/dev/null 2>&1 &",
            ])
            .spawn();
    } else {
        let _ = Command::new(
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agent-root-runner")),
        )
        .arg("tray")
        .spawn();
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
            items.push(
                StandardItem {
                    label: "ARM (5 minutes)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(|_| {
                        spawn_arm(&["--duration", "300"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            items.push(
                StandardItem {
                    label: "ARM (15 minutes)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(|_| {
                        spawn_arm(&["--duration", "900"]);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            items.push(
                StandardItem {
                    label: "ARM (Forever)".into(),
                    icon_name: "security-high".into(),
                    activate: Box::new(|_| {
                        spawn_arm(&["--forever"]);
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

fn spawn_arm(extra_args: &[&str]) {
    let mut args = vec!["agent-root-runner", "arm"];
    args.extend_from_slice(extra_args);
    let _ = Command::new("pkexec").args(&args).spawn();
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

    let sock = socket.to_path_buf();
    loop {
        if handle.is_closed() {
            break;
        }

        let resp = crate::rpc(&sock, "status", Map::new(), Duration::from_secs(2));

        let updated = handle.update(|tray| match resp {
            Ok(v) => {
                if let Some(res) = v.get("result") {
                    tray.available = true;
                    tray.armed = res["is_armed"].as_bool().unwrap_or(false);
                    tray.forever = res["forever"].as_bool().unwrap_or(false);
                    tray.remaining_seconds = res["remaining_seconds"].as_u64();
                    tray.quota_remaining = res["quota_remaining"].as_u64();
                    tray.commands_executed = res["commands_executed"].as_u64().unwrap_or(0);
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
