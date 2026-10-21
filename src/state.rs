use crate::audit::{AuditLogger, object};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicI32, Ordering},
};
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

pub const MAX_DURATION_SECONDS: u64 = 86_400;
const DEFAULT_DURATION_SECONDS: u64 = 900;
/// F1: absolute byte cap for the command text embedded in audit records.
/// Whatever the RPC layer does or does not enforce, no caller can
/// amplify the audit log through the command copy.
const MAX_AUDIT_COMMAND_BYTES: usize = 512;
const AUDIT_COMMAND_MARKER: &str = "[truncated]";
struct Session {
    id: String,
    started: SystemTime,
    mono: Instant,
    duration: Option<u64>,
    quota: Option<u64>,
    left: Option<u64>,
    uid: u32,
    pid: i32,
}
struct Inner {
    armed: bool,
    audit_failed: bool,
    session: Option<Session>,
    commands: u64,
    lifetime: u64,
    last: Option<String>,
    generation: u64,
    /// F5: an admission lifecycle is in progress (from `admit` until its
    /// result or refund is durably recorded). Re-arm is refused while
    /// set, so an in-flight command is always charged to the session that
    /// authorized it and can never outlive its own accounting.
    in_flight: bool,
    /// The most recent successful admission, used to keep EXEC_START
    /// truthful (F7): an admission invalidated before spawn must not be
    /// recorded as ADMITTED.
    last_admit: Option<Admission>,
}
pub struct StateMachine {
    inner: Mutex<Inner>,
    pgid: Arc<AtomicI32>,
    audit: Arc<AuditLogger>,
    allow_user_arm: bool,
}
#[derive(Clone, Debug)]
pub struct Admission {
    pub remaining_seconds: Option<f64>,
    pub(crate) deadline: Option<Instant>,
    generation: u64,
    final_slot: bool,
}
pub struct SpawnPermit<'a> {
    _guard: MutexGuard<'a, Inner>,
}
#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub reason: Option<String>,
}
impl RpcError {
    pub fn invalid(s: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: format!("Invalid params: {}", s.into()),
            reason: Some("INVALID_PARAMS".into()),
        }
    }
    pub fn permission(s: String) -> Self {
        Self {
            code: -32003,
            message: s,
            reason: Some("PERMISSION_DENIED".into()),
        }
    }
    pub fn internal(s: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: s.into(),
            reason: None,
        }
    }
}
impl StateMachine {
    pub fn new(audit: Arc<AuditLogger>, pgid: Arc<AtomicI32>, allow_user_arm: bool) -> Self {
        Self {
            inner: Mutex::new(Inner {
                armed: false,
                audit_failed: false,
                session: None,
                commands: 0,
                lifetime: 0,
                last: None,
                generation: 0,
                in_flight: false,
                last_admit: None,
            }),
            pgid,
            audit,
            allow_user_arm,
        }
    }
    pub fn arm(
        &self,
        duration: Option<u64>,
        quota: Option<u64>,
        forever: bool,
        uid: u32,
        pid: i32,
    ) -> Result<Value, RpcError> {
        if uid != 0 && !(self.allow_user_arm && uid != u32::MAX) {
            return Err(RpcError::permission(format!(
                "Permission denied: Arming requires root privileges (peer_uid == 0, got {uid}). Run 'sudo agent-root-runner arm' to enable."
            )));
        }
        if forever && duration.is_some() {
            return Err(RpcError::invalid(
                "'forever' and a duration are mutually exclusive",
            ));
        }
        let duration = if forever {
            None
        } else {
            let n = duration.unwrap_or(DEFAULT_DURATION_SECONDS);
            if n < 1 {
                return Err(RpcError::invalid(
                    "duration_seconds must be a positive integer >= 1",
                ));
            }
            if n > MAX_DURATION_SECONDS {
                return Err(RpcError::invalid(format!(
                    "duration_seconds exceeds maximum limit of {MAX_DURATION_SECONDS}s"
                )));
            }
            Some(n)
        };
        if quota == Some(0) {
            return Err(RpcError::invalid(
                "quota must be a positive integer >= 1 or None",
            ));
        }
        let now = SystemTime::now();
        let id = format!(
            "arm_{}_{}",
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            &Uuid::new_v4().simple().to_string()[..6]
        );
        let mut g = self
            .inner
            .lock()
            .map_err(|_| RpcError::internal("state mutex poisoned"))?;
        if g.audit_failed {
            return Err(RpcError::internal(
                "Audit logging previously failed; the daemon is fail-closed.",
            ));
        }
        // F5: while a command is in flight (from admission until its
        // result or refund is durably recorded) the current session must
        // stay put, so the command is charged to the session that
        // authorized it. Refuse the re-arm instead of killing or
        // re-attributing a running command.
        if g.in_flight {
            return Err(RpcError {
                code: -32000,
                message: "Cannot re-arm while a command is executing; wait for it to \
                          complete or disarm first."
                    .into(),
                reason: Some("COMMAND_IN_FLIGHT".into()),
            });
        }
        g.generation += 1;
        g.armed = true;
        g.commands = 0;
        g.last = None;
        g.last_admit = None;
        g.session = Some(Session {
            id: id.clone(),
            started: now,
            mono: Instant::now(),
            duration,
            quota,
            left: quota,
            uid,
            pid,
        });
        let exp = duration.map(|d| ts(now + Duration::from_secs(d)));
        let dv = duration.map(|d| json!(d)).unwrap_or(Value::Null);
        if let Err(error) = self.emit_locked(
            &mut g,
            "ARM",
            Some(pid),
            Some(uid),
            None,
            None,
            object(&[
                ("session_id", json!(id)),
                ("forever", json!(forever)),
                ("duration_seconds", dv.clone()),
                ("timeout_seconds", dv),
                ("quota", quota.map(|q| json!(q)).unwrap_or(Value::Null)),
                ("expires_at", exp.map(|e| json!(e)).unwrap_or(Value::Null)),
            ]),
        ) {
            g.armed = false;
            g.session = None;
            drop(g);
            self.kill();
            return Err(RpcError::internal(format!(
                "Cannot durably audit ARM; the daemon is fail-closed: {error}"
            )));
        }
        Ok(status_inner(&g))
    }
    pub fn disarm(&self, uid: u32) -> Result<Value, String> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.audit_failed {
            drop(g);
            self.kill();
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        let old = g.armed;
        let prev = if old { "ARMED" } else { "DISARMED" };
        let sid = g.session.as_ref().map(|s| json!(s.id));
        let elapsed = active_elapsed(&g);
        let n = g.commands;
        g.armed = false;
        g.last = Some("MANUAL_DISARM".into());
        // Invalidate a final-quota command that may be admitted but not yet
        // spawned when an explicit manual disarm arrives.
        g.generation += 1;
        let audit = self.emit_locked(
            &mut g,
            "DISARM",
            None,
            Some(uid),
            None,
            None,
            object(&[
                ("session_id", sid.clone().unwrap_or(Value::Null)),
                ("reason", json!("MANUAL_DISARM")),
                ("disarmed_by_uid", json!(uid)),
                ("active_duration_seconds", json!(round2(elapsed))),
                ("commands_executed", json!(n)),
            ]),
        );
        drop(g);
        self.kill();
        audit?;
        Ok(
            json!({"state":"DISARMED","previous_state":prev,"session_id":sid,"reason":"MANUAL_DISARM","commands_executed":n,"active_duration_seconds":round2(elapsed),"already_disarmed":!old,"message":if old{"Service successfully disarmed."}else{"Service was already disarmed."}}),
        )
    }
    pub fn shutdown(&self) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.audit_failed {
            drop(g);
            self.kill();
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        let sid = g.session.as_ref().map(|s| json!(s.id));
        let elapsed = active_elapsed(&g);
        g.armed = false;
        g.last = Some("SHUTDOWN".into());
        g.generation += 1;
        let commands = g.commands;
        let audit = self.emit_locked(
            &mut g,
            "DAEMON_STOP",
            None,
            None,
            None,
            None,
            object(&[
                ("session_id", sid.unwrap_or(Value::Null)),
                ("reason", json!("SHUTDOWN")),
                ("active_duration_seconds", json!(round2(elapsed))),
                ("commands_executed", json!(commands)),
            ]),
        );
        drop(g);
        self.kill();
        audit
    }
    pub fn status(&self) -> Result<Value, String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if g.armed && expired(&g) {
            self.transition(&mut g, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
        }
        Ok(status_inner(&g))
    }
    pub fn check_expiry(&self) -> Result<(), String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if g.audit_failed {
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        if g.armed && expired(&g) {
            self.transition(&mut g, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
        }
        Ok(())
    }
    pub fn reject_if_disarmed(
        &self,
        pid: i32,
        uid: u32,
        gid: u32,
        comm: &str,
        command: &str,
    ) -> Result<Option<String>, String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if g.audit_failed {
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        if g.armed && expired(&g) {
            self.transition(&mut g, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
        }
        if g.armed {
            return Ok(None);
        }
        let msg = if g.last.as_deref() == Some("QUOTA_EXHAUSTED") {
            "Execution quota exhausted. Re-arm with 'sudo agent-root-runner arm'."
        } else {
            "Service is DISARMED. Run 'sudo agent-root-runner arm' to enable."
        }
        .to_string();
        let mut data = object(&[
            ("command", json!(audit_command(command))),
            ("decision", json!("DENIED_DISARMED")),
            ("reason", json!(msg)),
        ]);
        tag_exec_record(&g, "EXEC_REJECTED", &mut data);
        let audit = self.emit_locked(
            &mut g,
            "EXEC_REJECTED",
            Some(pid),
            Some(uid),
            Some(gid),
            Some(comm),
            data,
        );
        if let Err(error) = audit {
            drop(g);
            self.kill();
            return Err(format!("Cannot durably audit rejected execution: {error}"));
        }
        Ok(Some(msg))
    }
    pub fn admit(
        &self,
        pid: i32,
        uid: u32,
        gid: u32,
        comm: &str,
        command: &str,
    ) -> Result<Admission, String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if g.audit_failed {
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        // F6: a blank or NUL-bearing command can never spawn (the executor
        // rejects it after the fact), so refuse it here — before the quota
        // slot is consumed and before any ADMITTED/ALLOWED audit record
        // can exist for a command that never runs.
        if command.trim().is_empty() || command.contains('\0') {
            return Err(
                "Invalid params: 'command' must not be blank or contain null bytes.".into(),
            );
        }
        if g.armed && expired(&g) {
            self.transition(&mut g, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
        }
        if !g.armed || g.session.is_none() {
            let msg = if g.last.as_deref() == Some("QUOTA_EXHAUSTED") {
                "Execution quota exhausted. Re-arm with 'sudo agent-root-runner arm'."
            } else {
                "Service is DISARMED. Run 'sudo agent-root-runner arm' to enable."
            };
            let mut data = object(&[
                ("command", json!(audit_command(command))),
                ("decision", json!("DENIED_DISARMED")),
                ("reason", json!(msg)),
            ]);
            tag_exec_record(&g, "EXEC_REJECTED", &mut data);
            let audit = self.emit_locked(
                &mut g,
                "EXEC_REJECTED",
                Some(pid),
                Some(uid),
                Some(gid),
                Some(comm),
                data,
            );
            if let Err(error) = audit {
                drop(g);
                self.kill();
                return Err(format!("Cannot durably audit rejected execution: {error}"));
            }
            return Err(msg.into());
        }
        let (remain, deadline) = {
            let session = g.session.as_ref().unwrap();
            match session.duration {
                Some(d) => {
                    let deadline = session.mono + Duration::from_secs(d);
                    let remain = deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs_f64();
                    (Some(remain), Some(deadline))
                }
                None => (None, None),
            }
        };
        if deadline.is_some_and(|d| Instant::now() >= d) {
            self.transition(&mut g, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
            return Err("Service is DISARMED. Run 'sudo agent-root-runner arm' to enable.".into());
        }
        let mut final_slot = false;
        if let Some(s) = g.session.as_mut() {
            if let Some(left) = s.left.as_mut() {
                if *left == 0 {
                    drop(g);
                    return Err(
                        "Execution quota exhausted. Re-arm with 'sudo agent-root-runner arm'."
                            .into(),
                    );
                }
                *left -= 1;
                final_slot = *left == 0;
            }
        }
        if final_slot {
            self.transition(&mut g, "QUOTA_EXHAUSTED", "QUOTA_LOCK", None)?;
        }
        let admission = Admission {
            remaining_seconds: remain,
            deadline,
            generation: g.generation,
            final_slot,
        };
        // F5: from admission until the result/refund is recorded, the
        // session that authorized this command must remain current.
        g.in_flight = true;
        g.last_admit = Some(admission.clone());
        Ok(admission)
    }
    #[cfg(test)]
    pub fn admission_valid(&self, a: &Admission) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        !g.audit_failed
            && g.generation == a.generation
            && (g.armed || a.final_slot && g.last.as_deref() == Some("QUOTA_EXHAUSTED"))
    }
    pub fn spawn_permit(&self, a: &Admission) -> Result<SpawnPermit<'_>, String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if guard.audit_failed
            || guard.generation != a.generation
            || !(guard.armed || a.final_slot && guard.last.as_deref() == Some("QUOTA_EXHAUSTED"))
        {
            return Err("Execution admission was invalidated before process start.".into());
        }
        if a.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.transition(&mut guard, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
            return Err("ARM deadline expired before process start.".into());
        }
        // F5: the in-flight window covers the spawn itself as well
        // (admissions granted by `admit` already set it).
        guard.in_flight = true;
        Ok(SpawnPermit { _guard: guard })
    }
    pub fn refund_quota(&self) -> Result<(), String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if g.audit_failed {
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        // F5/F10: the admission lifecycle this refund closes has ended;
        // re-arm becomes possible again and the refund stays attributable
        // to the session that actually admitted the command.
        g.in_flight = false;
        g.last_admit = None;
        if expired(&g) && (g.armed || g.last.as_deref() == Some("QUOTA_EXHAUSTED")) {
            self.transition(&mut g, "TIMEOUT_EXPIRED", "TIMEOUT_LOCK", None)?;
        }
        let quota_locked = !g.armed && g.last.as_deref() == Some("QUOTA_EXHAUSTED");
        let Some((session_id, forever, quota, left, uid, pid, remaining)) =
            g.session.as_ref().and_then(|session| {
                session.left.map(|left| {
                    (
                        session.id.clone(),
                        session.duration.is_none(),
                        session.quota,
                        left,
                        session.uid,
                        session.pid,
                        session
                            .duration
                            .map(|d| (d as f64 - session.mono.elapsed().as_secs_f64()).max(0.)),
                    )
                })
            })
        else {
            return Ok(());
        };
        let new_left = quota
            .map(|q| left.saturating_add(1).min(q))
            .unwrap_or_else(|| left.saturating_add(1));
        let rearm = quota_locked && !expired(&g);
        let event_type = if rearm { "ARM" } else { "QUOTA_REFUND" };
        let data = object(&[
            ("session_id", json!(session_id)),
            ("forever", json!(forever)),
            ("reason", json!("QUOTA_REFUND")),
            ("quota_remaining", json!(new_left)),
            (
                "remaining_seconds",
                remaining
                    .map(|v| json!((v * 10.).round() / 10.))
                    .unwrap_or(Value::Null),
            ),
        ]);
        if let Err(error) =
            self.emit_locked(&mut g, event_type, Some(pid), Some(uid), None, None, data)
        {
            drop(g);
            self.kill();
            return Err(format!("Cannot durably audit quota refund: {error}"));
        }
        if let Some(session) = g.session.as_mut() {
            session.left = Some(new_left);
        }
        if rearm {
            g.armed = true;
            g.last = None;
            g.generation += 1;
        }
        Ok(())
    }
    pub fn audit_event(
        &self,
        event_type: &str,
        peer_pid: Option<i32>,
        peer_uid: Option<u32>,
        peer_gid: Option<u32>,
        peer_comm: Option<&str>,
        mut data: serde_json::Map<String, Value>,
    ) -> Result<(), String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        // F7: an admission invalidated before spawn (disarm, expiry,
        // generation bump, or audit failure landing between admit and
        // start) must not be durably recorded as ADMITTED — the command
        // never ran. Record the abort instead, keeping the trail complete
        // and truthful.
        let mut event_type = event_type;
        if event_type == "EXEC_START"
            && g.last_admit
                .as_ref()
                .is_some_and(|a| !admission_still_valid(&g, a))
        {
            let command = data.get("command").cloned().unwrap_or(Value::Null);
            event_type = "EXEC_ABORTED";
            data = object(&[
                ("command", command),
                ("decision", json!("ABORTED")),
                ("reason", json!("ADMISSION_INVALIDATED_BEFORE_SPAWN")),
            ]);
        }
        tag_exec_record(&g, event_type, &mut data);
        let result = self.emit_locked(
            &mut g, event_type, peer_pid, peer_uid, peer_gid, peer_comm, data,
        );
        if result.is_err() {
            drop(g);
            self.kill();
        }
        result
    }
    pub fn record_execution(
        &self,
        event_type: &str,
        peer_pid: i32,
        peer_uid: u32,
        peer_gid: u32,
        peer_comm: &str,
        mut data: serde_json::Map<String, Value>,
    ) -> Result<(), String> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        g.commands += 1;
        g.lifetime += 1;
        // F5: the command lifecycle is complete — its result is charged to
        // the session that authorized it, and re-arm is possible again.
        g.in_flight = false;
        g.last_admit = None;
        tag_exec_record(&g, event_type, &mut data);
        let result = self.emit_locked(
            &mut g,
            event_type,
            Some(peer_pid),
            Some(peer_uid),
            Some(peer_gid),
            Some(peer_comm),
            data,
        );
        if result.is_err() {
            drop(g);
            self.kill();
        }
        result
    }
    fn transition(
        &self,
        g: &mut Inner,
        reason: &str,
        event: &str,
        uid: Option<u32>,
    ) -> Result<(), String> {
        if g.audit_failed {
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        let was = g.armed;
        let sid = g
            .session
            .as_ref()
            .map(|s| json!(s.id.clone()))
            .unwrap_or(Value::Null);
        let elapsed = active_elapsed(&g);
        g.armed = false;
        g.last = Some(reason.into());
        if was {
            g.generation += 1;
        }
        let result = self.emit_locked(
            g,
            event,
            None,
            uid,
            None,
            None,
            object(&[
                ("session_id", sid),
                ("reason", json!(reason)),
                (
                    "disarmed_by_uid",
                    uid.map(|u| json!(u)).unwrap_or(Value::Null),
                ),
                ("active_duration_seconds", json!(round2(elapsed))),
                ("commands_executed", json!(g.commands)),
            ]),
        );
        if was || result.is_err() {
            self.kill();
        }
        result
    }
    fn emit_locked(
        &self,
        g: &mut Inner,
        event_type: &str,
        peer_pid: Option<i32>,
        peer_uid: Option<u32>,
        peer_gid: Option<u32>,
        peer_comm: Option<&str>,
        data: serde_json::Map<String, Value>,
    ) -> Result<(), String> {
        if g.audit_failed {
            return Err("Audit logging previously failed; the daemon is fail-closed.".into());
        }
        match self
            .audit
            .event(event_type, peer_pid, peer_uid, peer_gid, peer_comm, data)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                g.audit_failed = true;
                g.armed = false;
                g.last = Some("AUDIT_FAILURE".into());
                g.generation += 1;
                Err(error)
            }
        }
    }
    fn kill(&self) {
        let p = self.pgid.load(Ordering::SeqCst);
        if p > 0 {
            crate::executor::kill_process_tree(p);
        }
    }
}
/// F1: bound the command text embedded in audit records. The copy is
/// capped at an absolute byte budget with an explicit truncation marker,
/// so no caller can amplify the audit log regardless of what the RPC
/// layer enforces.
fn audit_command(command: &str) -> String {
    if command.len() <= MAX_AUDIT_COMMAND_BYTES {
        return command.to_string();
    }
    // Leave room for the marker inside the cap and never split a UTF-8
    // character.
    let mut cut = MAX_AUDIT_COMMAND_BYTES - AUDIT_COMMAND_MARKER.len();
    while cut > 0 && !command.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{AUDIT_COMMAND_MARKER}", &command[..cut])
}
/// F1/F7: every EXEC_* audit record names the arm session it belongs to
/// (explicit null when no session exists), and the peer-supplied command
/// copy respects the byte cap.
fn tag_exec_record(g: &Inner, event_type: &str, data: &mut serde_json::Map<String, Value>) {
    if event_type.starts_with("EXEC_") {
        data.entry("session_id".to_string()).or_insert_with(|| {
            g.session
                .as_ref()
                .map(|s| json!(s.id))
                .unwrap_or(Value::Null)
        });
    }
    if let Some(Value::String(command)) = data.get_mut("command") {
        if command.len() > MAX_AUDIT_COMMAND_BYTES {
            *command = audit_command(command);
        }
    }
}
/// Mirrors `spawn_permit`: would this admission still be allowed to
/// spawn right now? Used to keep EXEC_START truthful (F7).
fn admission_still_valid(g: &Inner, a: &Admission) -> bool {
    !g.audit_failed
        && g.generation == a.generation
        && (g.armed || a.final_slot && g.last.as_deref() == Some("QUOTA_EXHAUSTED"))
        && !a
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
}
fn expired(g: &Inner) -> bool {
    g.session
        .as_ref()
        .and_then(|s| {
            s.duration
                .map(|d| s.mono.elapsed() >= Duration::from_secs(d))
        })
        .unwrap_or(false)
}
fn active_elapsed(g: &Inner) -> f64 {
    g.session
        .as_ref()
        .map(|s| {
            let elapsed = s.mono.elapsed().as_secs_f64();
            s.duration.map(|d| elapsed.min(d as f64)).unwrap_or(elapsed)
        })
        .unwrap_or(0.)
}
fn status_inner(g: &Inner) -> Value {
    let s = g.session.as_ref();
    let timed = if g.armed { s } else { None };
    // F9 (documented intent): the quota fields deliberately keep
    // describing the most recent arm session even while disarmed — a
    // QUOTA_LOCK disarm must still report quota_remaining: 0, matching
    // commands_executed and the callers that rely on it. Only the time
    // fields above are nulled when disarmed.
    let duration = timed.and_then(|s| s.duration);
    let forever = g.armed && s.is_some_and(|s| s.duration.is_none());
    let rem = if !g.armed {
        None
    } else if forever {
        None
    } else {
        s.and_then(|s| {
            s.duration.map(|d| {
                let left = (d as f64 - s.mono.elapsed().as_secs_f64()).max(0.);
                json!((left * 10.).ceil() / 10.)
            })
        })
    };
    let exp = timed.and_then(|s| s.duration.map(|d| ts(s.started + Duration::from_secs(d))));
    json!({"state":if g.armed{"ARMED"}else{"DISARMED"},"is_armed":g.armed,"forever":forever,"session_id":timed.map(|s|json!(s.id)).unwrap_or(Value::Null),"armed_at":timed.map(|s|json!(ts(s.started))).unwrap_or(Value::Null),"expires_at":exp.map(|x|json!(x)).unwrap_or(Value::Null),"remaining_seconds":rem.unwrap_or(Value::Null),"timeout_seconds":duration.map(|x|json!(x)).unwrap_or(Value::Null),"duration_seconds":duration.map(|x|json!(x)).unwrap_or(Value::Null),"quota_limit":s.and_then(|s|s.quota).map(|x|json!(x)).unwrap_or(Value::Null),"quota":s.and_then(|s|s.quota).map(|x|json!(x)).unwrap_or(Value::Null),"quota_remaining":s.and_then(|s|s.left).map(|x|json!(x)).unwrap_or(Value::Null),"commands_executed":g.commands,"lifetime_commands":g.lifetime})
}
fn ts(t: SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}
fn round2(v: f64) -> f64 {
    (v * 100.).round() / 100.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, atomic::AtomicI32, mpsc},
        thread,
        time::Duration,
    };
    fn machine() -> (StateMachine, std::path::PathBuf) {
        let (machine, _, path) = machine_with_audit();
        (machine, path)
    }
    fn machine_with_audit() -> (StateMachine, Arc<AuditLogger>, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!(
            "arr-state-{}-{}.log",
            std::process::id(),
            Uuid::new_v4()
        ));
        let a = Arc::new(AuditLogger::open(Some(p.to_str().unwrap()), true).unwrap());
        (
            StateMachine::new(a.clone(), Arc::new(AtomicI32::new(0)), false),
            a,
            p,
        )
    }
    #[test]
    fn root_auth_duration_and_forever_contract() {
        let (m, p) = machine();
        assert_eq!(
            m.arm(Some(30), None, false, 1000, 1).unwrap_err().code,
            -32003
        );
        assert_eq!(m.arm(Some(0), None, false, 0, 1).unwrap_err().code, -32602);
        assert_eq!(
            m.arm(Some(86_401), None, false, 0, 1).unwrap_err().code,
            -32602
        );
        assert_eq!(m.arm(Some(2), None, true, 0, 1).unwrap_err().code, -32602);
        let s = m.arm(None, Some(2), true, 0, 1).unwrap();
        assert_eq!(s["forever"], true);
        assert!(s["expires_at"].is_null());
        assert_eq!(s["quota_remaining"], 2);
        let _ = fs::remove_file(p);
    }
    #[test]
    fn quota_refund_only_reopens_quota_lock() {
        let (m, p) = machine();
        m.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let a = m.admit(1, 0, 0, "test", "echo x").unwrap();
        assert!(a.final_slot);
        assert_eq!(m.status().unwrap()["is_armed"], false);
        m.refund_quota().unwrap();
        let s = m.status().unwrap();
        assert!(s["is_armed"].as_bool().unwrap());
        assert_eq!(s["quota_remaining"], 1);
        let a = m.admit(1, 0, 0, "test", "echo y").unwrap();
        assert_eq!(a.remaining_seconds.unwrap_or_default() > 0., true);
        m.disarm(0).unwrap();
        m.refund_quota().unwrap();
        assert_eq!(m.status().unwrap()["is_armed"], false);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_quota_refund_audit_does_not_rearm() {
        let (m, audit, p) = machine_with_audit();
        m.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let admission = m.admit(1, 0, 0, "test", "echo x").unwrap();
        assert!(admission.final_slot);
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());

        audit.fail_next_event_for_test();
        assert!(m.refund_quota().is_err());

        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.arm(Some(30), None, false, 0, 2).is_err());
        assert!(m.admit(2, 0, 0, "test", "echo y").is_err());
        assert!(m.inner.lock().unwrap().audit_failed);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_quota_lock_audit_rejects_final_admission() {
        let (m, audit, p) = machine_with_audit();
        m.arm(Some(30), Some(1), false, 0, 1).unwrap();
        audit.fail_next_event_for_test();

        assert!(m.admit(1, 0, 0, "test", "echo final").is_err());
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.inner.lock().unwrap().audit_failed);
        assert!(m.arm(Some(30), None, false, 0, 2).is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_execution_result_audit_is_reported_and_fail_closed() {
        let (m, audit, p) = machine_with_audit();
        m.arm(Some(30), None, false, 0, 1).unwrap();
        audit.fail_next_event_for_test();

        assert!(
            m.record_execution("EXEC_ALLOWED", 1, 0, 0, "test", object(&[]))
                .is_err()
        );
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.inner.lock().unwrap().audit_failed);
        assert!(m.admit(2, 0, 0, "test", "echo later").is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_disarmed_execution_rejection_audit_latches_failure() {
        let (m, audit, p) = machine_with_audit();
        audit.fail_next_event_for_test();

        assert!(
            m.reject_if_disarmed(1, 0, 0, "test", "echo denied")
                .is_err()
        );
        assert!(m.inner.lock().unwrap().audit_failed);
        assert!(m.arm(Some(30), None, false, 0, 2).is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_arm_audit_never_leaves_the_machine_armed() {
        let (m, audit, p) = machine_with_audit();
        audit.fail_next_event_for_test();

        assert!(m.arm(Some(30), None, false, 0, 1).is_err());
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.inner.lock().unwrap().audit_failed);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn real_audit_write_error_from_full_device_fails_closed() {
        let audit = Arc::new(AuditLogger::full_for_test());
        let machine = StateMachine::new(audit, Arc::new(AtomicI32::new(0)), false);

        assert!(machine.arm(Some(30), None, false, 0, 1).is_err());
        assert!(!machine.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(machine.inner.lock().unwrap().audit_failed);
        assert!(machine.admit(2, 0, 0, "test", "echo later").is_err());
    }

    #[test]
    fn actual_audit_sync_stage_error_fails_closed_after_write() {
        let (machine, audit, path) = machine_with_audit();
        audit.fail_next_sync_for_test();

        assert!(machine.arm(Some(30), None, false, 0, 1).is_err());
        assert!(!machine.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(machine.inner.lock().unwrap().audit_failed);
        assert!(fs::metadata(&path).unwrap().len() > 0);
        assert!(machine.admit(2, 0, 0, "test", "echo later").is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn failed_disarm_audit_still_disarms_and_latches_failure() {
        let (m, audit, p) = machine_with_audit();
        m.arm(Some(30), None, false, 0, 1).unwrap();
        audit.fail_next_event_for_test();

        assert!(m.disarm(0).is_err());
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.inner.lock().unwrap().audit_failed);
        assert!(m.arm(Some(30), None, false, 0, 2).is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_timeout_transition_blocks_followup_work() {
        let (m, audit, p) = machine_with_audit();
        m.arm(Some(30), None, false, 0, 1).unwrap();
        {
            let mut inner = m.inner.lock().unwrap();
            let session = inner.session.as_mut().unwrap();
            session.duration = Some(0);
            session.mono = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        }
        audit.fail_next_event_for_test();

        assert!(m.check_expiry().is_err());
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.inner.lock().unwrap().audit_failed);
        assert!(m.admit(2, 0, 0, "test", "echo later").is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn failed_exec_start_and_block_events_are_fail_closed() {
        for event in ["EXEC_START", "EXEC_BLOCKED"] {
            let (m, audit, p) = machine_with_audit();
            m.arm(Some(30), None, false, 0, 1).unwrap();
            audit.fail_next_event_for_test();

            assert!(
                m.audit_event(event, Some(1), Some(0), Some(0), Some("test"), object(&[]))
                    .is_err()
            );
            assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
            assert!(m.inner.lock().unwrap().audit_failed);
            assert!(m.admit(2, 0, 0, "test", "echo later").is_err());
            let _ = fs::remove_file(p);
        }
    }

    #[test]
    fn failed_shutdown_audit_latches_fail_closed_state() {
        let (m, audit, p) = machine_with_audit();
        m.arm(Some(30), None, false, 0, 1).unwrap();
        audit.fail_next_event_for_test();

        assert!(m.shutdown().is_err());
        assert!(!m.status().unwrap()["is_armed"].as_bool().unwrap());
        assert!(m.inner.lock().unwrap().audit_failed);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn disarm_waits_for_the_spawn_permit_and_invalidates_admission() {
        let (machine, p) = machine();
        let machine = Arc::new(machine);
        machine.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let admission = machine.admit(1, 0, 0, "test", "echo final").unwrap();
        let permit = machine.spawn_permit(&admission).unwrap();

        let other = machine.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let disarm = thread::spawn(move || {
            started_tx.send(()).unwrap();
            other.disarm(0).unwrap();
            done_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(permit);
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        disarm.join().unwrap();
        assert!(machine.spawn_permit(&admission).is_err());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn expired_ordinary_admission_cannot_acquire_spawn_permit() {
        let (machine, path) = machine();
        machine.arm(Some(30), None, false, 0, 1).unwrap();
        let admission = machine.admit(1, 0, 0, "test", "echo expired").unwrap();
        let admission = Admission {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..admission
        };
        {
            let mut inner = machine.inner.lock().unwrap();
            let session = inner.session.as_mut().unwrap();
            session.duration = Some(0);
            session.mono = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        }

        assert!(machine.spawn_permit(&admission).is_err());
        assert!(!machine.status().unwrap()["is_armed"].as_bool().unwrap());
        assert_eq!(
            machine.inner.lock().unwrap().last.as_deref(),
            Some("TIMEOUT_EXPIRED")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_final_quota_admission_cannot_acquire_spawn_permit_or_rearm() {
        let (machine, path) = machine();
        machine.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let admission = machine.admit(1, 0, 0, "test", "echo final").unwrap();
        assert!(admission.final_slot);
        let admission = Admission {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..admission
        };
        {
            let mut inner = machine.inner.lock().unwrap();
            let session = inner.session.as_mut().unwrap();
            session.duration = Some(0);
            session.mono = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        }

        assert!(machine.spawn_permit(&admission).is_err());
        machine.refund_quota().unwrap();
        assert!(!machine.status().unwrap()["is_armed"].as_bool().unwrap());
        assert_eq!(
            machine.inner.lock().unwrap().last.as_deref(),
            Some("TIMEOUT_EXPIRED")
        );
        let _ = fs::remove_file(path);
    }
    #[test]
    fn explicit_disarm_invalidates_an_unspawned_final_quota_admission() {
        let (m, p) = machine();
        m.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let admitted = m.admit(1, 0, 0, "test", "echo final").unwrap();
        assert!(admitted.final_slot);
        assert!(m.admission_valid(&admitted));
        m.disarm(0).unwrap();
        assert!(!m.admission_valid(&admitted));
        let _ = fs::remove_file(p);
    }
    #[test]
    fn every_new_machine_starts_disarmed() {
        let (m, p) = machine();
        m.arm(Some(60), None, false, 0, 1).unwrap();
        let (a, p2) = machine();
        assert_eq!(a.status().unwrap()["state"], "DISARMED");
        let _ = fs::remove_file(p);
        let _ = fs::remove_file(p2);
    }
    #[test]
    fn disarmed_status_omits_stale_session_times() {
        let (m, p) = machine();
        m.arm(Some(60), None, false, 0, 1).unwrap();
        let armed = m.status().unwrap();
        assert!(armed["armed_at"].is_string());
        assert!(armed["expires_at"].is_string());
        assert!(armed["remaining_seconds"].is_number());

        m.disarm(0).unwrap();
        let s = m.status().unwrap();
        assert_eq!(s["state"], "DISARMED");
        for key in [
            "session_id",
            "armed_at",
            "expires_at",
            "remaining_seconds",
            "timeout_seconds",
            "duration_seconds",
        ] {
            assert!(
                s[key].is_null(),
                "disarmed status leaked stale {key}: {}",
                s[key]
            );
        }
        let _ = fs::remove_file(p);
    }
    #[test]
    fn audit_active_duration_uses_monotonic_and_caps_at_session_duration() {
        let (m, p) = machine();
        m.arm(Some(1), None, false, 0, 1).unwrap();
        thread::sleep(Duration::from_millis(1_200));
        // status() performs the TIMEOUT_EXPIRED transition for the expired session.
        assert_eq!(m.status().unwrap()["state"], "DISARMED");
        let log = fs::read_to_string(&p).unwrap();
        let expired = log
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["event_type"] == "TIMEOUT_LOCK")
            .expect("timeout audit record");
        let active = expired["active_duration_seconds"]
            .as_f64()
            .expect("active duration");
        assert!(
            active <= 1.0,
            "active duration {active}s exceeded the 1s session"
        );
        let _ = fs::remove_file(p);
    }

    // ---- F1: the audited command copy can never amplify the log ----

    #[test]
    fn disarmed_rejection_caps_the_audited_command_copy() {
        let (m, p) = machine();
        let huge = "x".repeat(2 * 1024 * 1024);
        m.reject_if_disarmed(1, 0, 0, "probe", &huge).unwrap();

        let log = fs::read_to_string(&p).unwrap();
        assert!(
            log.len() < 4096,
            "one disarmed rejection appended {} bytes to the audit log",
            log.len()
        );
        let record: Value =
            serde_json::from_str(log.lines().next().unwrap()).expect("audit record parses");
        assert_eq!(record["event_type"], "EXEC_REJECTED");
        assert_eq!(record["decision"], "DENIED_DISARMED");
        let command = record["command"].as_str().unwrap();
        assert!(
            command.len() <= MAX_AUDIT_COMMAND_BYTES,
            "command copy is {} bytes",
            command.len()
        );
        assert!(command.ends_with(AUDIT_COMMAND_MARKER));
        assert!(command.starts_with(&"x".repeat(256)));
        // Session correlation is explicit even before any arm exists.
        assert!(
            record.get("session_id").is_some() && record["session_id"].is_null(),
            "pre-arm rejection must carry an explicit null session_id: {record}"
        );
        let _ = fs::remove_file(p);
    }

    #[test]
    fn audit_command_copy_caps_at_exactly_512_bytes() {
        let fits = "a".repeat(MAX_AUDIT_COMMAND_BYTES);
        assert_eq!(audit_command(&fits), fits);
        assert_eq!(audit_command("").len(), 0);
        let over = audit_command(&"a".repeat(MAX_AUDIT_COMMAND_BYTES + 1));
        assert!(over.len() <= MAX_AUDIT_COMMAND_BYTES);
        assert!(over.ends_with(AUDIT_COMMAND_MARKER));
        assert!(over.starts_with(&"a".repeat(488)));
        // Multi-byte UTF-8 is never split mid-character.
        let euro = "€".repeat(200); // 600 bytes
        let capped = audit_command(&euro);
        assert!(capped.len() <= MAX_AUDIT_COMMAND_BYTES);
        assert!(capped.ends_with(AUDIT_COMMAND_MARKER));
        assert!(capped.starts_with(&"€".repeat(166)));
    }

    // ---- F5/F10: a command lifecycle pins its arm session ----

    #[test]
    fn rearm_is_refused_while_an_admission_is_in_flight() {
        let (m, p) = machine();
        m.arm(Some(30), Some(2), false, 0, 1).unwrap();
        // An admitted-but-not-yet-spawned admission already blocks re-arm:
        // the executor-error refund path must stay attributable to the
        // session that admitted the command (F10).
        let admission = m.admit(1, 0, 0, "test", "echo x").unwrap();
        let refused = m.arm(Some(30), None, false, 0, 1).unwrap_err();
        assert_eq!(refused.code, -32000);
        assert_eq!(refused.reason.as_deref(), Some("COMMAND_IN_FLIGHT"));

        // Executor-error path: the refund ends the admission lifecycle
        // and re-arm becomes possible again.
        drop(m.spawn_permit(&admission).unwrap());
        m.refund_quota().unwrap();
        m.arm(Some(30), None, false, 0, 1).unwrap();

        // Successful-command path: record_execution ends it too. The
        // spawn permit is dropped right after spawn, exactly like the
        // executor does.
        let admission = m.admit(1, 0, 0, "test", "echo y").unwrap();
        drop(m.spawn_permit(&admission).unwrap());
        m.record_execution("EXEC_ALLOWED", 1, 0, 0, "test", object(&[]))
            .unwrap();
        m.arm(Some(30), None, false, 0, 1).unwrap();
        let _ = fs::remove_file(p);
    }

    // ---- F6: invalid commands must not burn quota or reach the log ----

    #[test]
    fn empty_or_nul_command_rejection_does_not_consume_quota() {
        let (m, p) = machine();
        m.arm(Some(30), Some(1), false, 0, 1).unwrap();
        for bad in ["", "   ", "echo \u{0} x"] {
            let error = m.admit(1, 0, 0, "test", bad).unwrap_err();
            assert!(
                error.contains("Invalid params"),
                "invalid command {bad:?} misclassified: {error}"
            );
        }
        let status = m.status().unwrap();
        assert_eq!(status["is_armed"], true);
        assert_eq!(
            status["quota_remaining"], 1,
            "invalid commands must not burn the quota slot"
        );
        let log = fs::read_to_string(&p).unwrap();
        assert!(
            !log.contains("EXEC_"),
            "invalid commands must not reach the audit log: {log}"
        );
        // The final slot is still spendable on a real command.
        let admission = m.admit(1, 0, 0, "test", "echo ok").unwrap();
        assert!(admission.final_slot);
        let _ = fs::remove_file(p);
    }

    // ---- F7: EXEC_START truthfulness and session correlation ----

    #[test]
    fn invalidated_admission_is_never_audited_as_started() {
        let (m, p) = machine();
        m.arm(Some(30), Some(2), false, 0, 1).unwrap();
        let admission = m.admit(1, 0, 0, "test", "echo x").unwrap();
        // A disarm lands between admission and process start.
        m.disarm(0).unwrap();

        m.audit_event(
            "EXEC_START",
            Some(1),
            Some(0),
            Some(0),
            Some("test"),
            object(&[
                ("command", json!("echo x")),
                ("decision", json!("ADMITTED")),
            ]),
        )
        .unwrap();
        assert!(m.spawn_permit(&admission).is_err());

        let log = fs::read_to_string(&p).unwrap();
        assert!(!log.contains("EXEC_START"), "audit log: {log}");
        assert!(!log.contains("ADMITTED"), "audit log: {log}");
        let aborted = log
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["event_type"] == "EXEC_ABORTED")
            .expect("EXEC_ABORTED compensating record");
        assert_eq!(aborted["decision"], "ABORTED");
        assert_eq!(aborted["reason"], "ADMISSION_INVALIDATED_BEFORE_SPAWN");
        assert_eq!(aborted["command"], "echo x");
        assert!(aborted["session_id"].is_string());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn final_slot_admission_is_still_audited_as_started() {
        let (m, p) = machine();
        m.arm(Some(30), Some(1), false, 0, 1).unwrap();
        let admission = m.admit(1, 0, 0, "test", "echo final").unwrap();
        assert!(admission.final_slot);
        // QUOTA_LOCK disarmed the machine, but the final-slot admission
        // remains spawnable: EXEC_START must still be recorded.
        m.audit_event(
            "EXEC_START",
            Some(1),
            Some(0),
            Some(0),
            Some("test"),
            object(&[
                ("command", json!("echo final")),
                ("decision", json!("ADMITTED")),
            ]),
        )
        .unwrap();
        assert!(m.spawn_permit(&admission).is_ok());
        let log = fs::read_to_string(&p).unwrap();
        assert!(log.contains("EXEC_START"), "audit log: {log}");
        assert!(log.contains("ADMITTED"), "audit log: {log}");
        assert!(!log.contains("EXEC_ABORTED"), "audit log: {log}");
        let _ = fs::remove_file(p);
    }

    #[test]
    fn exec_audit_records_carry_the_authorizing_session_id() {
        let (m, p) = machine();
        // A rejection before any arm carries an explicit null session_id.
        m.reject_if_disarmed(1, 0, 0, "test", "echo denied")
            .unwrap();
        let armed = m.arm(Some(30), None, false, 0, 1).unwrap();
        let sid = armed["session_id"].as_str().unwrap().to_string();
        m.audit_event(
            "EXEC_BLOCKED",
            Some(1),
            Some(0),
            Some(0),
            Some("test"),
            object(&[
                ("command", json!("echo blocked")),
                ("decision", json!("GUARDRAIL_BLOCKED")),
            ]),
        )
        .unwrap();
        let _admission = m.admit(1, 0, 0, "test", "echo x").unwrap();
        m.audit_event(
            "EXEC_START",
            Some(1),
            Some(0),
            Some(0),
            Some("test"),
            object(&[
                ("command", json!("echo x")),
                ("decision", json!("ADMITTED")),
            ]),
        )
        .unwrap();
        m.record_execution(
            "EXEC_ALLOWED",
            1,
            0,
            0,
            "test",
            object(&[("command", json!("echo x")), ("decision", json!("ALLOWED"))]),
        )
        .unwrap();
        m.disarm(0).unwrap();
        m.reject_if_disarmed(1, 0, 0, "test", "echo after").unwrap();

        let mut saw_pre_arm_rejection = false;
        let mut correlated = 0;
        for line in fs::read_to_string(&p).unwrap().lines() {
            let record: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("unparseable audit line: {e}: {line}"));
            let event = record["event_type"].as_str().unwrap_or_default();
            match event {
                "EXEC_REJECTED" if record["session_id"].is_null() => {
                    saw_pre_arm_rejection = true;
                }
                "EXEC_BLOCKED" | "EXEC_START" | "EXEC_ALLOWED" | "EXEC_REJECTED" => {
                    assert_eq!(
                        record["session_id"].as_str(),
                        Some(sid.as_str()),
                        "{event} lacks session correlation: {record}"
                    );
                    correlated += 1;
                }
                _ => {}
            }
        }
        assert!(
            saw_pre_arm_rejection,
            "pre-arm rejection lacks its explicit null session_id"
        );
        assert!(
            correlated >= 4,
            "expected EXEC_BLOCKED/EXEC_START/EXEC_ALLOWED/post-disarm EXEC_REJECTED, got {correlated}"
        );
        let _ = fs::remove_file(p);
    }
}
