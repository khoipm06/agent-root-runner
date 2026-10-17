"""Arming State Machine and Dual-Tier Auto-Lock Engine.

Part of Milestone 1 (M1) of Agent Root Runner.
Provides a fail-closed state machine, dual-tier auto-lock timer,
atomic quota accounting, and audit integration.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import time
from typing import Any, Optional, Protocol, Tuple
import uuid

from src.daemon.auth import is_arm_authorized


class RunnerState(str, Enum):
    """Operational states of the daemon."""
    DISARMED = "DISARMED"
    ARMED = "ARMED"


# Alias for compatibility with explorer blueprints
DaemonState = RunnerState


class DisarmReason(str, Enum):
    """Reasons triggering a transition to DISARMED."""
    MANUAL_DISARM = "MANUAL_DISARM"
    TIMEOUT_EXPIRED = "TIMEOUT_EXPIRED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    SHUTDOWN = "SHUTDOWN"
    RESET = "RESET"


@dataclass
class ArmSession:
    """Active arming session metadata."""
    session_id: str
    arm_timestamp: float
    duration_seconds: int = 900
    expires_at_monotonic: float = 0.0
    quota: Optional[int] = None
    quota_remaining: Optional[int] = None
    requester_uid: int = 0
    requester_pid: Optional[int] = None


class AuditLoggerProtocol(Protocol):
    """Protocol for decoupled audit logger integration."""
    def log(self, event_type: str, data: dict[str, Any]) -> None:
        ...


class RunnerStateMachine:
    """Fail-closed state machine with dual-tier auto-lock and quota tracking.

    Invariants:
    1. Default initial state is always DISARMED.
    2. State is strictly in-memory; restarts always reset to DISARMED.
    3. State mutations are protected by an asyncio.Lock.
    4. Auto-lock is enforced proactively (active asyncio.sleep) and
       reactively (monotonic timestamp guard on every request).
    """

    DEFAULT_DURATION_SECONDS: int = 900   # 15 minutes
    MAX_DURATION_SECONDS: int = 86400       # 24 hours

    def __init__(self, audit_logger: Optional[Any] = None) -> None:
        self._audit_logger = audit_logger
        self._lock = asyncio.Lock()

        self._state: RunnerState = RunnerState.DISARMED
        self._session: Optional[ArmSession] = None
        self._timer_task: Optional[asyncio.Task[None]] = None

        self._session_commands_executed: int = 0
        self._in_flight_commands: int = 0
        self._lifetime_commands: int = 0
        self._last_disarm_reason: Optional[str] = None

    @property
    def state(self) -> RunnerState:
        return self._state

    async def arm(
        self,
        duration_seconds: int = DEFAULT_DURATION_SECONDS,
        quota: Optional[int] = None,
        requester_uid: int = 0,
        allow_user_arm: bool = False,
        requester_pid: Optional[int] = None,
    ) -> dict[str, Any]:
        """Transitions the daemon to the ARMED state.

        Raises:
            PermissionError: If requester_uid is not authorized.
            ValueError: If duration_seconds or quota are invalid.
        """
        if not is_arm_authorized(requester_uid, allow_user_arm=allow_user_arm):
            raise PermissionError(
                f"Permission denied: Arming requires root privileges (peer_uid == 0, got {requester_uid}). "
                "Run 'sudo agent-root-runner arm' to enable."
            )

        if not isinstance(duration_seconds, int) or duration_seconds < 1:
            raise ValueError("duration_seconds must be a positive integer >= 1")
        if duration_seconds > self.MAX_DURATION_SECONDS:
            raise ValueError(f"duration_seconds exceeds maximum limit of {self.MAX_DURATION_SECONDS}s")

        if quota is not None:
            if not isinstance(quota, int) or quota < 1:
                raise ValueError("quota must be a positive integer >= 1 or None")

        async with self._lock:
            # Cancel existing timer task if re-arming
            if self._timer_task is not None and not self._timer_task.done():
                self._timer_task.cancel()
                self._timer_task = None

            now_epoch = time.time()
            now_mono = time.monotonic()
            session_id = f"arm_{int(now_epoch)}_{uuid.uuid4().hex[:6]}"

            self._session = ArmSession(
                session_id=session_id,
                arm_timestamp=now_epoch,
                duration_seconds=duration_seconds,
                expires_at_monotonic=now_mono + duration_seconds,
                quota=quota,
                quota_remaining=quota,
                requester_uid=requester_uid,
                requester_pid=requester_pid,
            )
            self._state = RunnerState.ARMED
            self._session_commands_executed = 0
            self._in_flight_commands = 0
            self._last_disarm_reason = None

            # Spawn Active Countdown Task (Tier 1)
            self._timer_task = asyncio.create_task(
                self._auto_lock_countdown(session_id, duration_seconds)
            )

            # Emit audit log event
            self._emit_audit("ARM", {
                "session_id": session_id,
                "duration_seconds": duration_seconds,
                "timeout_seconds": duration_seconds,
                "quota": quota,
                "uid": requester_uid,
                "pid": requester_pid,
                "expires_at": self._format_iso(now_epoch + duration_seconds),
            })

            return self._build_status_dict_locked()

    async def disarm(
        self,
        reason: str = DisarmReason.MANUAL_DISARM.value,
        disarmed_by_uid: Optional[int] = None,
    ) -> dict[str, Any]:
        """Transitions daemon to DISARMED and terminates active session."""
        async with self._lock:
            return self._transition_to_disarmed_locked(
                reason=reason,
                disarmed_by_uid=disarmed_by_uid,
            )

    async def reset(self) -> None:
        """Pristine reset of state machine for shutdown or test teardown."""
        async with self._lock:
            if self._timer_task is not None and not self._timer_task.done():
                self._timer_task.cancel()
                self._timer_task = None
            self._state = RunnerState.DISARMED
            self._session = None
            self._session_commands_executed = 0
            self._in_flight_commands = 0
            self._last_disarm_reason = None

    async def get_status(self) -> dict[str, Any]:
        """Returns state snapshot, evaluating passive expiry first."""
        async with self._lock:
            self._check_passive_expiry_locked()
            return self._build_status_dict_locked()

    async def is_armed(self) -> bool:
        """Returns True if daemon is currently in valid ARMED state."""
        async with self._lock:
            self._check_passive_expiry_locked()
            return self._state == RunnerState.ARMED

    async def check_permission_and_decrement_quota(self) -> Tuple[bool, str]:
        """Atomically evaluates admission and decrements quota for an incoming command.

        Returns:
            Tuple of (allowed: bool, reason_message: str).
        """
        async with self._lock:
            self._check_passive_expiry_locked()

            if self._state != RunnerState.ARMED or self._session is None:
                if self._last_disarm_reason == DisarmReason.QUOTA_EXHAUSTED.value:
                    return False, "Execution quota exhausted. Re-arm with 'sudo agent-root-runner arm'."
                return False, "Service is DISARMED. Run 'sudo agent-root-runner arm' to enable."

            if self._session.quota_remaining is not None:
                if self._session.quota_remaining <= 0:
                    self._transition_to_disarmed_locked(reason=DisarmReason.QUOTA_EXHAUSTED.value)
                    return False, "Execution quota exhausted. Re-arm with 'sudo agent-root-runner arm'."

                self._session.quota_remaining -= 1
                if self._session.quota_remaining <= 0:
                    # Current command is admitted as the final quota slot; lock future requests
                    self._transition_to_disarmed_locked(reason=DisarmReason.QUOTA_EXHAUSTED.value)

            self._in_flight_commands += 1
            return True, "Allowed"

    async def refund_quota(self) -> None:
        """Refunds a quota slot if command was blocked pre-execution by guardrails.

        Security invariants:
        1. Only transitions back to ARMED if the previous disarm was caused
           strictly by QUOTA_EXHAUSTED.
        2. Never overrides MANUAL_DISARM, SHUTDOWN, RESET, or TIMEOUT_EXPIRED.
        3. If re-arming, restarts the active auto-lock countdown timer task
           for the remaining session duration.
        4. Quota remaining is capped at the session's configured quota limit.
        """
        async with self._lock:
            if self._in_flight_commands > 0:
                self._in_flight_commands -= 1

            if self._session is not None and self._session.quota_remaining is not None:
                # 1. Refund quota slot capped at session limit
                if self._session.quota is not None:
                    self._session.quota_remaining = min(
                        self._session.quota, self._session.quota_remaining + 1
                    )
                else:
                    self._session.quota_remaining += 1

                # 2. Re-arm ONLY if locked strictly due to quota exhaustion
                if (
                    self._state == RunnerState.DISARMED
                    and self._last_disarm_reason == DisarmReason.QUOTA_EXHAUSTED.value
                ):
                    if self._is_time_expired_locked():
                        # Session time has elapsed; transition to timeout disarm
                        self._last_disarm_reason = DisarmReason.TIMEOUT_EXPIRED.value
                    else:
                        # Restore ARMED state
                        self._state = RunnerState.ARMED
                        self._last_disarm_reason = None

                        # 3. Restart Active Countdown Task for remaining duration
                        remaining_seconds = max(
                            0.0, self._session.expires_at_monotonic - time.monotonic()
                        )
                        if self._timer_task is not None and not self._timer_task.done():
                            self._timer_task.cancel()
                        self._timer_task = asyncio.create_task(
                            self._auto_lock_countdown(
                                self._session.session_id, remaining_seconds
                            )
                        )

                        # 4. Emit audit log event for re-arming via quota refund
                        self._emit_audit("ARM", {
                            "session_id": self._session.session_id,
                            "reason": "QUOTA_REFUND",
                            "quota_remaining": self._session.quota_remaining,
                            "remaining_seconds": round(remaining_seconds, 1),
                        })

    async def record_command_execution(
        self,
        command: str = "",
        exit_code: int = 0,
        duration_ms: float = 0.0,
    ) -> None:
        """Records completion of an executed command."""
        async with self._lock:
            if self._in_flight_commands > 0:
                self._in_flight_commands -= 1
            self._session_commands_executed += 1
            self._lifetime_commands += 1

    # Aliases matching explorer_m1_2 blueprint
    check_execution_permission = check_permission_and_decrement_quota
    record_execution_start = check_permission_and_decrement_quota
    record_execution_finish = record_command_execution

    # -------------------------------------------------------------------------
    # Internal Dual-Tier Engine & Helper Routines (Must be called under lock)
    # -------------------------------------------------------------------------

    async def _auto_lock_countdown(self, session_id: str, timeout_seconds: float) -> None:
        """Tier-1 Active background timer task."""
        try:
            await asyncio.sleep(timeout_seconds)
            async with self._lock:
                if (
                    self._state == RunnerState.ARMED
                    and self._session is not None
                    and self._session.session_id == session_id
                ):
                    self._transition_to_disarmed_locked(reason=DisarmReason.TIMEOUT_EXPIRED.value)
        except asyncio.CancelledError:
            pass

    def _check_passive_expiry_locked(self) -> None:
        """Tier-2 Passive monotonic timestamp guard."""
        if self._state == RunnerState.ARMED and self._is_time_expired_locked():
            self._transition_to_disarmed_locked(reason=DisarmReason.TIMEOUT_EXPIRED.value)

    def _is_time_expired_locked(self) -> bool:
        if self._session is None or self._session.expires_at_monotonic == 0.0:
            return False
        return time.monotonic() >= self._session.expires_at_monotonic

    def _transition_to_disarmed_locked(
        self,
        reason: str,
        disarmed_by_uid: Optional[int] = None,
    ) -> dict[str, Any]:
        """Transitions state to DISARMED under lock."""
        previous_state = self._state.value
        already_disarmed = previous_state == RunnerState.DISARMED.value

        if self._timer_task is not None and not self._timer_task.done():
            self._timer_task.cancel()
            self._timer_task = None

        session_id = self._session.session_id if self._session else None
        active_duration = 0.0
        if self._session is not None:
            active_duration = max(0.0, round(time.time() - self._session.arm_timestamp, 2))
        commands_run = self._session_commands_executed

        self._state = RunnerState.DISARMED
        self._last_disarm_reason = reason

        # Map event name for audit log
        event_name = "DISARM"
        if reason == DisarmReason.TIMEOUT_EXPIRED.value:
            event_name = "TIMEOUT_LOCK"
        elif reason == DisarmReason.QUOTA_EXHAUSTED.value:
            event_name = "QUOTA_LOCK"
        elif reason == DisarmReason.SHUTDOWN.value:
            event_name = "DAEMON_STOP"

        self._emit_audit(event_name, {
            "session_id": session_id,
            "reason": reason,
            "disarmed_by_uid": disarmed_by_uid,
            "active_duration_seconds": active_duration,
            "commands_executed": commands_run,
        })

        return {
            "state": RunnerState.DISARMED.value,
            "previous_state": previous_state,
            "session_id": session_id,
            "reason": reason,
            "commands_executed": commands_run,
            "active_duration_seconds": active_duration,
            "already_disarmed": already_disarmed,
            "message": "Service successfully disarmed." if not already_disarmed else "Service was already disarmed.",
        }

    def _build_status_dict_locked(self) -> dict[str, Any]:
        now_mono = time.monotonic()
        remaining = 0.0
        session_id = None
        armed_at_iso = None
        expires_at_iso = None
        duration = None
        quota = None
        quota_remaining = None

        if self._session is not None:
            session_id = self._session.session_id
            duration = self._session.duration_seconds
            quota = self._session.quota
            quota_remaining = self._session.quota_remaining
            armed_at_iso = self._format_iso(self._session.arm_timestamp)
            expires_at_iso = self._format_iso(self._session.arm_timestamp + self._session.duration_seconds)

            if self._state == RunnerState.ARMED:
                remaining = max(0.0, round(self._session.expires_at_monotonic - now_mono, 1))

        return {
            "state": self._state.value,
            "is_armed": self._state == RunnerState.ARMED,
            "session_id": session_id,
            "armed_at": armed_at_iso,
            "expires_at": expires_at_iso,
            "remaining_seconds": remaining,
            "timeout_seconds": duration,
            "duration_seconds": duration,
            "quota_limit": quota,
            "quota": quota,
            "quota_remaining": quota_remaining,
            "commands_executed": self._session_commands_executed,
            "lifetime_commands": self._lifetime_commands,
        }

    def _emit_audit(self, event_type: str, data: dict[str, Any]) -> None:
        if self._audit_logger is not None:
            try:
                if hasattr(self._audit_logger, "log"):
                    self._audit_logger.log(event_type, data)
                elif hasattr(self._audit_logger, "log_event"):
                    self._audit_logger.log_event(event_type, **data)
            except Exception:
                pass

    @staticmethod
    def _format_iso(epoch_seconds: float) -> str:
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )


# Class alias for blueprint compatibility
StateMachine = RunnerStateMachine
