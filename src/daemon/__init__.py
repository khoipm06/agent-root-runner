"""Agent Root Runner Daemon Package.

Provides Unix domain socket IPC, authentication, state management,
subprocess execution, and audit logging.
"""

from src.daemon.audit import AuditLogger
from src.daemon.auth import (
    AuthenticationError,
    AuthorizationError,
    PeerCredentials,
    check_arm_permission,
    check_disarm_permission,
    extract_peer_credentials,
    get_peer_credentials,
    get_process_info,
    is_arm_authorized,
)
from src.daemon.executor import (
    ExecutionResult,
    ExecutorError,
    InvalidEnvironmentError,
    InvalidWorkdirError,
    SubprocessExecutor,
)
from src.daemon.server import AgentRootRunnerDaemon, DaemonServer, resolve_socket_path
from src.daemon.state import (
    ArmSession,
    DaemonState,
    DisarmReason,
    RunnerState,
    RunnerStateMachine,
    StateMachine,
)

__all__ = [
    "AgentRootRunnerDaemon",
    "DaemonServer",
    "resolve_socket_path",
    "PeerCredentials",
    "AuthenticationError",
    "AuthorizationError",
    "get_peer_credentials",
    "extract_peer_credentials",
    "get_process_info",
    "is_arm_authorized",
    "check_arm_permission",
    "check_disarm_permission",
    "RunnerState",
    "DaemonState",
    "ArmSession",
    "DisarmReason",
    "RunnerStateMachine",
    "StateMachine",
    "SubprocessExecutor",
    "ExecutionResult",
    "ExecutorError",
    "InvalidEnvironmentError",
    "InvalidWorkdirError",
    "AuditLogger",
]
