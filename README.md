# Agent Root Runner

<p align="center">
  <strong>Autonomous root command execution for AI coding agents with human-in-the-loop arming, kernel-enforced identity, and OS destabilization guardrails.</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT"/></a>
  <a href="#security-model"><img src="https://img.shields.io/badge/auth-SO__PEERCRED-blue.svg" alt="Auth SO_PEERCRED"/></a>
  <a href="#automated-testing"><img src="https://img.shields.io/badge/tests-59%2F59%20passed%20(100%25)-brightgreen.svg" alt="Tests 100% Passed"/></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"/></a>
</p>

---

## Philosophy & Threat Model

### Full Privileges by Design
The explicit purpose of **Agent Root Runner** is to grant autonomous AI coding agents (Antigravity, OpenCode, Pi, Claude Code, and others) **full administrative privilege** to execute whatever system tasks they require without continuous human intervention.

### What This Project IS and IS NOT
- **NOT an Absolute Sandbox**: This project does **not** provide zero-trust isolation or an unbreachable jail. The agent has genuine root privileges.
- **NOT Protection for Personal Data**: The system **does not** block the agent from modifying or deleting user workspace files, personal data, or `/home`. Constraining personal file access would paralyze the agent during ordinary build and development workflows.
- **A Guardrail Against System Destabilization**: The guardrails focus strictly on preventing catastrophic OS-level wreckage: destroying partition tables, corrupting the root filesystem, corrupting bootloader configs, tampering with dynamic linkers, or locking PAM authentication so the operator can never log in again.
- **Zero-Credential Workflow**: The primary workflow improvement is eliminating the need to supply interactive `sudo` passwords in prompts, preventing root credentials from being recorded in LLM model context and remote API logs.
- **Backups Are Always Required**: No automated guardrail can replace regular, independent backups. Privileged AI agents can and will break user data if instructed or hallucinating; always keep backups.

---

## Architecture

```
Operator (Human Admin)
   |  $ agent-root-runner arm --duration 300
   v
+-------------------------------------------------------------------------+
| Linux Kernel Socket Buffer (SO_PEERCRED peer credential verification)   |
+-------------------------------------------------------------------------+
                               ^
                               | Unix domain socket (/run/agent-root-runner/runner.sock)
                               |
+------------------------------+------------------------------------------+
| AI Agent Harnesses                                                      |
|   - Antigravity (agy)        - OpenCode (opencode)       - Pi (pi)      |
|                                                                         |
| Stdio MCP (agent-root-mcp) / CLI Wrapper (agent-root-exec)              |
+------------------------------+------------------------------------------+
                               v
+-------------------------------------------------------------------------+
| Root Daemon (agent-root-runner-daemon)                                  |
|   1. In-Memory State Machine  -> Check ARMED / Quota / Timeout          |
|   2. Universal Guardrails     -> Evaluate OS destabilization rules      |
|   3. Subprocess Executor      -> Isolated process group + RLIMIT caps   |
|   4. NDJSON Audit Logger      -> Append-only record with fdatasync      |
+-------------------------------------------------------------------------+
                               v (Only if ARMED and Guardrails PASS)
                      Privileged Subprocess (UID 0)
```

- **Root Daemon** (`src/daemon/server.py`): Systemd service running as root, owning the Unix domain socket.
- **Kernel-Verified Identity** (`src/daemon/auth.py`): Uses `SO_PEERCRED` to inspect the peer process UID, GID, and PID directly from the kernel. Non-root users cannot arm the service.
- **In-Memory State Machine** (`src/daemon/state.py`): The `ARMED` state exists only in memory; restarts immediately reset the daemon to `DISARMED`.
- **Universal Guardrails** (`src/guardrails/analyzer.py`): Pre-execution AST and stream inspection designed to catch OS destabilization universally across storage layouts and Linux distributions.
- **Subprocess Isolation** (`src/daemon/executor.py`): Executes commands in new process groups (`setpgid`) with resource limits (`RLIMIT`) and signal-tree cleanup.

---

## Installation & Setup

### 1. Install

A single command installs everything: it places the four CLI entry points on
`/usr/local/bin`, installs the systemd unit, enables the service, and starts and
verifies it.

**From a source checkout:**

```bash
git clone https://github.com/khoipm06/agent-root-runner.git
cd agent-root-runner
sudo ./bin/agent-root-runner install
```

**Or from a prebuilt release** (standalone binaries, no Python toolchain needed):

```bash
curl -LO https://github.com/khoipm06/agent-root-runner/releases/latest/download/agent-root-runner-linux-x86_64.tar.gz
tar xzf agent-root-runner-linux-x86_64.tar.gz
sudo ./agent-root-runner install
```

`install` is idempotent and safe to re-run (for example after a `git pull`).

### 2. Verify

```bash
agent-root-runner status
```

Expected output (the daemon starts **DISARMED** by design):

```text
State: DISARMED
Armed: False
Socket: /run/agent-root-runner/runner.sock
Daemon PID: <pid>
Daemon is disarmed. Run 'agent-root-runner arm' to enable.
```

*Note: Your non-root user must belong to the `wheel` group to reach the socket
(`sudo usermod -aG wheel $USER`; log out and back in afterwards).*

### 3. Uninstall

```bash
sudo agent-root-runner uninstall
```

> **Note:** The standalone binaries are PyInstaller one-file executables that
> unpack into `$TMPDIR` at runtime. On systems where `/tmp` (or `$TMPDIR`) is
> mounted `noexec`, set `TMPDIR` to an executable filesystem (or use a source
> install) before running them.

---

## Operator Workflow (Human-in-the-Loop)

1. **Arm**: Open a bounded execution window before tasking an agent with administrative work:
   ```bash
   # Arm for 5 minutes (300 seconds)
   sudo agent-root-runner arm --duration 300

   # Arm for 10 minutes, capped at 25 commands
   sudo agent-root-runner arm --duration 600 --quota 25
   ```

2. **Agent Execution**: The agent calls `agent-root-exec` or the MCP tool `run_privileged_command`:
   ```bash
   agent-root-exec -- <command...>
   ```

3. **Disarm**: The daemon automatically locks when `--duration` expires or `--quota` is exhausted. The operator may disarm immediately at any time:
   ```bash
   sudo agent-root-runner disarm
   ```

---

## Agent Harness Integration (MCP Server)

All supported harnesses connect via the stdio MCP binary `/usr/local/bin/agent-root-mcp`.

### Registration via Native CLI

The `agent-root-mcp` entry point is already on `PATH` after
`agent-root-runner install`. Register it with your harness's official CLI:

| Harness | Registration Command | Scope / Notes |
|---|---|---|
| **Antigravity (`agy`)** | `agy mcp add agent-root-runner /usr/local/bin/agent-root-mcp` | Adds to global Antigravity MCP settings |
| **OpenCode (`opencode`)** | `opencode mcp add --global agent-root-runner -- /usr/local/bin/agent-root-mcp` | `--global` configures across all projects |
| **Pi Coding Agent (`pi`)** | `pi mcp add agent-root-runner -- /usr/local/bin/agent-root-mcp` | Adds to `~/.pi/agent/mcp.json` |

### MCP Tool Schema

The agent gains access to the tool **`run_privileged_command`**:

| Parameter | Type | Required | Description | Default |
|---|---|:---:|---|---|
| `command` | `string` | **Yes** | Shell command to execute with root privileges | — |
| `workdir` | `string` | No | Working directory for execution | `/` |
| `timeout` | `integer` | No | Execution timeout threshold in seconds | `60` |
| `env` | `object` | No | Additional environment variables | `{}` |

---

## Destabilization Guardrails (Universal System Protection)

The guardrails inspect commands to block actions that render the underlying operating system unusable. They resolve storage topologies, device classes, and critical mount hierarchies dynamically to ensure universal protection across any Linux machine.

| Rule Identifier | Description & Scope |
|---|---|
| `RULE_PIPELINE_XARGS_DATAFLOW` | Pipeline dataflow inspection blocking stream-fed mutating commands directed at core system paths. |
| `RULE_BLOCK_DEV_RAW_WRITE` | Protection against direct byte-level writes, formatting, and wiping of system block devices, partitions, RAID arrays, device-mapper targets, and virtual disks. |
| `RULE_FS_RECURSIVE_ROOT_DELETE` | Protection against deletion of core system mount roots (`/`, `/sysroot`, `/boot`, `/etc`, `/usr`, `/var`, `/lib`, `/bin`) and destructive archive extraction targeting root. |
| `RULE_MOUNT_INTEGRITY` | Protection against mount overlaying or hijacking targeting critical OS directories. |
| `RULE_BOOTLOADER_TAMPERING` | Protection against bootloader corruption, EFI boot variable deletion, kernel module unloading, and kernel boot parameter mutation (`grubby`). |
| `RULE_BOOT_CONFIG_INTEGRITY` | Protection against in-place edits, symlinking, and truncation of critical boot configurations (`/etc/fstab`, `/etc/crypttab`, `/boot`). |
| `RULE_LINKER_HIJACK` | Protection against dynamic linker preloading and hijacking (`/etc/ld.so.preload`, `/etc/ld.so.conf.d`). |
| `RULE_AUTH_FILE_MUTATION` | Protection against tampering with system authentication databases (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/pam.d`). |
| `RULE_RECURSIVE_PERM_CHANGE` | Protection against stripping execution permissions from system roots or essential system binaries. |
| `RULE_PERSISTENCE_TAMPER` | Protection against wiping system crontabs and truncating sensitive system audit logs. |
| `RULE_RESOURCE_FORK_BOMB` | Static analysis blocking recursive shell fork bomb definitions. |
| `RULE_NETWORK_ISOLATION` | Protection against unmitigated firewall rule flushes and stopping primary network management daemons. |

---

## Exit Codes & Error Reference

`agent-root-exec` maps daemon responses into standard POSIX-compliant exit codes:

| Exit Code | Semantics | JSON-RPC Code | Root Cause & Resolution |
|:---:|---|:---:|---|
| `0` | **Success** | — | Command completed with exit code 0. |
| `1` | **Permission / Usage Error** | `-32003` (`PERMISSION_DENIED`) | User not in `wheel`, socket unreachable, or non-root `arm` invocation. |
| `124` | **Execution Timeout** | `-32004` (`TIMEOUT`) | Process exceeded `--timeout` threshold (default 60s). |
| `125` | **Disarmed / Quota Exhausted** | `-32001` (`DISARMED`) | Daemon is locked. Operator must run `sudo agent-root-runner arm`. |
| `126` | **Guardrail Blocked** | `-32002` (`GUARDRAIL_BLOCKED`) | Command matched an OS destabilization rule. |
| `128` | **Internal Daemon Error** | `-32603` (`INTERNAL_ERROR`) | Unexpected daemon error or RPC protocol failure. |

A command that executes successfully passes its **own** exit status straight
through (`0`–`255`). The codes above are emitted by the wrapper for *daemon-level*
conditions, so a command that itself exits `124`/`125`/`126` is indistinguishable
from a wrapper signal — check stderr for the `agent-root-exec:` prefix to tell
them apart.

---

## Security Model & Audit Trail

- **Root Arming Enforcement**: Arming requests (`arm`) must originate from UID 0 (`peer_uid == 0`). Non-root clients receive `-32003 PERMISSION_DENIED`.
- **Socket Permissions**: `/run/agent-root-runner/` is created with mode `0750` (owned by `root:wheel`), and `runner.sock` with mode `0660`. Non-root clients must be members of the `wheel` group.
- **Append-Only Audit Log**: Stored at `/var/log/agent-root-runner/audit.log` (mode `0600`), synced with `fdatasync`.
- **Fail-Closed Disarm**: Every arm session is bounded by a dual-tier timer and an optional command quota. When the window closes — timeout, quota exhaustion, or a manual `disarm` — any privileged command still running is **SIGKILLed** so it cannot outlive its authorization.
- **Development Mode**: `agent-root-runner-daemon --allow-user-arm` lets any local socket user arm. It is **refused when the daemon runs as root**, so it can never grant a non-root user root execution; run the daemon as your own unprivileged user for local development.

```bash
# View recent audit decisions
sudo tail -20 /var/log/agent-root-runner/audit.log | python3 -m json.tool --json-lines

# Find all commands blocked by guardrails
sudo grep "GUARDRAIL_BLOCKED" /var/log/agent-root-runner/audit.log
```

---

## Automated Testing

The repository includes a comprehensive 4-tier automated test suite requiring no sudo password prompts. The E2E tiers spawn the **real** `src.daemon.server` process (unprivileged, with `--allow-user-arm`), so they exercise the production state machine, guardrail analyzer, executor, and audit logger end-to-end.

```bash
# Run all 4 E2E tiers (59 tests)
./tests/test_runner.sh

# Run full unit and adversarial test suites (270 tests)
python3 -m unittest discover -s tests -t .
```

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
