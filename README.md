# Agent Root Runner

<p align="center">
  <strong>Autonomous root command execution for AI coding agents with human-in-the-loop arming, kernel-enforced identity, and OS destabilization guardrails.</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT"/></a>
  <a href="#security-model"><img src="https://img.shields.io/badge/auth-SO__PEERCRED-blue.svg" alt="Auth SO_PEERCRED"/></a>
  <a href="#automated-testing"><img src="https://img.shields.io/badge/tests-Rust%20unit%20%26%20integration-blue.svg" alt="Rust unit and integration tests"/></a>
  <img src="https://img.shields.io/badge/runtime-native%20Rust-orange.svg" alt="Native Rust runtime"/>
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
| Stdio MCP / CLI Wrapper (`agent-root-runner mcp|exec`)                   |
+------------------------------+------------------------------------------+
                               v
+-------------------------------------------------------------------------+
| Root Daemon (`agent-root-runner daemon`)                                 |
|   1. In-Memory State Machine  -> Check ARMED / Quota / Timeout          |
|   2. Universal Guardrails     -> Evaluate OS destabilization rules      |
|   3. Subprocess Executor      -> Isolated process group + RLIMIT caps   |
|   4. NDJSON Audit Logger      -> Append-only record with fdatasync      |
+-------------------------------------------------------------------------+
                               v (Only if ARMED and Guardrails PASS)
                      Privileged Subprocess (UID 0)
```

- **Single Native Executable**: One Rust ELF provides management, daemon, `exec`, and stdio MCP subcommands; installed services and harnesses need no secondary runtime.
- **Kernel-Verified Identity**: The daemon reads Linux `SO_PEERCRED` credentials (UID, GID, PID) directly from the kernel. Non-root users cannot ARM the service.
- **Volatile State Machine**: `ARMED` state exists only in memory; daemon restarts immediately reset it to `DISARMED`.
- **Universal Guardrails**: Pre-execution shell parsing and OS-destabilization rules inspect storage, auth, boot, linker, persistence, process, network, and mount changes.
- **Subprocess Isolation**: Commands execute in new process groups with resource limits and process-tree cleanup.

---

## Installation & Setup

### 1. Install

A single executable installs the service, enables it, and starts and verifies it.

**From a source checkout:**

```bash
git clone https://github.com/khoipm06/agent-root-runner.git
cd agent-root-runner
cargo build --release
sudo ./target/release/agent-root-runner install
```

**Or from a prebuilt release** (standalone native executable):

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

The release is one native ELF executable; the Plasma applet is published as a
separate archive. The executable requires no runtime extraction.

---

## Operator Workflow (Human-in-the-Loop)

1. **Arm**: Open a bounded execution window before tasking an agent with administrative work:
   ```bash
   # Arm for 5 minutes (300 seconds)
   sudo agent-root-runner arm --duration 300

   # Arm for 10 minutes, capped at 25 commands
   sudo agent-root-runner arm --duration 600 --quota 25
   ```

   ARM without a time limit only when you explicitly intend to leave privileged
   execution available. It remains active until manual disarm, quota exhaustion,
   or daemon restart; it is never restored after a restart:
   ```bash
   sudo agent-root-runner arm --forever --quota 25
   ```

2. **Agent Execution**: The agent calls the `exec` subcommand or the MCP tool `run_privileged_command`:
   ```bash
   agent-root-runner exec -- <command...>
   ```

3. **Disarm**: The daemon automatically locks when `--duration` expires or `--quota` is exhausted. The operator may disarm immediately at any time:
   ```bash
   sudo agent-root-runner disarm
   ```

   `--forever` has no time-based lock. Always use `disarm` when privileged work
   is complete. The daemon service itself is managed by systemd and normally
   stays running while its authorization state remains DISARMED.

### Plasma 6 System Tray Applet

The repository includes a Plasma 6 applet for monitoring and controlling the
daemon. It refreshes status every three seconds, offers bounded ARM and Disarm,
and requires a second confirmation before requesting an ARM without a time
limit. ARM actions invoke `pkexec` and still require system authorization.

```bash
kpackagetool6 --type Plasma/Applet --install ./plasma-applet
```

Then add **Agent Root Runner** to a panel from Plasma's **Add Widgets** dialog.
Remove it with:

```bash
kpackagetool6 --type Plasma/Applet --remove org.khoipm.agent-root-runner
```

The applet requires Agent Root Runner installed at `/usr/local/bin` and an
active `agent-root-runner.service`. The desktop user must be in the `wheel`
group to read status and send disarm requests through the protected socket (see
the install requirements above). To use the applet from a release archive,
download `agent-root-runner-plasma-applet.zip` and pass that archive to
`kpackagetool6 --type Plasma/Applet --install`.

### Command-Line Options

Management CLI:

| Command | Options | Behavior |
|---|---|---|
| `agent-root-runner [--socket PATH] status` | `--socket` overrides the daemon socket path | Show daemon/session state and quota. |
| `agent-root-runner [--socket PATH] disarm` | `--socket` overrides the daemon socket path | Immediately disable privileged execution. |
| `agent-root-runner [--socket PATH] arm` | `--duration SECONDS` (default `900`, range `1..86400`) | ARM for a bounded duration. |
| `agent-root-runner [--socket PATH] arm` | `--quota COUNT` (optional, positive integer) | Automatically disarm after this many admitted commands. Can be combined with either ARM mode. |
| `agent-root-runner [--socket PATH] arm` | `--forever` | ARM without a time deadline; mutually exclusive with `--duration`. Manual disarm, quota exhaustion, or daemon restart ends the session. |
| `agent-root-runner install` | — | Install/enable/start the systemd daemon service. Requires administrator authorization. |
| `agent-root-runner uninstall` | — | Remove the systemd service installation. Requires administrator authorization. |
| `agent-root-runner daemon` | `--audit-log PATH`, `--allow-user-arm` | Start the native Unix-socket daemon (normally systemd-managed). |
| `agent-root-runner exec` | `--timeout`, `--workdir`, `--socket`, repeated `--env KEY=VALUE`, `-- COMMAND...` | Request guarded privileged execution. |
| `agent-root-runner mcp` | `--socket` | Run stdio MCP server for harness integration. |

On a desktop with Polkit, prefix administrative CLI operations with
`pkexec` (for example, `pkexec agent-root-runner arm --duration 300`). On other
systems use the configured administrator mechanism, such as `sudo`.

Privileged execution (`exec` subcommand):

| Option | Default | Behavior |
|---|---|---|
| `--timeout SECONDS` | `60` | Maximum execution time (`1..3600` seconds); execution also cannot outlive the ARM window. |
| `--workdir PATH` | `/` | Working directory for the command. |
| `--socket PATH` | Automatically resolved | Override the daemon socket. |
| `--env KEY=VALUE` | None | Add an environment variable; repeat to pass several. |
| `command [command ...]` | Required | Command text joined with spaces and executed by the daemon. |

For example, after ARM:

```bash
agent-root-runner exec --timeout 30 --workdir / --env EDITOR=vi -- id -u
```

Daemon options (normally supplied by systemd):

| Option | Default | Behavior |
|---|---|---|
| `--socket PATH` | `/run/agent-root-runner/runner.sock` | Unix socket path. |
| `--audit-log PATH` | `/var/log/agent-root-runner/audit.log` | Append-only audit log path. |
| `--allow-user-arm` | Disabled | Development/test mode only; rejected when the daemon runs as root. |

Run `agent-root-runner <subcommand> --help` for help. The MCP server
`agent-root-runner mcp [--socket PATH]` exposes `run_privileged_command` with
`command` (required), `workdir` (default `/`), `timeout` (default `60`, range
`1..3600`), and `env` (default `{}`, string values). MCP tools execute commands but cannot ARM the daemon;
the operator must ARM first.

---

## Agent Harness Integration (MCP Server)

All supported harnesses connect to the stdio MCP subcommand of
`/usr/local/bin/agent-root-runner`.

### Registration via Native CLI

The `agent-root-runner` executable is on `PATH` after install. Register the
`mcp` subcommand with your harness's official CLI:

| Harness | Registration Command | Scope / Notes |
|---|---|---|
| **Antigravity (`agy`)** | `agy mcp add agent-root-runner /usr/local/bin/agent-root-runner mcp` | Adds to global Antigravity MCP settings |
| **OpenCode (`opencode`)** | `opencode mcp add --global agent-root-runner -- /usr/local/bin/agent-root-runner mcp` | `--global` configures across all projects |
| **Pi Coding Agent (`pi`)** | `pi mcp add agent-root-runner --exposure direct -- /usr/local/bin/agent-root-runner mcp` | Adds to `~/.pi/agent/mcp.json` and exposes the tool directly to the model |

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

Static analysis is deliberately fail-closed where it cannot determine filesystem
effects: unsupported brace-group, function, or subshell syntax; opaque
interpreter and uninspectable shebang-script execution; shell-script/source
invocations; `env -S` command strings; shell startup hooks and interactive
startup options; unresolved relative mutations; uncertain `find` actions; and chained
filesystem writes after commands that may create or move path aliases
(including `mv --exchange`) are rejected. Simple shell shebang scripts are
analyzed conservatively; interpreter version/help queries remain available.
Archive extraction is denied when member destinations cannot be verified.

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
| `RULE_EVASION_SYNTAX_ERROR` | Unsupported or malformed shell syntax that prevents reliable command analysis. |
| `RULE_EVASION_INTERPRETER_CODE` | Opaque interpreter, shebang-script, shell startup, shell-script/source, or `env -S` execution whose filesystem effects cannot be statically analyzed. |
| `RULE_EVASION_UNRESOLVED_VAR` | Unresolved paths, unverified archive member destinations, or chained filesystem mutations whose target cannot be safely established. |
| `RULE_NETWORK_ISOLATION` | Protection against unmitigated firewall rule flushes and stopping primary network management daemons. |

---

## Exit Codes & Error Reference

`agent-root-runner exec` maps daemon responses into standard POSIX-compliant exit codes:

| Exit Code | Semantics | JSON-RPC Code | Root Cause & Resolution |
|:---:|---|:---:|---|
| `0` | **Success** | — | Command completed with exit code 0. |
| `1` | **Permission / Usage Error** | `-32003` (`PERMISSION_DENIED`) | User not in the socket admin group (`wheel`/`sudo`/`adm`), socket unreachable, or non-root `arm` invocation. |
| `2` | **Invalid Parameters** | `-32602` (`INVALID_PARAMS`) | Malformed request, invalid duration/quota, blank command, or unusable workdir. |
| `124` | **Execution Timeout** | `-32004` (`TIMEOUT`) | Process exceeded `--timeout` threshold (default 60s). |
| `125` | **Disarmed / Quota Exhausted** | `-32001` (`DISARMED`) | Daemon is locked. Operator must run `sudo agent-root-runner arm`. |
| `126` | **Guardrail Blocked** | `-32002` (`GUARDRAIL_BLOCKED`) | Command matched an OS destabilization rule. |
| `128` | **Internal Daemon Error** | `-32603` (`INTERNAL_ERROR`) | Unexpected daemon error, audit-integrity failure, or RPC protocol failure. |
| `141` | **Broken Pipe** | — | Output consumer closed the pipe (for example `status \| head`); not an error. |

A command that executes successfully passes its **own** exit status straight
through (`0`–`255`). The codes above are emitted by the wrapper for *daemon-level*
conditions, so a command that itself exits `124`/`125`/`126` is indistinguishable
from a wrapper signal — check stderr for the `agent-root-runner exec:` prefix to tell
them apart.

---

## Security Model & Audit Trail

- **Root Arming Enforcement**: Arming requests (`arm`) must originate from UID 0 (`peer_uid == 0`). Non-root clients receive `-32003 PERMISSION_DENIED`.
- **Socket Permissions**: `/run/agent-root-runner/` is created with mode `0750` (owned by `root:wheel`), and `runner.sock` with mode `0660`. Non-root clients must be members of the `wheel` group.
- **Append-Only Audit Log**: Stored at `/var/log/agent-root-runner/audit.log` (mode `0600`), synced with `fdatasync`.
- **Fail-Closed Disarm**: Every arm session is bounded by a dual-tier timer and an optional command quota. When the window closes — timeout, quota exhaustion, or a manual `disarm` — any privileged command still running is **SIGKILLed** so it cannot outlive its authorization.
- **Development Mode**: `agent-root-runner daemon --allow-user-arm` lets any local socket user arm. It is **refused when the daemon runs as root**, so it can never grant a non-root user root execution; run the daemon as your own unprivileged user for local development.

```bash
# View recent audit decisions
sudo tail -20 /var/log/agent-root-runner/audit.log | jq -c .

# Find all commands blocked by guardrails
sudo grep "GUARDRAIL_BLOCKED" /var/log/agent-root-runner/audit.log
```

---

## Automated Testing

The repository's native Rust unit and integration tests exercise guardrail
vectors, daemon IPC, execution boundaries, and the release executable.

```bash
# Native unit and integration tests
cargo test --locked --all-targets
```

---

## License

This project is licensed under the terms of the [MIT License](LICENSE).
