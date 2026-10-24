# Agent Root Runner

A privileged command runner for AI coding agents. A human **arms** a root daemon
for a limited time and command quota; agents then run commands through a local
Unix socket without ever handling a `sudo` password. Guardrails block commands
that would destabilize the OS, and every decision is written to an append-only
audit log.

## Motivation

AI coding agents (such as Claude Code, Antigravity, and OpenCode) increasingly
require administrative privileges to install system packages, manage services,
configure containers, and prepare build environments.

Granting root access to autonomous models introduces a trade-off:
- **Unrestricted sudo access**: Giving agents `sudo` passwords or blanket
  `NOPASSWD: ALL` rules risks catastrophic failure—such as wiping block devices,
  breaking core authentication configurations (`/etc/shadow`, PAM, sudoers),
  corrupting bootloaders, or creating unwanted persistence mechanisms.
- **Per-command human confirmation**: Prompting an operator for every individual
  privileged invocation disrupts agent workflows and defeats autonomy.

**Agent Root Runner** resolves this trade-off:
- **Human-in-the-loop arming**: An operator explicitly grants a bounded window
  with an expiration timeout and command quota (`sudo agent-root-runner arm`).
- **Autonomy without secret sharing**: The agent executes root commands over a
  local Unix domain socket without ever reading or passing a `sudo` password.
- **Kernel-verified identity**: Callers are authenticated via kernel peer
  credentials (`SO_PEERCRED`), preventing impersonation across user boundaries.
- **OS safety guardrails**: Shell AST inspection blocks commands that threaten
  the integrity of storage, boot files, authentication, or the root filesystem.
- **Fail-closed audit log**: All decisions are written to an append-only log with
  guaranteed disk sync before execution.

## How it works

```
operator:  sudo agent-root-runner arm --duration 600 --quota 20
agent:     agent-root-runner exec -- make install      (or the MCP tool)
daemon:    checks ARMED + quota + timeout, applies guardrails, runs as root
```

- The caller is identified by the kernel (`SO_PEERCRED`), not by anything the
  client sends. Agents cannot claim another user.
- The session ends on manual disarm, expiry, quota exhaustion, or daemon
  restart. Nothing survives a reboot.
- Guardrails refuse catastrophic changes (partition tables, root filesystem,
  bootloader, PAM/shadow/sudoers, dynamic linker, mounts, cron/systemd
  persistence, fork bombs, and common shell-evasion tricks).
- This is **not a sandbox**. During an armed session the agent has genuine root
  and can modify your files. Keep backups.

## Requirements

- Linux with systemd (for `install`)
- Cargo / C toolchain 1.85+ (to build)

## Install

```bash
cargo build --release
sudo ./target/release/agent-root-runner install
```

`install` copies the binary to `/usr/local/bin`, writes
`/etc/systemd/system/agent-root-runner.service`, enables it, and starts the
daemon. It also adds the first admin group it finds (`wheel`, then `sudo`, then
`adm`) to the unit so that group can reach the socket. If none exists, the
socket stays root-only.

Default paths:

| What | Path |
|---|---|
| Socket | `/run/agent-root-runner/runner.sock` |
| Audit log | `/var/log/agent-root-runner/audit.log` |
| Unit | `/etc/systemd/system/agent-root-runner.service` |
| Binary | `/usr/local/bin/agent-root-runner` |

Every command accepts `--socket <path>` to override the socket, which is handy
for testing against a non-system daemon.

## Quick start

```bash
# Arm for 10 minutes, 20 commands
sudo agent-root-runner arm --duration 600 --quota 20

# Check state
agent-root-runner status

# Run something as root
agent-root-runner exec --workdir "$PWD" -- make install

# End the session immediately
sudo agent-root-runner disarm
```

`arm` options:

| Option | Meaning |
|---|---|
| `--duration <sec>` | Session length; default 900, maximum 86400 |
| `--quota <n>` | Maximum commands admitted before automatic disarm |
| `--forever` | No time limit; ends on manual disarm, quota exhaustion, or daemon restart |

`exec` options:

| Option | Meaning |
|---|---|
| `--timeout <sec>` | Per-command timeout, 1–3600 (default 60) |
| `--workdir <path>` | Working directory (default `/`) |
| `--env KEY=VALUE` | Extra environment variable; repeatable |

Put `--` before the command so its own flags are not parsed by the runner.

## Use from an AI agent

MCP (stdio) is the simplest integration. Register the server with your agent:

```json
{
  "mcpServers": {
    "agent-root-runner": {
      "command": "agent-root-runner",
      "args": ["mcp"]
    }
  }
}
```

It exposes one tool, `run_privileged_command`, which returns the command's exit
code, stdout and stderr. The daemon must be armed, or the call fails.

Agents can also shell out directly:

```bash
agent-root-runner exec --workdir "$PWD" -- <command...>
```

## Exit codes

| Code | Meaning |
|:--:|---|
| `0` | Command succeeded |
| `1` | Permission denied or daemon unreachable (not in the socket group, non-root `arm`, or the socket is not there) |
| `2` | Invalid parameters (bad duration/quota, blank command, unusable workdir) |
| `124` | Command timed out |
| `125` | Daemon disarmed or quota exhausted |
| `126` | Blocked by a guardrail |
| `128` | Internal daemon or audit-integrity failure |
| `141` | Output pipe closed (e.g. `status \| head`); not an error |

A command that runs successfully passes its own exit status through unchanged.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied` on the socket | Add your user to the socket group and log back in: `sudo usermod -aG wheel $USER` (or `sudo`/`adm`, whichever `install` reported) |
| `Service is DISARMED` | `sudo agent-root-runner arm` |
| `Execution quota exhausted` | Re-arm with a larger `--quota` |
| Blocked command (`exit 126`) | The guardrail rule is named in the error; the same rule appears in the audit log |
| Daemon not running | `systemctl status agent-root-runner`, then `journalctl -u agent-root-runner` |

Every decision, including rejections, is appended to the audit log with a UTC
timestamp and the caller's kernel-verified uid.

## Development

```bash
cargo fmt --all -- --check
cargo test --locked --all-targets
```

To run a daemon without root for local testing, use a temporary socket and
`--allow-user-arm`:

```bash
agent-root-runner daemon --socket /tmp/arr.sock --audit-log /tmp/arr.log --allow-user-arm
```

Three integration tests submit commands aimed at protected system paths and are
ignored by default. Run them only on a disposable machine and only when you
intend to authorize those payloads.

## Uninstall

```bash
sudo agent-root-runner uninstall
```

Removes the unit, stops the service, and deletes the installed binary.

## License

MIT
