# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-11-10
### Added
- Desktop notifications via `notify-send` when an ARM session has ≤60 seconds remaining.
- JSON output for `agent-root-runner status` (`--json` flag) for programmatic monitoring.
- `log` subcommand to view recent daemon audit logs over Unix domain socket RPC (root-only).
- Tray menu items to extend an active ARM session (+10 min, +15 min) without resetting quota.

### Fixed
- Correct handling of leading `sudo` prefixes; unsupported options reject instead of forwarding to bash.
- Prevent non-root peers from accessing audit logs via `logs` RPC.
- Session-extension logic now preserves quota and start timestamps.
- Mutex synchronization on audit log tail reading to prevent race conditions.

### Changed
- Updated README examples to reflect root requirement for `log` command.
- Refactored `StateMachine::extend` to audit extensions durably with fail-closed safety.

## [1.2.0] - 2026-10-24
### Added
- Complete rewrite and architectural transformation from Python to native Rust.
- Single standalone native ELF binary (~4 MB) with zero runtime dependencies.
- Native Unix domain socket server with atomic state transitions and kernel-verified peer credentials (`SO_PEERCRED`).
- Rust AST guardrail engine inspecting shell syntax trees to block system-destabilizing operations.
- Append-only audit logger with fail-closed disk synchronization before any command spawn.

## [1.0.2] - 2026-10-19
### Fixed
- Stripped PyInstaller extraction directories from `LD_LIBRARY_PATH` before spawning host utilities (such as `systemctl`).
- Resolved host shared-library collisions during frozen CLI installations.

### Added
- E2E test suites migrated to exercise the real running daemon.
- Guardrail regression test coverage across all policy families (270 unit + 59 E2E tests).

## [1.0.1] - 2026-10-19
### Added
- Manifest-based atomic installer deploying to `/usr/local/lib` with `bin_t` launchers and active unit verification.
- Pass-through of child exit status in `exec` command.

### Fixed
- Daemon now clamps requested execution timeouts to the remaining ARM session window.
- In-flight commands are terminated with `SIGKILL` on manual or timeout disarm.
- Refuse `--allow-user-arm` when running as root.
- MCP protocol conformance: proper JSON-RPC error mapping (`-32600`, `-32602`) and silent notification handling.
- Guardrail AST unwrapping for `command`, `builtin`, `nocorrect`, and `!`.

## [1.0.0] - 2026-10-18
### Added
- Initial production-ready release of Agent Root Runner (Python edition).
- Privileged daemon running with root permissions, authenticating local peers using kernel `SO_PEERCRED`.
- Human-in-the-loop arming with bounded duration (`--duration`) and quota (`--quota`).
- Semantic OS guardrails blocking destructive disk operations, partition wipes, and auth tampering.
- Stdio Model Context Protocol (MCP) server for integration with AI coding agents.
- Append-only fail-closed audit log.
