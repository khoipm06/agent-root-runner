# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-11-10
### Added
- Desktop notifications when an ARM session has ≤60 seconds remaining.
- JSON output for `agent-root-runner status` (`--json` flag).
- `log` subcommand to view recent audit logs (root‑only).
- Tray menu items to extend an ARM session (+10 min, +15 min) without resetting quota.

### Fixed
- Correct handling of leading `sudo` prefixes; unsupported options now reject.
- Prevent non‑root users from accessing audit logs via RPC.
- Session‑extension logic now preserves quota and start time.
- Fixed race conditions in audit log tail reading.

### Changed
- Updated README examples to reflect new `log` command requirements.
- Refactored `StateMachine::extend` to audit extensions durably.
- Minor refactoring and formatting fixes.

## [1.2.0] - 2026-10-24
### Added
- Initial implementation of desktop system tray indicator.
- Basic arm/disarm RPC API with quota and timeout.
- `status` subcommand with human‑readable output.
- Audit logging of command executions.

### Fixed
- Various guardrail rules for protecting system files.
- Improved error handling for malformed commands.

### Changed
- Adjusted CLI flag parsing for better ergonomics.
