use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};
use serde_json::{Map, Value};
use std::{io, path::Path, time::Duration};

struct AuditEntry {
    raw: String,
    parsed: Option<Value>,
    time_short: String,
    event_type: String,
    status_badge: String,
    uid_pid: String,
    command: String,
    severity: Severity,
}

#[derive(Clone, Copy)]
enum Severity {
    Success,
    Danger,
    Warning,
    Info,
    Neutral,
}

impl Severity {
    fn color(self) -> Color {
        match self {
            Severity::Success => Color::Green,
            Severity::Danger => Color::Red,
            Severity::Warning => Color::Yellow,
            Severity::Info => Color::Cyan,
            Severity::Neutral => Color::Gray,
        }
    }
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn parse_entries(lines: Vec<String>) -> Vec<AuditEntry> {
    lines
        .into_iter()
        .rev()
        .map(|raw| {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                let ts = val["timestamp"].as_str().unwrap_or("").to_string();
                let time_short = if ts.len() >= 19 {
                    ts[..19].replace('T', " ")
                } else {
                    ts.clone()
                };
                let event_type = val["event_type"].as_str().unwrap_or("UNKNOWN").to_string();
                let uid = val["uid"]
                    .as_u64()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "-".into());
                let pid = val["pid"]
                    .as_i64()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into());
                let uid_pid = format!("{uid}/{pid}");
                let command = val["command"].as_str().unwrap_or("").to_string();
                let decision = val["decision"].as_str();
                let exit_code = val["exit_code"].as_i64();

                let status_badge = if let Some(code) = exit_code {
                    format!("exit {code}")
                } else if let Some(dec) = decision {
                    dec.to_string()
                } else if event_type == "ARM" {
                    if val["forever"].as_bool() == Some(true) {
                        "forever".into()
                    } else if let Some(d) = val["duration_seconds"].as_u64() {
                        format!("{d}s")
                    } else {
                        "-".into()
                    }
                } else if event_type == "ARM_EXTEND" {
                    let s = val["extension_seconds"].as_u64().unwrap_or(0);
                    let q = val["extension_quota"].as_u64().unwrap_or(0);
                    match (s > 0, q > 0) {
                        (true, true) => format!("+{s}s, +{q}q"),
                        (true, false) => format!("+{s}s"),
                        (false, true) => format!("+{q} cmd"),
                        _ => "extended".into(),
                    }
                } else if let Some(r) = val["reason"].as_str() {
                    r.to_string()
                } else {
                    "-".into()
                };

                let severity = if event_type.contains("BLOCK")
                    || event_type.contains("FAIL")
                    || event_type.contains("REJECT")
                    || decision == Some("BLOCKED")
                    || decision == Some("DENIED")
                    || exit_code.is_some_and(|c| c != 0)
                {
                    Severity::Danger
                } else if event_type == "EXEC_RESULT" && exit_code == Some(0)
                    || decision == Some("ALLOWED")
                {
                    Severity::Success
                } else if event_type == "ARM" || event_type == "ARM_EXTEND" {
                    Severity::Warning
                } else if event_type == "DISARM"
                    || event_type == "DAEMON_START"
                    || event_type == "DAEMON_STOP"
                {
                    Severity::Info
                } else {
                    Severity::Neutral
                };

                AuditEntry {
                    raw,
                    parsed: Some(val),
                    time_short,
                    event_type,
                    status_badge,
                    uid_pid,
                    command,
                    severity,
                }
            } else {
                AuditEntry {
                    raw: raw.clone(),
                    parsed: None,
                    time_short: "-".into(),
                    event_type: "RAW".into(),
                    status_badge: "-".into(),
                    uid_pid: "-".into(),
                    command: raw,
                    severity: Severity::Neutral,
                }
            }
        })
        .collect()
}

fn fetch_logs(socket: &Path, limit: usize) -> Result<Vec<AuditEntry>, String> {
    let mut params = Map::new();
    params.insert("limit".into(), serde_json::json!(limit));
    let resp = crate::rpc(socket, "logs", params, Duration::from_secs(5))?;
    if let Some(err) = resp.get("error") {
        let msg = err["message"].as_str().unwrap_or("Unknown daemon error");
        return Err(msg.to_string());
    }
    let lines = resp["result"]["lines"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(parse_entries(lines))
}

pub fn run_log_viewer(socket: &Path, limit: usize) -> Result<i32, String> {
    let mut entries = fetch_logs(socket, limit)?;
    let mut status_msg = format!("Loaded {} audit entries (newest first)", entries.len());

    enable_raw_mode().map_err(|e| format!("Failed to enable raw mode: {e}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| format!("Failed to enter alternate screen: {e}"))?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("Failed to init terminal: {e}"))?;

    let mut table_state = TableState::default();
    if !entries.is_empty() {
        table_state.select(Some(0));
    }

    loop {
        terminal
            .draw(|f| draw_ui(f, &entries, &mut table_state, &status_msg))
            .map_err(|e| format!("Draw error: {e}"))?;

        if event::poll(Duration::from_millis(250)).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !entries.is_empty() {
                            let i = match table_state.selected() {
                                Some(i) if i + 1 < entries.len() => i + 1,
                                Some(i) => i,
                                None => 0,
                            };
                            table_state.select(Some(i));
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if !entries.is_empty() {
                            let i = match table_state.selected() {
                                Some(i) if i > 0 => i - 1,
                                _ => 0,
                            };
                            table_state.select(Some(i));
                        }
                    }
                    KeyCode::PageDown => {
                        if !entries.is_empty() {
                            let i = table_state.selected().unwrap_or(0);
                            let next = (i + 10).min(entries.len() - 1);
                            table_state.select(Some(next));
                        }
                    }
                    KeyCode::PageUp => {
                        if !entries.is_empty() {
                            let i = table_state.selected().unwrap_or(0);
                            table_state.select(Some(i.saturating_sub(10)));
                        }
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        if !entries.is_empty() {
                            table_state.select(Some(0));
                        }
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        if !entries.is_empty() {
                            table_state.select(Some(entries.len() - 1));
                        }
                    }
                    KeyCode::Char('r') => match fetch_logs(socket, limit) {
                        Ok(new_entries) => {
                            entries = new_entries;
                            status_msg = format!("Refreshed: {} entries", entries.len());
                            if entries.is_empty() {
                                table_state.select(None);
                            } else {
                                let cur = table_state.selected().unwrap_or(0);
                                table_state.select(Some(cur.min(entries.len() - 1)));
                            }
                        }
                        Err(e) => {
                            status_msg = format!("Refresh failed: {e}");
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    Ok(0)
}

fn draw_ui(f: &mut Frame, entries: &[AuditEntry], table_state: &mut TableState, status_msg: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(55),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Agent Root Runner — Audit Inspector ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(status_msg, Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Table
    let header_cells = [
        "Timestamp (UTC)",
        "Event Type",
        "Result",
        "UID/PID",
        "Command",
    ]
    .into_iter()
    .map(|h| {
        Cell::from(h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let table_header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = entries.iter().map(|item| {
        let color = item.severity.color();
        let cmd_preview = if item.command.is_empty() {
            "-".to_string()
        } else {
            item.command.replace('\n', " ")
        };
        Row::new(vec![
            Cell::from(item.time_short.as_str()).style(Style::default().fg(Color::DarkGray)),
            Cell::from(item.event_type.as_str())
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Cell::from(item.status_badge.as_str()).style(Style::default().fg(color)),
            Cell::from(item.uid_pid.as_str()),
            Cell::from(cmd_preview),
        ])
    });

    let widths = [
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(table_header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Audit Events "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[1], table_state);

    // Detail Panel
    let detail_lines = if let Some(idx) = table_state.selected() {
        if let Some(entry) = entries.get(idx) {
            format_entry_details(entry)
        } else {
            vec![Line::from("No event selected.")]
        }
    } else {
        vec![Line::from("No audit events available.")]
    };

    let detail = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Event Details "),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(detail, chunks[2]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " ↑/↓, j/k ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Navigate  "),
        Span::styled(
            " PgUp/PgDn ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Page  "),
        Span::styled(
            " r ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Refresh  "),
        Span::styled(
            " q/Esc ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Quit"),
    ]));
    f.render_widget(footer, chunks[3]);
}

fn format_entry_details(entry: &AuditEntry) -> Vec<Line<'static>> {
    let Some(val) = &entry.parsed else {
        return vec![Line::from(entry.raw.clone())];
    };
    let mut lines = Vec::new();
    let color = entry.severity.color();

    let kv = |label: &str, v: String, val_color: Color| {
        Line::from(vec![
            Span::styled(
                format!("{label:<14}: "),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(v, Style::default().fg(val_color)),
        ])
    };

    lines.push(kv(
        "Event Type",
        format!(
            "{} ({})",
            entry.event_type,
            val["event_id"].as_str().unwrap_or("-")
        ),
        color,
    ));
    lines.push(kv(
        "Timestamp",
        val["timestamp"].as_str().unwrap_or("-").to_string(),
        Color::White,
    ));
    if let Some(sid) = val["session_id"].as_str() {
        lines.push(kv("Session ID", sid.to_string(), Color::Cyan));
    }
    lines.push(kv(
        "Caller",
        format!(
            "uid={} gid={} pid={} comm={}",
            val["uid"]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            val["gid"]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            val["pid"]
                .as_i64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            val["comm"].as_str().unwrap_or("-"),
        ),
        Color::White,
    ));

    if !entry.command.is_empty() {
        lines.push(kv("Command", entry.command.clone(), Color::LightGreen));
    }
    if let Some(dec) = val["decision"].as_str() {
        lines.push(kv("Decision", dec.to_string(), color));
    }
    if let Some(code) = val["exit_code"].as_i64() {
        lines.push(kv("Exit Code", code.to_string(), color));
    }
    if let Some(rule) = val["rule"].as_str().or_else(|| val["reason"].as_str()) {
        lines.push(kv("Reason/Rule", rule.to_string(), color));
    }
    if let Some(ms) = val["duration_ms"].as_u64() {
        lines.push(kv("Duration", format!("{ms} ms"), Color::Gray));
    }
    if let Some(err) = val["error"].as_str() {
        lines.push(kv("Error", err.to_string(), Color::Red));
    }

    lines.push(Line::from(Span::styled(
        "--- Raw Payload ---",
        Style::default().fg(Color::DarkGray),
    )));
    if let Ok(pretty) = serde_json::to_string_pretty(val) {
        for p in pretty.lines() {
            lines.push(Line::from(Span::styled(
                p.to_string(),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entries_highlights_severity_and_reverses_order() {
        let lines = vec![
            r#"{"timestamp":"2026-11-11T05:00:00.000Z","event_type":"ARM","uid":0,"pid":10,"duration_seconds":900}"#.to_string(),
            r#"{"timestamp":"2026-11-11T05:01:00.000Z","event_type":"EXEC_RESULT","uid":1000,"pid":20,"command":"ls -la","exit_code":0}"#.to_string(),
            r#"{"timestamp":"2026-11-11T05:02:00.000Z","event_type":"GUARDRAIL_BLOCKED","uid":1000,"pid":30,"command":"rm -rf /","decision":"BLOCKED"}"#.to_string(),
        ];
        let entries = parse_entries(lines);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event_type, "GUARDRAIL_BLOCKED");
        assert!(matches!(entries[0].severity, Severity::Danger));
        assert_eq!(entries[1].event_type, "EXEC_RESULT");
        assert!(matches!(entries[1].severity, Severity::Success));
        assert_eq!(entries[2].event_type, "ARM");
        assert!(matches!(entries[2].severity, Severity::Warning));
    }
}
