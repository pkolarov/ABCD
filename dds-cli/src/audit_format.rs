//! Audit-event line formatters for `dds-cli audit tail` /
//! `dds-cli audit export`.
//!
//! Closes the Phase B.1 follow-up gap from
//! [`docs/observability/audit-event-schema.md`](../docs/observability/audit-event-schema.md):
//! the canonical `jsonl` shape ships alongside CEF (ArcSight / Splunk)
//! and RFC 5424 syslog so SIEM operators that cannot run a Vector /
//! fluent-bit transform have a turnkey output.
//!
//! Every formatter consumes the same [`AuditLine`] struct so the
//! verification path runs once per row regardless of output format.
//! Severity is derived from `(action, sig_ok)` per
//! [`audit-event-schema.md` §5](../docs/observability/audit-event-schema.md);
//! a `sig_ok=false` line escalates to the highest severity bucket
//! regardless of the action stem so SIEM operators never silently lose
//! a tampering signal.

use serde::Serialize;

/// Output format for `audit tail` / `audit export`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFormat {
    /// One JSON object per line (canonical, default).
    Jsonl,
    /// CEF:0 — single-line ArcSight / Splunk Common Event Format.
    Cef,
    /// RFC 5424 syslog with audit fields in STRUCTURED-DATA.
    Syslog,
}

impl AuditFormat {
    /// Parse a `--format <s>` value. Returns the canonical lower-snake
    /// spelling that the rest of the CLI uses. Unknown values produce a
    /// human-readable error pointing at the supported set so an operator
    /// on an old build does not silently emit nothing.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "jsonl" => Ok(Self::Jsonl),
            "cef" => Ok(Self::Cef),
            "syslog" => Ok(Self::Syslog),
            other => Err(format!(
                "unsupported audit format `{other}` — supported: jsonl, cef, syslog"
            )),
        }
    }
}

/// One audit row, post-decode. The CLI builds this once per entry from
/// the wire response + the locally-verified `sig_ok` flag, then hands
/// it to the per-format renderer.
#[derive(Clone, Debug, Serialize)]
pub struct AuditLine<'a> {
    pub ts: u64,
    pub action: &'a str,
    pub reason: Option<&'a str>,
    pub node_urn: &'a str,
    pub chain_hash: Option<&'a str>,
    pub prev_hash: Option<&'a str>,
    pub sig_ok: bool,
    pub token_cbor_b64: &'a str,
}

/// CEF severity (0-10) per audit-event-schema.md §5. `sig_ok=false`
/// overrides the action-based bucket to 8 (high) so a forwarded SIEM
/// alert always fires on tampering even when the action stem is
/// otherwise informational.
pub fn cef_severity(action: &str, sig_ok: bool) -> u8 {
    if !sig_ok {
        return 8;
    }
    if action.ends_with(".rejected") || action == "apply.failed" {
        return 4;
    }
    if matches!(
        action,
        "revoke" | "burn" | "admin.bootstrap" | "admission.cert.revoked"
    ) {
        return 3;
    }
    2
}

/// RFC 5424 syslog severity per audit-event-schema.md §5. Lower values
/// are more urgent. `sig_ok=false` always promotes to `alert (1)`.
pub fn syslog_severity(action: &str, sig_ok: bool) -> u8 {
    if !sig_ok {
        return 1;
    }
    if action.ends_with(".rejected") || action == "apply.failed" {
        return 4;
    }
    if matches!(
        action,
        "revoke" | "burn" | "admin.bootstrap" | "admission.cert.revoked"
    ) {
        return 5;
    }
    6
}

/// Render the canonical JSONL line. The key set is pinned by
/// `audit-event-schema.md` §2 — additive minor-version changes are
/// allowed but must not remove or rename keys.
pub fn render_jsonl(line: &AuditLine<'_>) -> String {
    let value = serde_json::json!({
        "ts": line.ts,
        "action": line.action,
        "reason": line.reason,
        "node_urn": line.node_urn,
        "chain_hash": line.chain_hash,
        "prev_hash": line.prev_hash,
        "sig_ok": line.sig_ok,
        "token_cbor_b64": line.token_cbor_b64,
    });
    value.to_string()
}

/// Escape a CEF extension value per the CEF specification: `\\`, `\=`,
/// `\|`, `\n` (the four metacharacters that survive the `key=value`
/// pair parser). Empty strings round-trip as empty.
fn cef_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a CEF header field (Device Vendor / Product / Version /
/// Signature / Name). `|` and `\` are reserved by the header
/// delimiter; `\n` would terminate the line. `=` is *not* reserved in
/// the header — it only delimits extension key=value pairs.
fn cef_header_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render a CEF:0 line per audit-event-schema.md §6. The Device
/// Version field is the running `dds-cli` version (workspace-versioned
/// in lockstep with `dds-node`). Values that contain CEF
/// metacharacters are escaped; missing optional fields render as the
/// empty string so the extension key is still present (CEF parsers
/// tolerate empty values).
pub fn render_cef(line: &AuditLine<'_>, dds_version: &str) -> String {
    let severity = cef_severity(line.action, line.sig_ok);
    let action_h = cef_header_escape(line.action);
    let chain = line.chain_hash.unwrap_or("");
    let prev = line.prev_hash.unwrap_or("");
    let reason = line.reason.unwrap_or("");

    format!(
        "CEF:0|Anthropic|DDS|{ver}|{sig}|{name}|{sev}|rt={rt} dvc={dvc} cs1Label=chainHash cs1={cs1} cs2Label=prevHash cs2={cs2} cs3Label=reason cs3={cs3} cs4Label=sigOk cs4={cs4}",
        ver = cef_header_escape(dds_version),
        sig = action_h,
        name = action_h,
        sev = severity,
        rt = line.ts.saturating_mul(1000),
        dvc = cef_escape(line.node_urn),
        cs1 = cef_escape(chain),
        cs2 = cef_escape(prev),
        cs3 = cef_escape(reason),
        cs4 = if line.sig_ok { "true" } else { "false" },
    )
}

/// Format a Unix-seconds timestamp as RFC 3339 / ISO 8601 with `Z`
/// terminator. Inlined to avoid pulling `chrono` into `dds-cli` for
/// one call site.
pub fn format_iso8601_utc(unix_seconds: u64) -> String {
    // Days/months from civil_from_days (Howard Hinnant's algorithm —
    // public domain, used by chrono and date.h).
    let secs_per_day: u64 = 86_400;
    let days = (unix_seconds / secs_per_day) as i64;
    let secs_of_day = (unix_seconds % secs_per_day) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Shift epoch from 1970-01-01 to 0000-03-01 so the calendar math is
    // monotonic across leap-year boundaries.
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year: i64 = if month <= 2 { y + 1 } else { y };

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        year = year,
        month = month,
        day = day,
        hour = hour,
        minute = minute,
        second = second,
    )
}

/// Escape an RFC 5424 STRUCTURED-DATA PARAM-VALUE: `\`, `]`, `"` get a
/// leading backslash. Other characters pass through.
fn syslog_sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

/// Best-effort current hostname. Tries `HOSTNAME` (Unix shells) then
/// `COMPUTERNAME` (Windows) then `/etc/hostname` (Linux), falling back
/// to RFC 5424 NILVALUE `-` when none of those resolve. The audit
/// pipeline tolerates `-` — the signing `node_urn` carries the actual
/// node identity, the syslog hostname is just the forwarder host.
pub fn current_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "-".to_string()
}

/// RFC 5424 facility — `13` is "log audit", which matches the spirit of
/// dds-node's signed audit chain better than `1` (user) or `4`
/// (security/auth).
const SYSLOG_FACILITY_LOG_AUDIT: u8 = 13;

/// Render an RFC 5424 line per audit-event-schema.md §6. The
/// STRUCTURED-DATA SD-ID `dds@32473` uses the IANA Private Enterprise
/// Number `32473` (the example PEN reserved by RFC 5612 for documents
/// that have not yet registered) so an operator can substitute their
/// own PEN with a one-line sed without breaking field parsing — the
/// audit-event-schema doc pins the `dds@<PEN>` convention.
pub fn render_syslog(line: &AuditLine<'_>, hostname: &str) -> String {
    let severity = syslog_severity(line.action, line.sig_ok);
    let priority: u16 = (SYSLOG_FACILITY_LOG_AUDIT as u16) * 8 + (severity as u16);
    let ts = format_iso8601_utc(line.ts);
    let host = if hostname.is_empty() { "-" } else { hostname };
    let chain = line.chain_hash.unwrap_or("");
    let prev = line.prev_hash.unwrap_or("");
    let reason = line.reason.unwrap_or("");

    format!(
        "<{prio}>1 {ts} {host} dds-cli - audit [dds@32473 action=\"{action}\" node_urn=\"{urn}\" chain_hash=\"{chain}\" prev_hash=\"{prev}\" reason=\"{reason}\" sig_ok=\"{sig_ok}\"]",
        prio = priority,
        ts = ts,
        host = host,
        action = syslog_sd_escape(line.action),
        urn = syslog_sd_escape(line.node_urn),
        chain = syslog_sd_escape(chain),
        prev = syslog_sd_escape(prev),
        reason = syslog_sd_escape(reason),
        sig_ok = if line.sig_ok { "true" } else { "false" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<'a>(action: &'a str, sig_ok: bool) -> AuditLine<'a> {
        AuditLine {
            ts: 1_745_625_600,
            action,
            reason: None,
            node_urn: "urn:dds:node:7f3a",
            chain_hash: Some("5b2c"),
            prev_hash: Some("a017"),
            sig_ok,
            token_cbor_b64: "o2dwYXls",
        }
    }

    #[test]
    fn parse_format_round_trips_supported_values() {
        assert_eq!(AuditFormat::parse("jsonl").unwrap(), AuditFormat::Jsonl);
        assert_eq!(AuditFormat::parse("cef").unwrap(), AuditFormat::Cef);
        assert_eq!(AuditFormat::parse("syslog").unwrap(), AuditFormat::Syslog);
        let err = AuditFormat::parse("xml").unwrap_err();
        assert!(err.contains("jsonl, cef, syslog"));
    }

    #[test]
    fn cef_severity_matches_schema_table() {
        // §5 default mapping.
        assert_eq!(cef_severity("attest", true), 2);
        assert_eq!(cef_severity("attest.rejected", true), 4);
        assert_eq!(cef_severity("apply.failed", true), 4);
        assert_eq!(cef_severity("revoke", true), 3);
        assert_eq!(cef_severity("burn", true), 3);
        assert_eq!(cef_severity("admin.bootstrap", true), 3);
        assert_eq!(cef_severity("admission.cert.revoked", true), 3);
        // sig_ok=false override always wins, even on informational stems.
        assert_eq!(cef_severity("attest", false), 8);
        assert_eq!(cef_severity("apply.applied", false), 8);
    }

    #[test]
    fn syslog_severity_matches_schema_table() {
        assert_eq!(syslog_severity("attest", true), 6);
        assert_eq!(syslog_severity("attest.rejected", true), 4);
        assert_eq!(syslog_severity("apply.failed", true), 4);
        assert_eq!(syslog_severity("revoke", true), 5);
        assert_eq!(syslog_severity("burn", true), 5);
        assert_eq!(syslog_severity("admin.bootstrap", true), 5);
        assert_eq!(syslog_severity("admission.cert.revoked", true), 5);
        // alert (1) on tampering.
        assert_eq!(syslog_severity("attest", false), 1);
    }

    #[test]
    fn cef_escape_handles_metacharacters() {
        assert_eq!(cef_escape("a=b|c\\d\nE"), "a\\=b\\|c\\\\d\\nE");
        assert_eq!(cef_escape(""), "");
        assert_eq!(cef_escape("plain"), "plain");
    }

    #[test]
    fn cef_header_escape_does_not_escape_equals() {
        // `=` is reserved in extensions, not headers, so the action stem
        // `attest.rejected` does not need it; ensure we did not
        // over-escape.
        assert_eq!(cef_header_escape("attest.rejected"), "attest.rejected");
        assert_eq!(cef_header_escape("a|b\\c"), "a\\|b\\\\c");
    }

    #[test]
    fn render_cef_emits_required_fields() {
        let l = line("attest.rejected", true);
        let cef = render_cef(&l, "0.1.0");
        assert!(cef.starts_with("CEF:0|Anthropic|DDS|0.1.0|attest.rejected|attest.rejected|4|"));
        assert!(cef.contains("rt=1745625600000"));
        assert!(cef.contains("dvc=urn:dds:node:7f3a"));
        assert!(cef.contains("cs1Label=chainHash cs1=5b2c"));
        assert!(cef.contains("cs2Label=prevHash cs2=a017"));
        assert!(cef.contains("cs4Label=sigOk cs4=true"));
        assert!(!cef.contains('\n'));
    }

    #[test]
    fn render_cef_escapes_pipe_in_node_urn() {
        let mut l = line("attest", true);
        l.node_urn = "urn:dds:node:weird|host";
        let cef = render_cef(&l, "0.1.0");
        assert!(cef.contains("dvc=urn:dds:node:weird\\|host"));
    }

    #[test]
    fn render_cef_escalates_severity_on_tampering() {
        let l = line("attest", false);
        let cef = render_cef(&l, "0.1.0");
        // Sixth field is severity.
        let sev = cef.split('|').nth(6).unwrap();
        assert_eq!(sev, "8");
        assert!(cef.contains("cs4Label=sigOk cs4=false"));
    }

    #[test]
    fn render_syslog_pins_priority_and_structured_data() {
        let l = line("attest.rejected", true);
        let s = render_syslog(&l, "audit-host");
        // facility=13 (log audit), severity=4 (warning) → 13*8+4 = 108.
        assert!(s.starts_with("<108>1 "));
        assert!(s.contains(" audit-host dds-cli - audit "));
        assert!(s.contains("[dds@32473 action=\"attest.rejected\" "));
        assert!(s.contains(" node_urn=\"urn:dds:node:7f3a\" "));
        assert!(s.contains(" chain_hash=\"5b2c\" "));
        assert!(s.contains(" sig_ok=\"true\"]"));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn render_syslog_escalates_priority_on_tampering() {
        let l = line("attest", false);
        let s = render_syslog(&l, "h");
        // facility=13, severity=1 (alert) → 13*8+1 = 105.
        assert!(s.starts_with("<105>1 "));
        assert!(s.contains(" sig_ok=\"false\"]"));
    }

    #[test]
    fn render_syslog_uses_nil_value_when_hostname_empty() {
        let l = line("attest", true);
        let s = render_syslog(&l, "");
        assert!(s.contains(" - dds-cli - audit "));
    }

    #[test]
    fn syslog_sd_escape_handles_quotes_brackets_backslash() {
        assert_eq!(
            syslog_sd_escape("he said \"hi\" [now]\\done"),
            "he said \\\"hi\\\" [now\\]\\\\done"
        );
    }

    #[test]
    fn render_jsonl_keeps_canonical_keys() {
        let l = line("attest", true);
        let s = render_jsonl(&l);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["ts"], 1_745_625_600);
        assert_eq!(v["action"], "attest");
        assert_eq!(v["reason"], serde_json::Value::Null);
        assert_eq!(v["node_urn"], "urn:dds:node:7f3a");
        assert_eq!(v["chain_hash"], "5b2c");
        assert_eq!(v["prev_hash"], "a017");
        assert_eq!(v["sig_ok"], true);
        assert_eq!(v["token_cbor_b64"], "o2dwYXls");
    }

    #[test]
    fn format_iso8601_utc_handles_known_timestamps() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
        // 2025-04-26 00:00:00 UTC.
        assert_eq!(format_iso8601_utc(1_745_625_600), "2025-04-26T00:00:00Z");
        // Leap-year boundary: 2024-02-29 00:00:00 UTC.
        assert_eq!(format_iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        // Round decade tick: 2030-01-01 00:00:00 UTC.
        assert_eq!(format_iso8601_utc(1_893_456_000), "2030-01-01T00:00:00Z");
        // Hour/minute/second resolution at a known wall-clock instant
        // (2025-04-26 12:34:56 UTC = 1745670896).
        assert_eq!(format_iso8601_utc(1_745_670_896), "2025-04-26T12:34:56Z");
    }
}
