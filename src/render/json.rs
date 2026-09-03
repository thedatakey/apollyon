//! Findings v1 JSON serialization.

use super::SCOPE_NOTE;
use crate::{report::ScanReport, VERSION};
use std::fmt::Write as _;

pub(super) fn json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control <= '\u{1f}' => {
                let _ = write!(output, "\\u{:04x}", control as u32);
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

pub fn render_json(report: &ScanReport) -> String {
    let mut output = String::from("{\"schema\":\"apollyon.findings/v1\",\"tool\":{");
    output.push_str("\"name\":\"apollyon\",\"version\":");
    json_string(&mut output, VERSION);
    output.push_str("},\"scope\":");
    json_string(&mut output, SCOPE_NOTE);
    output.push_str(",\"root\":");
    json_string(&mut output, &report.root);
    let _ = write!(
        output,
        ",\"summary\":{{\"supported_files\":{},\"scanned_files\":{},\"skipped_files\":{},\"skipped_symlinks\":{},\"excluded_files\":{},\"excluded_directories\":{},\"total_bytes\":{},\"suppressed_errors\":{},\"complete\":{}",
        report.supported_files,
        report.scanned_files,
        report.skipped_files,
        report.skipped_symlinks,
        report.excluded_files,
        report.excluded_directories,
        report.total_bytes,
        report.suppressed_errors,
        report.complete
    );
    output.push_str(&super::control_properties(report));
    output.push_str("},\"errors\":[");
    for (index, error) in report.errors.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        json_string(&mut output, error);
    }
    output.push_str("],\"findings\":[");
    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"rule_id\":");
        json_string(&mut output, finding.rule_id);
        output.push_str(",\"severity\":");
        json_string(&mut output, finding.severity.as_str());
        output.push_str(",\"message\":");
        json_string(&mut output, finding.message);
        output.push_str(",\"fingerprint\":");
        json_string(&mut output, &finding.fingerprint);
        output.push_str(",\"path\":");
        json_string(&mut output, &finding.path);
        let _ = write!(output, ",\"line\":{},\"snippet\":", finding.line);
        if let Some(snippet) = &finding.snippet {
            json_string(&mut output, snippet);
        } else {
            output.push_str("null");
        }
        output.push('}');
    }
    output.push_str("]}");
    output
}
