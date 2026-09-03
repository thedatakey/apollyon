//! SARIF 2.1.0 serialization and URI encoding.

use super::{json::json_string, SCOPE_NOTE};
use crate::{report::ScanReport, rules::RULES, VERSION};
use std::fmt::Write as _;

fn sarif_uri(path: &str) -> String {
    let mut output = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            output.push(char::from(byte));
        } else {
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

pub fn render_sarif(report: &ScanReport) -> String {
    let mut output = String::from(
        "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Apollyon\",\"semanticVersion\":",
    );
    json_string(&mut output, VERSION);
    output.push_str(",\"informationUri\":\"https://github.com/thedatakey/apollyon\",\"rules\":[");
    for (index, rule) in RULES.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"id\":");
        json_string(&mut output, rule.id);
        output.push_str(",\"name\":");
        json_string(&mut output, rule.name);
        output.push_str(",\"shortDescription\":{\"text\":");
        json_string(&mut output, rule.message);
        output.push_str("},\"properties\":{\"languages\":");
        json_string(&mut output, rule.languages);
        output.push_str("}}");
    }
    output.push_str("],\"properties\":{\"scope\":");
    json_string(&mut output, SCOPE_NOTE);
    output.push_str("}}},\"invocations\":[{\"executionSuccessful\":");
    output.push_str(if report.complete { "true" } else { "false" });
    output.push_str(",\"toolExecutionNotifications\":[");
    for (index, error) in report.errors.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"level\":\"warning\",\"message\":{\"text\":");
        json_string(&mut output, error);
        output.push_str("}}");
    }
    if report.suppressed_errors > 0 {
        if !report.errors.is_empty() {
            output.push(',');
        }
        output.push_str("{\"level\":\"warning\",\"message\":{\"text\":");
        json_string(
            &mut output,
            &format!(
                "{} additional scan error(s) were suppressed",
                report.suppressed_errors
            ),
        );
        output.push_str("}}");
    }
    output.push_str("],\"properties\":{\"scannedFiles\":");
    let _ = write!(
        output,
        "{},\"supportedFiles\":{},\"totalBytes\":{},\"skippedSymlinks\":{},\"excludedFiles\":{},\"excludedDirectories\":{}",
        report.scanned_files,
        report.supported_files,
        report.total_bytes,
        report.skipped_symlinks,
        report.excluded_files,
        report.excluded_directories
    );
    output.push_str(&super::control_properties(report));
    output.push_str("}}],\"results\":[");
    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"ruleId\":");
        json_string(&mut output, finding.rule_id);
        output.push_str(",\"partialFingerprints\":{\"apollyon/v1\":");
        json_string(&mut output, &finding.fingerprint);
        output.push_str("},\"level\":");
        json_string(&mut output, finding.severity.sarif_level());
        output.push_str(",\"message\":{\"text\":");
        json_string(&mut output, finding.message);
        output.push_str("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        json_string(&mut output, &sarif_uri(&finding.path));
        let _ = write!(output, "}},\"region\":{{\"startLine\":{}", finding.line);
        if let Some(snippet) = &finding.snippet {
            output.push_str(",\"snippet\":{\"text\":");
            json_string(&mut output, snippet);
            output.push('}');
        }
        output.push_str("}}}]}");
    }
    output.push_str("]}]}");
    output
}
