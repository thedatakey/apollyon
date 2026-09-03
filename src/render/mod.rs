//! Output serializers. Rendering does not mutate reports.

mod json;
mod sarif;
mod text;

pub use json::render_json;
pub use sarif::render_sarif;
pub use text::{render_rules, render_text};

const SCOPE_NOTE: &str = "Findings reflect a fixed set of bounded lexical rules only. Zero findings is not a security guarantee and does not imply the scanned code is safe.";

fn control_properties(report: &crate::report::ScanReport) -> String {
    format!(",\"suppressed_findings\":{},\"disabled_findings\":{},\"new\":{},\"baselined\":{},\"total\":{},\"unselected_files\":{},\"missing_selected_files\":{},\"unsupported_selected_files\":{}", report.suppressed_findings, report.disabled_findings, report.findings.len(), report.baselined_findings, report.total_findings, report.unselected_files, report.missing_selected_files, report.unsupported_selected_files)
}

#[cfg(test)]
mod tests {
    use super::json::json_string;
    use super::*;
    use crate::{
        report::{Finding, ScanReport},
        scanner::{scan_file, MAX_FINDINGS},
    };
    use std::path::Path;
    fn findings(path: &str, source: &str) -> Vec<Finding> {
        scan_file(Path::new(path), path, source, true, MAX_FINDINGS).0
    }

    #[test]
    fn json_escapes_all_ascii_controls() {
        let mut escaped = String::new();
        json_string(&mut escaped, "a\t\0\u{08}\u{0c}\n\r\"\\");
        assert_eq!(escaped, "\"a\\t\\u0000\\b\\f\\n\\r\\\"\\\\\"");
        assert!(!escaped.chars().any(|character| character.is_control()));
    }

    #[test]
    fn machine_outputs_preserve_json_paths_and_encode_sarif_uris() {
        let report = ScanReport {
            root: ".".to_owned(),
            supported_files: 1,
            scanned_files: 1,
            skipped_files: 0,
            skipped_symlinks: 0,
            excluded_files: 0,
            excluded_directories: 0,
            total_bytes: 10,
            complete: true,
            errors: Vec::new(),
            suppressed_errors: 0,
            findings: findings("src/é a#%?.py", "eval(input)"),
            ..Default::default()
        };
        let json = render_json(&report);
        let sarif = render_sarif(&report);
        assert!(json.contains("\"path\":\"src/é a#%?.py\""));
        assert!(sarif.contains("\"version\":\"2.1.0\""));
        assert!(sarif.contains("\"ruleId\":\"APO004\""));
        assert!(sarif.contains("\"uri\":\"src/%C3%A9%20a%23%25%3F.py\""));
    }
}
