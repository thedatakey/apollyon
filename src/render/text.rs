//! Human-readable findings and rule listing.

use crate::{display::safe_terminal, report::ScanReport, rules::RULES};
use std::fmt::Write as _;

pub fn render_rules() -> String {
    let mut output = String::from("Supported source families:\n");
    output.push_str(
        "  C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, PHP, Python, Ruby, Rust, Swift\n\nBounded rules:\n",
    );
    for rule in RULES {
        let _ = writeln!(
            output,
            "  {} [{}] {}\n    Languages: {}",
            rule.id,
            rule.severity.as_str(),
            rule.message,
            rule.languages
        );
    }
    output
}

pub fn render_text(report: &ScanReport) -> String {
    let mut output = String::new();
    for finding in &report.findings {
        let _ = writeln!(
            output,
            "[{}] {} {}:{}\n  {}",
            finding.severity.as_str().to_uppercase(),
            finding.rule_id,
            safe_terminal(&finding.path),
            finding.line,
            finding.message
        );
        if let Some(snippet) = &finding.snippet {
            let _ = writeln!(output, "  evidence: {snippet}");
        }
    }
    if report.findings.is_empty() {
        if report.complete {
            output.push_str("Apollyon: no matches for the enabled bounded rules.\n");
        } else {
            output.push_str(
                "Apollyon: scan incomplete; no matches in the files successfully scanned.\n",
            );
        }
    }
    let _ = writeln!(
        output,
        "\n{} finding(s); {}/{} supported file(s) scanned; {} byte(s) read; {} symlink(s) skipped; {} file(s) and {} directories excluded; complete: {}.",
        report.findings.len(),
        report.scanned_files,
        report.supported_files,
        report.total_bytes,
        report.skipped_symlinks,
        report.excluded_files,
        report.excluded_directories,
        report.complete
    );
    let _ = writeln!(output, "{} new; {} baselined; {} suppressed; {} disabled; {} total candidate(s); {} unselected file(s); {} missing selected path(s); {} unsupported selected path(s).", report.findings.len(), report.baselined_findings, report.suppressed_findings, report.disabled_findings, report.total_findings, report.unselected_files, report.missing_selected_files, report.unsupported_selected_files);
    for error in &report.errors {
        let _ = writeln!(output, "warning: {}", safe_terminal(error));
    }
    if report.suppressed_errors > 0 {
        let _ = writeln!(
            output,
            "warning: {} additional error(s) suppressed",
            report.suppressed_errors
        );
    }
    output
}
