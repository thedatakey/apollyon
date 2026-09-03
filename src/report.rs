//! Findings and coverage accounting shared by all output formats.

use crate::rules::Severity;
use crate::scanner::MAX_ERRORS;

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub message: &'static str,
    pub path: String,
    pub line: usize,
    pub snippet: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub root: String,
    pub supported_files: usize,
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub skipped_symlinks: usize,
    pub excluded_files: usize,
    pub excluded_directories: usize,
    pub total_bytes: usize,
    pub complete: bool,
    pub errors: Vec<String>,
    pub suppressed_errors: usize,
    pub findings: Vec<Finding>,
    pub total_findings: usize,
    pub suppressed_findings: usize,
    pub disabled_findings: usize,
    pub baselined_findings: usize,
    pub unselected_files: usize,
    pub missing_selected_files: usize,
    pub unsupported_selected_files: usize,
}

impl ScanReport {
    pub(crate) fn add_error(&mut self, message: String) {
        self.complete = false;
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(message);
        } else {
            self.suppressed_errors += 1;
        }
    }
}
