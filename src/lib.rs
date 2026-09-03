//! Apollyon reports bounded review candidates, never proof of whole-program security.
//! The library API is pre-alpha; the existing CLI and findings v1 contract are preserved.

mod ast;
mod baseline;
mod cli;
mod config;
mod display;
mod fingerprint;
mod ignore;
mod lexer;
mod render;
mod report;
mod rules;
mod scanner;
mod selection;
mod suppression;
mod taint;

pub use config::ScanSettings;
pub use render::{render_json, render_rules, render_sarif, render_text};
pub use report::{Confidence, Engine, Finding, ScanReport, TraceStep};
pub use rules::Severity;
pub use scanner::{scan_path, scan_with_settings};

use cli::{emit_output, parse_args, usage, Command, OutputFormat};
use display::safe_terminal;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the CLI with arguments excluding the executable name and return its exit code.
/// Output goes to stdout/stderr or the explicitly requested create-new report file.
pub fn run(args: &[String]) -> i32 {
    let command = match parse_args(args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{}", safe_terminal(&message));
            return 2;
        }
    };
    match command {
        Command::Help => println!("{}", usage()),
        Command::Rules => print!("{}", render_rules()),
        Command::Version => println!("apollyon {VERSION}"),
        Command::Scan(options) => {
            let prepared = prepare_scan(&options);
            let (settings, threshold, existing_baseline) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("{}", safe_terminal(&error));
                    return 2;
                }
            };
            let mut report = scan_with_settings(&options.path, &settings);
            if let Some(path) = &options.controls.write_baseline {
                if report.complete {
                    if let Err(error) = emit_output(&baseline::render(&report), Some(path)) {
                        eprintln!("{}", safe_terminal(&error));
                        return 2;
                    }
                } else {
                    report.add_error(
                        "baseline was not written because the scan is incomplete".into(),
                    );
                }
            }
            if let Some(existing) = existing_baseline {
                baseline::apply(&mut report, &existing);
            }
            let rendered = match options.format {
                OutputFormat::Text => render_text(&report),
                OutputFormat::Json => render_json(&report),
                OutputFormat::Sarif => render_sarif(&report),
            };
            if let Err(message) = emit_output(&rendered, options.output.as_deref()) {
                eprintln!("{}", safe_terminal(&message));
                return 2;
            }
            if !report.complete {
                return 3;
            }
            if threshold.is_some_and(|threshold| {
                report
                    .findings
                    .iter()
                    .any(|finding| finding.severity.rank() >= threshold.rank())
            }) {
                return 1;
            }
        }
    }
    0
}

type PreparedScan = (
    ScanSettings,
    Option<Severity>,
    Option<std::collections::BTreeSet<String>>,
);
fn prepare_scan(options: &cli::ScanOptions) -> Result<PreparedScan, String> {
    let config = config::load(&options.path)?;
    let mut settings = config.settings;
    settings.include_snippets = options.include_snippets;
    if !options.excludes.is_empty() {
        settings.excludes = options.excludes.clone();
    }
    settings.no_gitignore = options.controls.no_gitignore;
    settings.interprocedural = options.controls.interprocedural;
    for id in &options.controls.enable_rules {
        settings.disabled_rules.remove(id);
        if let Some(ids) = &mut settings.enabled_rules {
            ids.insert(id.clone());
        }
    }
    settings
        .disabled_rules
        .extend(options.controls.disable_rules.iter().cloned());
    settings
        .severity
        .extend(options.controls.severities.iter().cloned());
    if let Some(path) = &options.controls.changed_files {
        settings.selected_files = Some(selection::from_file(path)?);
    }
    if let Some(reference) = &options.controls.diff {
        settings.selected_files = Some(selection::from_git(&options.path, reference)?);
    }
    let threshold = if options.controls.fail_on_explicit {
        options.fail_on
    } else {
        config.fail_on
    };
    let existing = options
        .controls
        .baseline
        .as_ref()
        .map(|path| baseline::load(path))
        .transpose()?;
    Ok((settings, threshold, existing))
}
