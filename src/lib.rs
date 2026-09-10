//! Apollyon reports bounded review candidates, never proof of whole-program security.
//! The library API is pre-alpha; the CLI emits the documented findings v2 contract.

mod ast;
mod baseline;
mod case;
mod cli;
mod config;
mod dependencies;
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
mod workflow;

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
            if let Some(prefix) = message.strip_suffix(usage()) {
                eprint!("{}", safe_terminal(prefix.trim_end()));
                if !prefix.is_empty() {
                    eprintln!("\n");
                }
                eprintln!("{}", usage());
            } else {
                eprintln!("{}", safe_terminal(&message));
            }
            return 2;
        }
    };
    match command {
        Command::Dependencies(root, db) => {
            return match dependencies::run(&root, db.as_deref()) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", safe_terminal(&e));
                    2
                }
            }
        }
        Command::Init(path, action, hook) => {
            return match workflow::init(&path, action, hook) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{}", safe_terminal(&e));
                    2
                }
            }
        }
        Command::Explain(id) => print!("{}", workflow::explain(&id)),
        Command::Help => println!("{}", usage()),
        Command::Rules => print!("{}", render_rules()),
        Command::Version => println!("apollyon {VERSION}"),
        Command::Scan(options) => {
            if options.controls.watch {
                let mut once = Vec::new();
                let mut skip = false;
                for arg in args {
                    if skip {
                        skip = false;
                        continue;
                    }
                    if arg == "--watch" {
                        continue;
                    }
                    if arg == "--watch-count" {
                        skip = true;
                        continue;
                    }
                    once.push(arg.clone());
                }
                let mut last = 0;
                for iteration in 0..options.controls.watch_count.unwrap_or(usize::MAX) {
                    if iteration > 0 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    last = run(&once);
                    if last == 2 {
                        break;
                    }
                }
                return last;
            }
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
            if let Some(directory) = &options.controls.cases_dir {
                if !report.complete {
                    report.add_error(
                        "case records were not written because the scan is incomplete".into(),
                    );
                } else {
                    let case_options = case::CaseOptions {
                        directory: directory.clone(),
                        repository: options
                            .controls
                            .repository
                            .clone()
                            .unwrap_or_else(|| "local".into()),
                        revision: options
                            .controls
                            .revision
                            .clone()
                            .unwrap_or_else(|| "working-tree".into()),
                    };
                    if let Err(error) = case::write_candidates(&mut report, &case_options) {
                        eprintln!("{}", safe_terminal(&error));
                        return 2;
                    }
                }
            }
            let threshold_met = report.findings.iter().any(|finding| {
                (!options.controls.production_only
                    || workflow::classification(&finding.path) == "production")
                    && settings
                        .threshold(&finding.path, threshold)
                        .is_some_and(|t| finding.severity.rank() >= t.rank())
            });
            if options.controls.fix || options.controls.fix_dry_run {
                if !report.complete {
                    eprintln!("fixes require a complete scan");
                    return 3;
                }
                return match workflow::fixes(&options.path, &report, options.controls.fix) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("{}", safe_terminal(&e));
                        2
                    }
                };
            }
            let unfiltered = report.findings.len();
            report.findings.retain(|f| {
                settings
                    .min_severity
                    .is_none_or(|min| f.severity.rank() >= min.rank())
                    && (!options.controls.production_only
                        || workflow::classification(&f.path) == "production")
            });
            report.filtered_findings = unfiltered - report.findings.len();
            let rendered = match options.format {
                OutputFormat::Text => workflow::text(
                    &report,
                    options.controls.quiet,
                    options.controls.color.as_deref(),
                ),
                OutputFormat::Json => render_json(&report),
                OutputFormat::Sarif => render_sarif(&report),
                OutputFormat::Markdown => workflow::markdown(&report),
                OutputFormat::Github => workflow::annotations(&report, false),
                OutputFormat::Gitlab => workflow::annotations(&report, true),
            };
            if let Err(message) = emit_output(&rendered, options.output.as_deref()) {
                eprintln!("{}", safe_terminal(&message));
                return 2;
            }
            if !report.complete {
                return 3;
            }
            if threshold_met {
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
    if let Some(ids) = &options.controls.only {
        settings.enabled_rules = Some(ids.iter().cloned().collect());
    }
    if options.controls.min_severity.is_some() {
        settings.min_severity = options.controls.min_severity;
    }
    settings.no_default_ignores |= options.controls.no_default_ignores;
    for (name, value) in &options.controls.numbers {
        match name.as_str() {
            "jobs" => settings.jobs = *value,
            "max_findings" => settings.max_findings = *value,
            "max_file_bytes" => settings.max_file_bytes = *value as u64,
            "max_total_bytes" => settings.max_total_bytes = *value,
            "max_entries" => settings.max_entries = *value,
            _ => unreachable!(),
        }
    }
    settings.validate()?;
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
    let base = if options.path.is_file() {
        options.path.parent().unwrap_or(std::path::Path::new("."))
    } else {
        &options.path
    };
    let automatic = base.join("apollyon-baseline.json");
    let baseline_path = options.controls.baseline.as_ref().or_else(|| {
        (!options.controls.no_auto_baseline && std::fs::symlink_metadata(&automatic).is_ok())
            .then_some(&automatic)
    });
    let existing = baseline_path.map(|path| baseline::load(path)).transpose()?;
    Ok((settings, threshold, existing))
}
