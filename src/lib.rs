//! Apollyon reports bounded review candidates, never proof of whole-program security.
//! The library API is pre-alpha; the existing CLI and findings v1 contract are preserved.

mod cli;
mod display;
mod lexer;
mod render;
mod report;
mod rules;
mod scanner;

pub use render::{render_json, render_rules, render_sarif, render_text};
pub use report::{Finding, ScanReport};
pub use rules::Severity;
pub use scanner::scan_path;

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
            let report = scan_path(&options.path, options.include_snippets, &options.excludes);
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
            if options.fail_on.is_some_and(|threshold| {
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
