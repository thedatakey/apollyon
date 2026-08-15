//! Apollyon is evidence-first: it reports bounded, reproducible findings and
//! never claims to prove an arbitrary program secure.

use std::{
    env,
    fmt::Write as _,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_DISCOVERED_ENTRIES: usize = 100_000;
const MAX_FINDINGS: usize = 10_000;
const MAX_ERRORS: usize = 1_000;
const MAX_SNIPPET_CHARS: usize = 180;
const EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "h", "hpp", "rs"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Info,
    Medium,
    High,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    rule_id: &'static str,
    severity: Severity,
    message: &'static str,
    path: String,
    line: usize,
    snippet: Option<String>,
}

#[derive(Debug)]
struct ScanReport {
    root: String,
    supported_files: usize,
    scanned_files: usize,
    skipped_files: usize,
    skipped_symlinks: usize,
    total_bytes: usize,
    complete: bool,
    errors: Vec<String>,
    suppressed_errors: usize,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, PartialEq, Eq)]
struct ScanOptions {
    path: PathBuf,
    format: OutputFormat,
    include_snippets: bool,
    fail_on: Option<Severity>,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Scan(ScanOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    CLike,
    Rust,
}

#[derive(Default)]
struct LexState {
    block_comment_depth: usize,
    quote: Option<char>,
    rust_raw_hashes: Option<usize>,
}

fn usage() -> &'static str {
    "Apollyon — bounded, evidence-first source assessment\n\n\
Usage:\n  apollyon scan <path> [--format text|json] [--include-snippets] [--fail-on info|medium|high|never]\n  apollyon --version\n  apollyon --help\n\n\
Exit codes: 0 complete, 1 finding met --fail-on, 2 usage error, 3 incomplete scan."
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("--help" | "-h" | "help") if args.len() == 1 => return Ok(Command::Help),
        Some("--version" | "-V") if args.len() == 1 => return Ok(Command::Version),
        Some("scan") => {}
        _ => return Err(usage().to_owned()),
    }

    let path = args
        .get(1)
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| "scan requires a path\n\n".to_owned() + usage())?;
    let mut options = ScanOptions {
        path: PathBuf::from(path),
        format: OutputFormat::Text,
        include_snippets: false,
        fail_on: None,
    };
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--format requires text or json".to_owned())?;
                options.format = match value.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    _ => return Err("--format must be text or json".to_owned()),
                };
                index += 2;
            }
            "--include-snippets" => {
                options.include_snippets = true;
                index += 1;
            }
            "--no-snippets" => {
                // Kept as a compatibility no-op from the earliest pre-alpha CLI.
                options.include_snippets = false;
                index += 1;
            }
            "--fail-on" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--fail-on requires info, medium, high, or never".to_owned())?;
                options.fail_on = match value.as_str() {
                    "info" => Some(Severity::Info),
                    "medium" => Some(Severity::Medium),
                    "high" => Some(Severity::High),
                    "never" => None,
                    _ => return Err("--fail-on must be info, medium, high, or never".to_owned()),
                };
                index += 2;
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }
    Ok(Command::Scan(options))
}

fn language_for(path: &Path) -> Option<Language> {
    let extension = path.extension()?.to_str()?;
    if extension.eq_ignore_ascii_case("rs") {
        Some(Language::Rust)
    } else if EXTENSIONS
        .iter()
        .filter(|candidate| **candidate != "rs")
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    {
        Some(Language::CLike)
    } else {
        None
    }
}

fn rust_raw_string_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if chars.get(cursor) == Some(&'b') {
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'r') {
        return None;
    }
    cursor += 1;
    let mut hashes = 0;
    while chars.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    (chars.get(cursor) == Some(&'"')).then_some((cursor + 1, hashes))
}

fn is_rust_lifetime(chars: &[char], index: usize) -> bool {
    if chars.get(index) != Some(&'\'') {
        return false;
    }
    let Some(first) = chars.get(index + 1) else {
        return false;
    };
    if !(first.is_alphabetic() || *first == '_') {
        return false;
    }
    let mut cursor = index + 2;
    while chars
        .get(cursor)
        .is_some_and(|character| character.is_alphanumeric() || *character == '_')
    {
        cursor += 1;
    }
    chars.get(cursor) != Some(&'\'')
}

fn sanitize_code_line(line: &str, language: Language, state: &mut LexState) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut output = String::with_capacity(line.len());
    let mut index = 0;
    while index < chars.len() {
        if let Some(hashes) = state.rust_raw_hashes {
            if chars[index] == '"'
                && (0..hashes).all(|offset| chars.get(index + 1 + offset) == Some(&'#'))
            {
                state.rust_raw_hashes = None;
                index += 1 + hashes;
            } else {
                index += 1;
            }
            output.push(' ');
            continue;
        }
        if let Some(quote) = state.quote {
            if chars[index] == '\\' {
                index = (index + 2).min(chars.len());
            } else {
                if chars[index] == quote {
                    state.quote = None;
                }
                index += 1;
            }
            output.push(' ');
            continue;
        }
        if state.block_comment_depth > 0 {
            if language == Language::Rust
                && chars[index] == '/'
                && chars.get(index + 1) == Some(&'*')
            {
                state.block_comment_depth += 1;
                index += 2;
            } else if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                state.block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            output.push(' ');
            continue;
        }
        if chars[index] == '/' && chars.get(index + 1) == Some(&'/') {
            output.push(' ');
            break;
        }
        if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
            state.block_comment_depth = 1;
            output.push(' ');
            index += 2;
            continue;
        }
        if language == Language::Rust {
            if let Some((content_start, hashes)) = rust_raw_string_start(&chars, index) {
                state.rust_raw_hashes = Some(hashes);
                output.push(' ');
                index = content_start;
                continue;
            }
            if is_rust_lifetime(&chars, index) {
                output.push(chars[index]);
                index += 1;
                continue;
            }
        }
        if matches!(chars[index], '"' | '\'') {
            state.quote = Some(chars[index]);
            output.push(' ');
            index += 1;
            continue;
        }
        output.push(chars[index]);
        index += 1;
    }
    output
}

fn is_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

fn contains_token(code: &str, token: &str) -> bool {
    for (start, _) in code.match_indices(token) {
        let end = start + token.len();
        let left_ok = !matches!(
            code[..start].chars().next_back(),
            Some(character) if is_identifier_character(character)
        );
        let right_ok = !matches!(
            code[end..].chars().next(),
            Some(character) if is_identifier_character(character)
        );
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

fn contains_call(code: &str, function: &str) -> bool {
    for (start, _) in code.match_indices(function) {
        let end = start + function.len();
        let left_ok = !matches!(
            code[..start].chars().next_back(),
            Some(character) if is_identifier_character(character)
        );
        let name_ok = !matches!(
            code[end..].chars().next(),
            Some(character) if is_identifier_character(character)
        );
        if left_ok && name_ok && code[end..].trim_start().starts_with('(') {
            return true;
        }
    }
    false
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
        )
}

fn push_terminal_character(output: &mut String, character: char) {
    if is_unsafe_display_character(character) {
        let _ = write!(output, "\\u{:04x}", character as u32);
    } else {
        output.push(character);
    }
}

fn safe_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let mut output = String::new();
    let mut truncated = false;
    for (index, character) in trimmed.chars().enumerate() {
        if index == MAX_SNIPPET_CHARS {
            truncated = true;
            break;
        }
        push_terminal_character(&mut output, character);
    }
    if truncated {
        output.push('…');
    }
    output
}

fn safe_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        push_terminal_character(&mut output, character);
    }
    output
}

fn scan_file(
    path: &Path,
    display_path: &str,
    contents: &str,
    include_snippets: bool,
    finding_budget: usize,
) -> (Vec<Finding>, bool, bool) {
    let Some(language) = language_for(path) else {
        return (Vec::new(), false, true);
    };
    let mut findings = Vec::new();
    let mut lex_state = LexState::default();
    for (index, original_line) in contents.lines().enumerate() {
        let code = sanitize_code_line(original_line, language, &mut lex_state);
        let mut candidates = Vec::with_capacity(2);
        if language == Language::CLike
            && ["gets", "strcpy", "strcat", "sprintf", "vsprintf"]
                .iter()
                .any(|function| contains_call(&code, function))
        {
            candidates.push((
                    "APO001",
                    Severity::High,
                    "Unbounded C string operation may permit memory corruption; use a length-aware API and verify destination bounds.",
                ));
        }
        if language == Language::CLike
            && ["memcpy", "memmove"]
                .iter()
                .any(|function| contains_call(&code, function))
        {
            candidates.push((
                    "APO002",
                    Severity::Info,
                    "Manual memory copy boundary requires review of source length, destination capacity, and overlap assumptions.",
                ));
        }
        if language == Language::Rust && contains_token(&code, "unsafe") {
            candidates.push((
                "APO003",
                Severity::Medium,
                "Rust unsafe code requires a documented safety invariant and focused validation.",
            ));
        }
        for (rule_id, severity, message) in candidates {
            if findings.len() == finding_budget {
                return (findings, true, true);
            }
            findings.push(Finding {
                rule_id,
                severity,
                message,
                path: display_path.to_owned(),
                line: index + 1,
                snippet: include_snippets.then(|| safe_snippet(original_line)),
            });
        }
    }
    let lexically_complete = lex_state.block_comment_depth == 0
        && lex_state.quote.is_none()
        && lex_state.rust_raw_hashes.is_none();
    (findings, false, lexically_complete)
}

fn relative_display(root: &Path, path: &Path) -> String {
    if root.is_file() {
        return path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();
    }
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[derive(Default)]
struct Discovery {
    files: Vec<PathBuf>,
    skipped_symlinks: usize,
    errors: Vec<String>,
    suppressed_errors: usize,
}

impl Discovery {
    fn add_error(&mut self, message: String) {
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(message);
        } else {
            self.suppressed_errors += 1;
        }
    }
}

impl ScanReport {
    fn add_error(&mut self, message: String) {
        self.complete = false;
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(message);
        } else {
            self.suppressed_errors += 1;
        }
    }
}

fn discover_files(root: &Path) -> Discovery {
    let mut discovery = Discovery::default();
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            discovery.add_error(format!("cannot inspect {}: {error}", root.display()));
            return discovery;
        }
    };
    if root_metadata.file_type().is_symlink() {
        discovery.add_error("the scan root must not be a symbolic link".to_owned());
        return discovery;
    }
    if root_metadata.is_file() {
        if language_for(root).is_some() {
            discovery.files.push(root.to_path_buf());
        } else {
            discovery.add_error(
                "the scan root is not a supported C, C++, header, or Rust file".to_owned(),
            );
        }
        return discovery;
    }
    if !root_metadata.is_dir() {
        discovery.add_error("the scan root is neither a regular file nor a directory".to_owned());
        return discovery;
    }

    let mut stack = vec![root.to_path_buf()];
    let mut discovered_entries = 0;
    'walk: while let Some(directory) = stack.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                discovery.add_error(format!(
                    "cannot read {}: {error}",
                    relative_display(root, &directory)
                ));
                continue;
            }
        };
        for entry in entries {
            discovered_entries += 1;
            if discovered_entries > MAX_DISCOVERED_ENTRIES {
                discovery.add_error(format!(
                    "discovery stopped after {MAX_DISCOVERED_ENTRIES} filesystem entries"
                ));
                break 'walk;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    discovery.add_error(format!("directory entry error: {error}"));
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    discovery.add_error(format!(
                        "cannot classify {}: {error}",
                        relative_display(root, &path)
                    ));
                    continue;
                }
            };
            if file_type.is_symlink() {
                discovery.skipped_symlinks += 1;
                continue;
            }
            if file_type.is_dir() {
                if !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| matches!(name, ".git" | "target" | "node_modules"))
                {
                    stack.push(path);
                }
            } else if file_type.is_file() && language_for(&path).is_some() {
                discovery.files.push(path);
            }
        }
    }
    discovery.files.sort();
    discovery
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err("path is no longer a regular non-symlink file".to_owned());
    }
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file() {
        return Err("opened handle is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("file changed between inspection and open".to_owned());
        }
    }
    if opened.len() > MAX_FILE_BYTES {
        return Err(format!("file exceeds {MAX_FILE_BYTES} bytes"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "file exceeded {MAX_FILE_BYTES} bytes while reading"
        ));
    }
    Ok(bytes)
}

fn path_is_within_root(canonical_root: &Path, root_is_file: bool, candidate: &Path) -> bool {
    if root_is_file {
        candidate == canonical_root
    } else {
        candidate.starts_with(canonical_root)
    }
}

fn scan_path(root: &Path, include_snippets: bool) -> ScanReport {
    let discovery = discover_files(root);
    let supported_files = discovery.files.len();
    let canonical_root = fs::canonicalize(root).ok();
    let root_is_file = root.is_file();
    let mut report = ScanReport {
        root: root.display().to_string(),
        supported_files,
        scanned_files: 0,
        skipped_files: 0,
        skipped_symlinks: discovery.skipped_symlinks,
        total_bytes: 0,
        complete: discovery.errors.is_empty() && discovery.suppressed_errors == 0,
        errors: discovery.errors,
        suppressed_errors: discovery.suppressed_errors,
        findings: Vec::new(),
    };

    for path in discovery.files {
        let display_path = relative_display(root, &path);
        let resolved_before = match fs::canonicalize(&path) {
            Ok(resolved) => resolved,
            Err(error) => {
                report.skipped_files += 1;
                report.add_error(format!("cannot resolve {display_path}: {error}"));
                continue;
            }
        };
        if !canonical_root.as_ref().is_some_and(|canonical_root| {
            path_is_within_root(canonical_root, root_is_file, &resolved_before)
        }) {
            report.skipped_files += 1;
            report.add_error(format!(
                "skipped {display_path}: path resolved outside scan root"
            ));
            continue;
        }
        let bytes = match read_bounded_regular_file(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                report.skipped_files += 1;
                report.add_error(format!("cannot read {display_path}: {error}"));
                continue;
            }
        };
        if fs::canonicalize(&path).ok().as_ref() != Some(&resolved_before) {
            report.skipped_files += 1;
            report.add_error(format!("skipped {display_path}: path changed during read"));
            continue;
        }
        if report.total_bytes.saturating_add(bytes.len()) > MAX_TOTAL_BYTES {
            report.add_error(format!(
                "scan stopped at the aggregate input limit of {MAX_TOTAL_BYTES} bytes"
            ));
            break;
        }
        report.total_bytes += bytes.len();
        let contents = match String::from_utf8(bytes) {
            Ok(contents) => contents,
            Err(error) => {
                report.add_error(format!("scanned {display_path} with lossy UTF-8 decoding"));
                String::from_utf8_lossy(error.as_bytes()).into_owned()
            }
        };
        report.scanned_files += 1;
        let remaining = MAX_FINDINGS - report.findings.len();
        let (findings, truncated, lexically_complete) =
            scan_file(&path, &display_path, &contents, include_snippets, remaining);
        report.findings.extend(findings);
        if !lexically_complete {
            report.add_error(format!(
                "lexical scan of {display_path} ended inside a comment or string"
            ));
        }
        if truncated {
            report.add_error(format!(
                "finding output stopped at the limit of {MAX_FINDINGS}"
            ));
            break;
        }
    }
    report
        .findings
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.line.cmp(&right.line)));
    report
}

fn json_string(output: &mut String, value: &str) {
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

fn render_json(report: &ScanReport) -> String {
    let mut output = String::from("{\"schema\":\"apollyon.findings/v1\",\"tool\":{");
    output.push_str("\"name\":\"apollyon\",\"version\":");
    json_string(&mut output, VERSION);
    output.push_str("},\"root\":");
    json_string(&mut output, &report.root);
    let _ = write!(
        output,
        ",\"summary\":{{\"supported_files\":{},\"scanned_files\":{},\"skipped_files\":{},\"skipped_symlinks\":{},\"total_bytes\":{},\"suppressed_errors\":{},\"complete\":{}}},\"errors\":[",
        report.supported_files,
        report.scanned_files,
        report.skipped_files,
        report.skipped_symlinks,
        report.total_bytes,
        report.suppressed_errors,
        report.complete
    );
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

fn render_text(report: &ScanReport) -> String {
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
        output.push_str("Apollyon: no matches for the enabled bounded rules.\n");
    }
    let _ = writeln!(
        output,
        "\n{} finding(s); {}/{} supported file(s) scanned; {} byte(s) read; {} symlink(s) skipped; complete: {}.",
        report.findings.len(),
        report.scanned_files,
        report.supported_files,
        report.total_bytes,
        report.skipped_symlinks,
        report.complete
    );
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

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{}", safe_terminal(&message));
            std::process::exit(2);
        }
    };
    match command {
        Command::Help => println!("{}", usage()),
        Command::Version => println!("apollyon {VERSION}"),
        Command::Scan(options) => {
            let report = scan_path(&options.path, options.include_snippets);
            match options.format {
                OutputFormat::Text => print!("{}", render_text(&report)),
                OutputFormat::Json => println!("{}", render_json(&report)),
            }
            if !report.complete {
                std::process::exit(3);
            }
            if options.fail_on.is_some_and(|threshold| {
                report
                    .findings
                    .iter()
                    .any(|finding| finding.severity.rank() >= threshold.rank())
            }) {
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(path: &str, source: &str) -> Vec<Finding> {
        scan_file(Path::new(path), path, source, true, MAX_FINDINGS).0
    }

    #[test]
    fn finds_spaced_unbounded_copy_with_line_number() {
        let result = findings("example.c", "int main() {\n  strcpy (target, input);\n}");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "APO001");
        assert_eq!(result[0].line, 2);
    }

    #[test]
    fn does_not_confuse_fgets_with_gets() {
        assert!(findings("safe.c", "fgets(buffer, sizeof buffer, stdin);").is_empty());
    }

    #[test]
    fn ignores_comments_and_string_literals() {
        let source = "// strcpy(a, b)\nconst char *s = \"gets(input)\";\n/* sprintf(a, b); */";
        assert!(findings("comments.c", source).is_empty());
    }

    #[test]
    fn scopes_rules_by_language() {
        assert!(findings("safe.rs", "fn strcpy() {}").is_empty());
        assert!(findings("safe.c", "void unsafe(void) {}").is_empty());
        assert_eq!(findings("unsafe.rs", "unsafe fn boundary() {}").len(), 1);
    }

    #[test]
    fn handles_rust_lifetimes_nested_comments_and_strings() {
        assert_eq!(
            findings("lifetime.rs", "fn boundary<'a>() { unsafe { call(); } }").len(),
            1
        );
        assert!(findings("comments.rs", "/* outer /* inner */ unsafe { call(); } */").is_empty());
        assert!(findings(
            "strings.rs",
            "let first = r#\"\nunsafe { call(); }\n\"#;\nlet second = \"\nunsafe {}\n\";"
        )
        .is_empty());
    }

    #[test]
    fn emits_each_matching_rule_on_the_same_line() {
        let result = findings("mixed.c", "strcpy(a, b); memcpy(c, d, n);");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].rule_id, "APO001");
        assert_eq!(result[1].rule_id, "APO002");
    }

    #[test]
    fn enforces_finding_budget_before_allocation() {
        let source = "strcpy(a, b);\n".repeat(100);
        let (result, truncated, _) = scan_file(Path::new("many.c"), "many.c", &source, false, 2);
        assert_eq!(result.len(), 2);
        assert!(truncated);
    }

    #[test]
    fn reports_incomplete_lexical_state() {
        let (_, _, complete) = scan_file(
            Path::new("broken.rs"),
            "broken.rs",
            "let value = r#\"unterminated",
            false,
            MAX_FINDINGS,
        );
        assert!(!complete);
    }

    #[test]
    fn json_escapes_all_ascii_controls() {
        let mut escaped = String::new();
        json_string(&mut escaped, "a\t\0\u{08}\u{0c}\n\r\"\\");
        assert_eq!(escaped, "\"a\\t\\u0000\\b\\f\\n\\r\\\"\\\\\"");
        assert!(!escaped.chars().any(|character| character.is_control()));
    }

    #[test]
    fn no_snippets_removes_source_from_findings() {
        let result = scan_file(
            Path::new("example.c"),
            "example.c",
            "strcpy(a, b);",
            false,
            MAX_FINDINGS,
        )
        .0;
        assert_eq!(result[0].snippet, None);
    }

    #[test]
    fn rejects_unknown_and_incomplete_options() {
        assert!(parse_args(&["scan".into(), ".".into(), "--typo".into()]).is_err());
        assert!(parse_args(&["scan".into(), ".".into(), "--format".into()]).is_err());
        assert!(parse_args(&["scan".into()]).is_err());
    }

    #[test]
    fn scan_defaults_to_redacted_snippets() {
        let command = parse_args(&["scan".into(), "src".into()]).unwrap();
        let Command::Scan(options) = command else {
            panic!("expected scan command");
        };
        assert!(!options.include_snippets);
    }

    #[test]
    fn parses_ci_threshold() {
        let command = parse_args(&[
            "scan".into(),
            "src".into(),
            "--format".into(),
            "json".into(),
            "--include-snippets".into(),
            "--fail-on".into(),
            "high".into(),
        ])
        .unwrap();
        assert_eq!(
            command,
            Command::Scan(ScanOptions {
                path: PathBuf::from("src"),
                format: OutputFormat::Json,
                include_snippets: true,
                fail_on: Some(Severity::High),
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovery_skips_symbolic_links() {
        use std::os::unix::fs::symlink;

        let fixture = env::temp_dir().join(format!("apollyon-test-{}", std::process::id()));
        let source = fixture.join("source.c");
        let link = fixture.join("outside.c");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();
        fs::write(&source, "strcpy(a, b);").unwrap();
        symlink(&source, &link).unwrap();

        let discovery = discover_files(&fixture);
        assert_eq!(discovery.files, vec![source]);
        assert_eq!(discovery.skipped_symlinks, 1);
        assert!(discovery.errors.is_empty());

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_final_symbolic_link() {
        use std::os::unix::fs::symlink;

        let fixture =
            env::temp_dir().join(format!("apollyon-reader-link-test-{}", std::process::id()));
        let source = fixture.join("source.c");
        let link = fixture.join("link.c");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();
        fs::write(&source, "strcpy(a, b);").unwrap();
        symlink(&source, &link).unwrap();

        assert!(read_bounded_regular_file(&link).is_err());

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn bounded_reader_rejects_oversize_file() {
        let fixture =
            env::temp_dir().join(format!("apollyon-reader-size-test-{}", std::process::id()));
        let source = fixture.join("large.c");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();
        let file = fs::File::create(&source).unwrap();
        file.set_len(MAX_FILE_BYTES + 1).unwrap();

        assert!(read_bounded_regular_file(&source).is_err());

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn terminal_output_escapes_bidi_controls() {
        assert_eq!(safe_terminal("safe\u{202e}txt"), "safe\\u202etxt");
    }
}
