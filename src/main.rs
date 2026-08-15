//! Apollyon is evidence-first: it reports bounded, reproducible findings and
//! never claims to prove an arbitrary program secure.

use std::{
    env,
    fmt::Write as _,
    fs,
    io::{ErrorKind, Read, Write as _},
    path::{Component, Path, PathBuf},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_DISCOVERED_ENTRIES: usize = 100_000;
const MAX_FINDINGS: usize = 10_000;
const MAX_ERRORS: usize = 1_000;
const MAX_SNIPPET_CHARS: usize = 180;
const CSHARP_FORMATTER_PROXIMITY_LINES: usize = 20;
const SCOPE_NOTE: &str = "Findings reflect a fixed set of bounded lexical rules only. Zero findings is not a security guarantee and does not imply the scanned code is safe.";
const DEFAULT_IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".tox",
    ".venv",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
];

#[derive(Clone, Copy)]
struct RuleInfo {
    id: &'static str,
    name: &'static str,
    severity: Severity,
    message: &'static str,
    languages: &'static str,
}

const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "APO001",
        name: "unbounded-c-string-operation",
        severity: Severity::High,
        message: "Unbounded C string operation may permit memory corruption; use a length-aware API and verify destination bounds.",
        languages: "C and C++",
    },
    RuleInfo {
        id: "APO002",
        name: "manual-memory-copy-boundary",
        severity: Severity::Info,
        message: "Manual memory copy boundary requires review of source length, destination capacity, and overlap assumptions.",
        languages: "C and C++",
    },
    RuleInfo {
        id: "APO003",
        name: "rust-unsafe-boundary",
        severity: Severity::Medium,
        message: "Rust unsafe code requires a documented safety invariant and focused validation.",
        languages: "Rust",
    },
    RuleInfo {
        id: "APO004",
        name: "dynamic-code-execution",
        severity: Severity::High,
        message: "Dynamic code execution requires review of whether code or input can be influenced by an attacker.",
        languages: "JavaScript, TypeScript, Python, PHP, and Ruby",
    },
    RuleInfo {
        id: "APO005",
        name: "operating-system-command-boundary",
        severity: Severity::Medium,
        message: "Operating-system command execution requires review of argument separation, shell use, and untrusted input.",
        languages: "C, C++, C#, Go, Java, Kotlin, JavaScript, TypeScript, PHP, Python, Ruby, Rust, and Swift",
    },
    RuleInfo {
        id: "APO006",
        name: "unsafe-deserialization-boundary",
        severity: Severity::High,
        message: "Deserialization API may construct attacker-controlled objects; require a safe format, trusted input, or an explicit allowlist.",
        languages: "Python, Java, Kotlin, C#, PHP, and Ruby",
    },
];

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

    fn sarif_level(self) -> &'static str {
        match self {
            Self::Info => "note",
            Self::Medium => "warning",
            Self::High => "error",
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
    excluded_files: usize,
    excluded_directories: usize,
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
    Sarif,
}

#[derive(Debug, PartialEq, Eq)]
struct ScanOptions {
    path: PathBuf,
    format: OutputFormat,
    include_snippets: bool,
    fail_on: Option<Severity>,
    output: Option<PathBuf>,
    excludes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Rules,
    Version,
    Scan(ScanOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    CFamily,
    CSharp,
    Go,
    JavaScript,
    Jvm,
    Php,
    Python,
    Ruby,
    Rust,
    Swift,
}

#[derive(Default)]
struct LexState {
    block_comment_depth: usize,
    quote: Option<char>,
    csharp_verbatim_quote: bool,
    triple_quote: Option<char>,
    rust_raw_hashes: Option<usize>,
    slash_regex_unterminated: bool,
}

fn usage() -> &'static str {
    "Apollyon — bounded, evidence-first source assessment\n\n\
Usage:\n  apollyon scan <path> [--format text|json|sarif] [--output <file>] [--exclude <path>]...\n                       [--include-snippets] [--fail-on info|medium|high|never]\n  apollyon rules\n  apollyon --version\n  apollyon --help\n\n\
Exit codes: 0 complete, 1 finding met --fail-on, 2 invocation/output error, 3 incomplete scan."
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("--help" | "-h" | "help") if args.len() == 1 => return Ok(Command::Help),
        Some("rules") if args.len() == 1 => return Ok(Command::Rules),
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
        output: None,
        excludes: Vec::new(),
    };
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--format requires text, json, or sarif".to_owned())?;
                options.format = match value.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    "sarif" => OutputFormat::Sarif,
                    _ => return Err("--format must be text, json, or sarif".to_owned()),
                };
                index += 2;
            }
            "--output" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--output requires a file path".to_owned())?;
                options.output = Some(PathBuf::from(value));
                index += 2;
            }
            "--exclude" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--exclude requires a relative path or directory name".to_owned()
                })?;
                options.excludes.push(normalize_exclude(value)?);
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

fn normalize_exclude(value: &str) -> Result<String, String> {
    let normalized_separators = value.replace('\\', "/");
    let mut parts = Vec::new();
    for component in Path::new(&normalized_separators).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("--exclude must stay within the scan root".to_owned());
            }
        }
    }
    if parts.is_empty() {
        return Err("--exclude must not be empty".to_owned());
    }
    Ok(parts.join("/"))
}

fn language_for(path: &Path) -> Option<Language> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" => Some(Language::CFamily),
        "cs" => Some(Language::CSharp),
        "go" => Some(Language::Go),
        "java" | "kt" | "kts" => Some(Language::Jvm),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Some(Language::JavaScript),
        "php" | "phtml" => Some(Language::Php),
        "py" | "pyw" => Some(Language::Python),
        "rb" | "rake" => Some(Language::Ruby),
        "rs" => Some(Language::Rust),
        "swift" => Some(Language::Swift),
        _ => None,
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

fn uses_slash_comments(language: Language) -> bool {
    !matches!(language, Language::Python | Language::Ruby)
}

fn uses_hash_comments(language: Language) -> bool {
    matches!(language, Language::Php | Language::Python | Language::Ruby)
}

fn supports_nested_block_comments(language: Language) -> bool {
    matches!(language, Language::Rust | Language::Swift)
}

fn supports_backtick_strings(language: Language) -> bool {
    matches!(language, Language::Go | Language::JavaScript)
}

fn supports_triple_quotes(language: Language) -> bool {
    matches!(
        language,
        Language::CSharp | Language::Jvm | Language::Python | Language::Swift
    )
}

fn starts_triple_quote(chars: &[char], index: usize, quote: char) -> bool {
    chars.get(index) == Some(&quote)
        && chars.get(index + 1) == Some(&quote)
        && chars.get(index + 2) == Some(&quote)
}

fn slash_regex_can_start(code_before_slash: &str) -> bool {
    let trimmed = code_before_slash.trim_end();
    let Some(last) = trimmed.chars().next_back() else {
        return true;
    };
    if matches!(
        last,
        '(' | '['
            | '{'
            | ':'
            | ','
            | ';'
            | '='
            | '!'
            | '?'
            | '&'
            | '|'
            | '+'
            | '-'
            | '*'
            | '%'
            | '^'
            | '~'
            | '<'
            | '>'
    ) {
        return true;
    }
    [
        "await", "case", "delete", "in", "instanceof", "new", "of", "return", "throw",
        "typeof", "void", "yield",
    ]
    .iter()
    .any(|keyword| {
        trimmed.strip_suffix(keyword).is_some_and(|prefix| {
            !matches!(prefix.chars().next_back(), Some(character) if is_identifier_character(character))
        })
    })
}

fn slash_regex_end(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    let mut in_character_class = false;
    while index < chars.len() {
        match chars[index] {
            '\\' => index = (index + 2).min(chars.len()),
            '[' if !in_character_class => {
                in_character_class = true;
                index += 1;
            }
            ']' if in_character_class => {
                in_character_class = false;
                index += 1;
            }
            '/' if !in_character_class => {
                index += 1;
                while chars
                    .get(index)
                    .is_some_and(|character| character.is_alphabetic())
                {
                    index += 1;
                }
                return Some(index);
            }
            _ => index += 1,
        }
    }
    None
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
        if let Some(quote) = state.triple_quote {
            if starts_triple_quote(&chars, index, quote) {
                state.triple_quote = None;
                index += 3;
            } else if chars[index] == '\\' {
                index = (index + 2).min(chars.len());
            } else {
                index += 1;
            }
            output.push(' ');
            continue;
        }
        if let Some(quote) = state.quote {
            if state.csharp_verbatim_quote
                && chars[index] == quote
                && chars.get(index + 1) == Some(&quote)
            {
                index += 2;
            } else if state.csharp_verbatim_quote && chars[index] == quote {
                state.quote = None;
                state.csharp_verbatim_quote = false;
                index += 1;
            } else if chars[index] == '\\'
                && !(language == Language::Go && quote == '`')
                && !state.csharp_verbatim_quote
            {
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
            if supports_nested_block_comments(language)
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
        if uses_hash_comments(language) && chars[index] == '#' {
            output.push(' ');
            break;
        }
        if uses_slash_comments(language)
            && chars[index] == '/'
            && chars.get(index + 1) == Some(&'/')
        {
            output.push(' ');
            break;
        }
        if uses_slash_comments(language)
            && chars[index] == '/'
            && chars.get(index + 1) == Some(&'*')
        {
            state.block_comment_depth = 1;
            output.push(' ');
            index += 2;
            continue;
        }
        if matches!(language, Language::JavaScript | Language::Ruby)
            && chars[index] == '/'
            && chars.get(index + 1) != Some(&'=')
            && slash_regex_can_start(&output)
        {
            if let Some(end) = slash_regex_end(&chars, index) {
                index = end;
            } else {
                state.slash_regex_unterminated = true;
                index = chars.len();
            }
            output.push(' ');
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
        if supports_triple_quotes(language)
            && (chars[index] == '"' || (language == Language::Python && chars[index] == '\''))
            && starts_triple_quote(&chars, index, chars[index])
        {
            state.triple_quote = Some(chars[index]);
            output.push(' ');
            index += 3;
            continue;
        }
        if matches!(chars[index], '"' | '\'')
            || (chars[index] == '`' && supports_backtick_strings(language))
        {
            let previous = index
                .checked_sub(1)
                .and_then(|position| chars.get(position));
            let two_before = index
                .checked_sub(2)
                .and_then(|position| chars.get(position));
            state.csharp_verbatim_quote = language == Language::CSharp
                && chars[index] == '"'
                && (previous == Some(&'@') || (two_before == Some(&'@') && previous == Some(&'$')));
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

fn contains_any_call(code: &str, functions: &[&str]) -> bool {
    functions
        .iter()
        .any(|function| contains_call(code, function))
}

fn contains_ruby_command(code: &str, name: &str) -> bool {
    for (start, _) in code.match_indices(name) {
        let end = start + name.len();
        let previous_character = code[..start].chars().next_back();
        let left_ok = !matches!(
            previous_character,
            Some(character) if is_identifier_character(character)
        );
        let right_ok = !matches!(
            code[end..].chars().next(),
            Some(character) if is_identifier_character(character)
        );
        if !left_ok || !right_ok {
            continue;
        }

        // A Ruby symbol literal (`:name`) has no whitespace between the
        // colon and the name; a hash-literal key (`name: value`) always
        // does. Checking the immediately preceding character (rather than
        // trimming whitespace first) tells the two apart, so a dangerous
        // call used as a hash value (e.g. `{ run: spawn(cmd) }`) is still
        // reported instead of being mistaken for a symbol reference.
        let statement_prefix = code[..start]
            .rsplit_once(';')
            .map_or(&code[..start], |(_, suffix)| suffix)
            .trim_start();
        if statement_prefix.starts_with("def ") || previous_character == Some(':') {
            continue;
        }

        let after = &code[end..];
        if after.starts_with('(') {
            return true;
        }
        let argument = after.trim_start();
        if argument.len() < after.len()
            && argument.chars().next().is_some_and(|character| {
                !matches!(character, '=' | ':' | ';' | ',' | ')' | ']' | '}')
            })
        {
            return true;
        }
    }
    false
}

fn contains_any_ruby_command(code: &str, names: &[&str]) -> bool {
    names.iter().any(|name| contains_ruby_command(code, name))
}

fn rule_info(id: &str) -> &'static RuleInfo {
    RULES
        .iter()
        .find(|rule| rule.id == id)
        .expect("scanner references a registered rule")
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
    let mut csharp_unsafe_formatter_seen_at: Option<usize> = None;
    for (index, original_line) in contents.lines().enumerate() {
        let code = sanitize_code_line(original_line, language, &mut lex_state);
        if language == Language::CSharp
            && [
                "new BinaryFormatter",
                "new LosFormatter",
                "new ObjectStateFormatter",
            ]
            .iter()
            .any(|constructor| code.contains(constructor))
        {
            csharp_unsafe_formatter_seen_at = Some(index);
        }
        let mut candidates = Vec::with_capacity(4);
        if language == Language::CFamily
            && contains_any_call(&code, &["gets", "strcpy", "strcat", "sprintf", "vsprintf"])
        {
            candidates.push(rule_info("APO001"));
        }
        if language == Language::CFamily && contains_any_call(&code, &["memcpy", "memmove"]) {
            candidates.push(rule_info("APO002"));
        }
        if language == Language::Rust && contains_token(&code, "unsafe") {
            candidates.push(rule_info("APO003"));
        }
        let dynamic_execution = match language {
            Language::JavaScript => contains_any_call(&code, &["eval", "Function"]),
            Language::Python => contains_any_call(&code, &["eval", "exec"]),
            Language::Php => contains_call(&code, "eval"),
            Language::Ruby => contains_any_ruby_command(
                &code,
                &["eval", "class_eval", "instance_eval", "module_eval"],
            ),
            _ => false,
        };
        if dynamic_execution {
            candidates.push(rule_info("APO004"));
        }
        let shell_execution = match language {
            Language::CFamily => contains_any_call(&code, &["system", "popen"]),
            Language::CSharp => contains_call(&code, "Process.Start"),
            Language::JavaScript => {
                contains_any_call(&code, &["child_process.exec", "child_process.execSync"])
            }
            Language::Go => contains_any_call(&code, &["exec.Command", "exec.CommandContext"]),
            Language::Jvm => {
                contains_any_call(&code, &["ProcessBuilder", "Runtime.getRuntime().exec"])
            }
            Language::Php => contains_any_call(
                &code,
                &[
                    "exec",
                    "passthru",
                    "popen",
                    "proc_open",
                    "shell_exec",
                    "system",
                ],
            ),
            Language::Python => contains_any_call(
                &code,
                &[
                    "os.popen",
                    "os.system",
                    "subprocess.call",
                    "subprocess.check_call",
                    "subprocess.check_output",
                    "subprocess.Popen",
                    "subprocess.run",
                ],
            ),
            Language::Ruby => contains_any_ruby_command(&code, &["exec", "spawn", "system"]),
            Language::Rust => contains_call(&code, "Command::new"),
            Language::Swift => contains_call(&code, "Process"),
        };
        if shell_execution {
            candidates.push(rule_info("APO005"));
        }
        let unsafe_deserialization = match language {
            Language::CSharp => {
                csharp_unsafe_formatter_seen_at.is_some_and(|seen_at| {
                    index.saturating_sub(seen_at) <= CSHARP_FORMATTER_PROXIMITY_LINES
                }) && contains_call(&code, "Deserialize")
            }
            Language::Jvm => contains_call(&code, "readObject"),
            Language::Php => contains_call(&code, "unserialize"),
            Language::Python => {
                contains_any_call(&code, &["pickle.load", "pickle.loads", "yaml.load"])
            }
            Language::Ruby => contains_ruby_command(&code, "Marshal.load"),
            _ => false,
        };
        if unsafe_deserialization {
            candidates.push(rule_info("APO006"));
        }
        for rule in candidates {
            if findings.len() == finding_budget {
                return (findings, true, true);
            }
            findings.push(Finding {
                rule_id: rule.id,
                severity: rule.severity,
                message: rule.message,
                path: display_path.to_owned(),
                line: index + 1,
                snippet: include_snippets.then(|| safe_snippet(original_line)),
            });
        }
    }
    let lexically_complete = lex_state.block_comment_depth == 0
        && lex_state.quote.is_none()
        && lex_state.triple_quote.is_none()
        && lex_state.rust_raw_hashes.is_none()
        && !lex_state.slash_regex_unterminated;
    (findings, false, lexically_complete)
}

fn relative_display(root: &Path, path: &Path) -> String {
    let display = if root.is_file() {
        path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned()
    } else {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    };
    display.replace('\\', "/")
}

fn root_display(root: &Path) -> String {
    if root.is_file() || root != Path::new(".") {
        root.file_name()
            .map(|name| name.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| ".".to_owned())
    } else {
        ".".to_owned()
    }
}

fn matches_custom_exclude(root: &Path, path: &Path, excludes: &[String]) -> bool {
    let name = path.file_name().and_then(|name| name.to_str());
    let relative = relative_display(root, path);
    excludes.iter().any(|exclude| {
        if exclude.contains('/') {
            relative == *exclude || relative.starts_with(&format!("{exclude}/"))
        } else {
            name == Some(exclude.as_str())
        }
    })
}

fn should_ignore_directory(root: &Path, path: &Path, excludes: &[String]) -> bool {
    let name = path.file_name().and_then(|name| name.to_str());
    name.is_some_and(|name| DEFAULT_IGNORED_DIRECTORIES.contains(&name))
        || matches_custom_exclude(root, path, excludes)
}

#[derive(Default)]
struct Discovery {
    files: Vec<PathBuf>,
    skipped_symlinks: usize,
    excluded_files: usize,
    excluded_directories: usize,
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

fn discover_files(root: &Path, excludes: &[String]) -> Discovery {
    let mut discovery = Discovery::default();
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            discovery.add_error(format!("cannot inspect scan root: {error}"));
            return discovery;
        }
    };
    if root_metadata.file_type().is_symlink() {
        discovery.add_error("the scan root must not be a symbolic link".to_owned());
        return discovery;
    }
    if root_metadata.is_file() {
        if matches_custom_exclude(root, root, excludes) {
            discovery.excluded_files += 1;
        } else if language_for(root).is_some() {
            discovery.files.push(root.to_path_buf());
        } else {
            discovery.add_error("the scan root is not a supported source file".to_owned());
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
                if should_ignore_directory(root, &path, excludes) {
                    discovery.excluded_directories += 1;
                } else {
                    stack.push(path);
                }
            } else if file_type.is_file() && language_for(&path).is_some() {
                if matches_custom_exclude(root, &path, excludes) {
                    discovery.excluded_files += 1;
                } else {
                    discovery.files.push(path);
                }
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

fn scan_path(root: &Path, include_snippets: bool, excludes: &[String]) -> ScanReport {
    let discovery = discover_files(root, excludes);
    let supported_files = discovery.files.len();
    let canonical_root = fs::canonicalize(root).ok();
    let root_is_file = root.is_file();
    let mut report = ScanReport {
        root: root_display(root),
        supported_files,
        scanned_files: 0,
        skipped_files: 0,
        skipped_symlinks: discovery.skipped_symlinks,
        excluded_files: discovery.excluded_files,
        excluded_directories: discovery.excluded_directories,
        total_bytes: 0,
        complete: discovery.errors.is_empty() && discovery.suppressed_errors == 0,
        errors: discovery.errors,
        suppressed_errors: discovery.suppressed_errors,
        findings: Vec::new(),
    };

    if report.supported_files == 0 && report.errors.is_empty() {
        report.add_error("no supported source files were discovered".to_owned());
    }

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

fn render_json(report: &ScanReport) -> String {
    let mut output = String::from("{\"schema\":\"apollyon.findings/v1\",\"tool\":{");
    output.push_str("\"name\":\"apollyon\",\"version\":");
    json_string(&mut output, VERSION);
    output.push_str("},\"scope\":");
    json_string(&mut output, SCOPE_NOTE);
    output.push_str(",\"root\":");
    json_string(&mut output, &report.root);
    let _ = write!(
        output,
        ",\"summary\":{{\"supported_files\":{},\"scanned_files\":{},\"skipped_files\":{},\"skipped_symlinks\":{},\"excluded_files\":{},\"excluded_directories\":{},\"total_bytes\":{},\"suppressed_errors\":{},\"complete\":{}}},\"errors\":[",
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

fn render_sarif(report: &ScanReport) -> String {
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
        "{},\"supportedFiles\":{},\"totalBytes\":{},\"skippedSymlinks\":{},\"excludedFiles\":{},\"excludedDirectories\":{}}}}}],\"results\":[",
        report.scanned_files,
        report.supported_files,
        report.total_bytes,
        report.skipped_symlinks,
        report.excluded_files,
        report.excluded_directories
    );
    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"ruleId\":");
        json_string(&mut output, finding.rule_id);
        output.push_str(",\"level\":");
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

fn render_rules() -> String {
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

fn emit_output(rendered: &str, output_path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = output_path {
        let mut contents = rendered.to_owned();
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists {
                format!("refusing to overwrite existing output {}", path.display())
            } else {
                format!("cannot create output file {}: {error}", path.display())
            }
        })?;
        file.write_all(contents.as_bytes())
            .map_err(|error| format!("cannot write output file {}: {error}", path.display()))
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
        Ok(())
    }
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
                std::process::exit(2);
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
    fn supports_major_manual_project_languages() {
        for path in [
            "code.c",
            "code.cpp",
            "code.cs",
            "code.go",
            "code.java",
            "code.kt",
            "code.js",
            "code.tsx",
            "code.php",
            "code.py",
            "code.rb",
            "code.rs",
            "code.swift",
        ] {
            assert!(
                language_for(Path::new(path)).is_some(),
                "unsupported: {path}"
            );
        }
        assert!(language_for(Path::new("notes.txt")).is_none());
    }

    #[test]
    fn detects_cross_language_review_boundaries() {
        assert_eq!(
            findings("dynamic.py", "result = eval(user_input)")[0].rule_id,
            "APO004"
        );
        assert_eq!(
            findings("shell.ts", "child_process.exec(command)")[0].rule_id,
            "APO005"
        );
        assert_eq!(
            findings("object.php", "$value = unserialize($input);")[0].rule_id,
            "APO006"
        );
        assert_eq!(
            findings("runner.go", "exec.Command(name, args...)")[0].rule_id,
            "APO005"
        );
        assert_eq!(
            findings(
                "legacy.cs",
                "var formatter = new BinaryFormatter();\nformatter.Deserialize(stream);"
            )[0]
            .rule_id,
            "APO006"
        );
    }

    #[test]
    fn csharp_unsafe_formatter_flags_deserialize_within_proximity_window() {
        let source = format!(
            "var formatter = new BinaryFormatter();\n{}formatter.Deserialize(stream);",
            "// unrelated line\n".repeat(CSHARP_FORMATTER_PROXIMITY_LINES - 1)
        );
        let result = findings("boundary.cs", &source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "APO006");
    }

    #[test]
    fn csharp_unsafe_formatter_does_not_flag_unrelated_far_deserialize_call() {
        let source = format!(
            "var formatter = new BinaryFormatter();\n{}otherObject.Deserialize(stream);",
            "// unrelated line\n".repeat(CSHARP_FORMATTER_PROXIMITY_LINES + 1)
        );
        assert!(findings("unrelated.cs", &source).is_empty());
    }

    #[test]
    fn handles_go_raw_strings_without_backslash_escapes() {
        let (result, _, complete) = scan_file(
            Path::new("runner.go"),
            "runner.go",
            "var separator = `\\`\nexec.Command(name, args...)",
            false,
            MAX_FINDINGS,
        );
        assert!(complete);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "APO005");
    }

    #[test]
    fn handles_csharp_verbatim_paths_without_backslash_escapes() {
        let (result, _, complete) = scan_file(
            Path::new("runner.cs"),
            "runner.cs",
            r#"var path = @"C:\";
Process.Start(command);"#,
            false,
            MAX_FINDINGS,
        );
        assert!(complete);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "APO005");
    }

    #[test]
    fn detects_ruby_command_style_calls_but_not_method_definitions() {
        let result = findings(
            "commands.rb",
            "eval user_input\nsystem command\nMarshal.load payload",
        );
        assert_eq!(
            result
                .iter()
                .map(|finding| finding.rule_id)
                .collect::<Vec<_>>(),
            vec!["APO004", "APO005", "APO006"]
        );
        assert!(findings(
            "definitions.rb",
            "def eval(input); end\ndef self.system(command); end\ndef Marshal.load(value); end"
        )
        .is_empty());
    }

    #[test]
    fn detects_ruby_command_calls_used_as_hash_values() {
        let result = findings(
            "options.rb",
            "h1 = { block: class_eval(code) }\nh2 = { payload: Marshal.load(data) }\nh3 = { run: spawn(cmd) }",
        );
        assert_eq!(
            result
                .iter()
                .map(|finding| finding.rule_id)
                .collect::<Vec<_>>(),
            vec!["APO004", "APO006", "APO005"]
        );
    }

    #[test]
    fn does_not_flag_ruby_symbol_literals_as_command_calls() {
        assert!(findings("symbols.rb", "send(:system, cmd)").is_empty());
        assert!(findings("symbols.rb", "callbacks = [:eval, :system]").is_empty());
    }

    #[test]
    fn javascript_regex_literals_do_not_hide_later_calls() {
        let source = "const quotes = /['\"]/;\nconst url = /https?:\\/\\/example/;\neval(input);";
        let (result, _, complete) = scan_file(
            Path::new("regex.js"),
            "regex.js",
            source,
            false,
            MAX_FINDINGS,
        );
        assert!(complete);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "APO004");
    }

    #[test]
    fn ruby_regex_literals_do_not_hide_later_commands() {
        let (result, _, complete) = scan_file(
            Path::new("regex.rb"),
            "regex.rb",
            "quotes = /['\"]/\nsystem command",
            false,
            MAX_FINDINGS,
        );
        assert!(complete);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "APO005");
    }

    #[test]
    fn ignores_python_comments_and_multiline_strings() {
        let source = "# eval(input)\ntext = \"\"\"\neval(input)\n\"\"\"\nprint(text)";
        assert!(findings("safe.py", source).is_empty());
        assert!(findings(
            "safe.swift",
            "let text = \"\"\"\nProcess()\n\"\"\"\nprint(text)"
        )
        .is_empty());
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
        assert!(parse_args(&[
            "scan".into(),
            ".".into(),
            "--exclude".into(),
            "../outside".into(),
        ])
        .is_err());
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
                output: None,
                excludes: Vec::new(),
            })
        );
    }

    #[test]
    fn parses_sarif_output_and_exclusions() {
        let command = parse_args(&[
            "scan".into(),
            ".".into(),
            "--format".into(),
            "sarif".into(),
            "--output".into(),
            "report.sarif".into(),
            "--exclude".into(),
            "fixtures/generated".into(),
        ])
        .unwrap();
        let Command::Scan(options) = command else {
            panic!("expected scan command");
        };
        assert_eq!(options.format, OutputFormat::Sarif);
        assert_eq!(options.output, Some(PathBuf::from("report.sarif")));
        assert_eq!(options.excludes, vec!["fixtures/generated"]);
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

        let discovery = discover_files(&fixture, &[]);
        assert_eq!(discovery.files, vec![source]);
        assert_eq!(discovery.skipped_symlinks, 1);
        assert!(discovery.errors.is_empty());

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn discovery_ignores_dependencies_and_custom_directories() {
        let fixture = env::temp_dir().join(format!("apollyon-exclude-test-{}", std::process::id()));
        let source = fixture.join("src");
        let dependency = fixture.join("node_modules");
        let generated = fixture.join("fixtures/generated");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dependency).unwrap();
        fs::create_dir_all(&generated).unwrap();
        fs::write(source.join("app.py"), "eval(user_input)").unwrap();
        fs::write(source.join("skip.py"), "eval(user_input)").unwrap();
        fs::write(dependency.join("dependency.js"), "eval(input)").unwrap();
        fs::write(generated.join("generated.c"), "strcpy(a, b);").unwrap();

        let discovery = discover_files(
            &fixture,
            &["fixtures/generated".to_owned(), "src/skip.py".to_owned()],
        );
        assert_eq!(discovery.files, vec![source.join("app.py")]);
        assert_eq!(discovery.excluded_files, 1);
        assert_eq!(discovery.excluded_directories, 2);

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn empty_or_unsupported_directory_is_incomplete() {
        let fixture = env::temp_dir().join(format!("apollyon-empty-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();
        fs::write(fixture.join("notes.txt"), "not source code").unwrap();

        let report = scan_path(&fixture, false, &[]);
        assert!(!report.complete);
        assert_eq!(report.supported_files, 0);
        assert_eq!(
            report.errors,
            vec!["no supported source files were discovered"]
        );
        let text = render_text(&report);
        assert!(text.contains("scan incomplete; no matches"));
        assert!(!text.contains("no matches for the enabled bounded rules"));

        fs::remove_dir_all(&fixture).unwrap();
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
        };
        let json = render_json(&report);
        let sarif = render_sarif(&report);
        assert!(json.contains("\"path\":\"src/é a#%?.py\""));
        assert!(sarif.contains("\"version\":\"2.1.0\""));
        assert!(sarif.contains("\"ruleId\":\"APO004\""));
        assert!(sarif.contains("\"uri\":\"src/%C3%A9%20a%23%25%3F.py\""));
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

    #[cfg(unix)]
    #[test]
    fn output_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let fixture =
            env::temp_dir().join(format!("apollyon-output-link-test-{}", std::process::id()));
        let target = fixture.join("target.json");
        let link = fixture.join("report.json");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();
        fs::write(&target, "preserve").unwrap();
        symlink(&target, &link).unwrap();

        assert!(emit_output("{}", Some(&link)).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "preserve");

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn output_rejects_existing_regular_files_without_modifying_them() {
        let fixture =
            env::temp_dir().join(format!("apollyon-output-file-test-{}", std::process::id()));
        let target = fixture.join("report.json");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();
        fs::write(&target, "preserve").unwrap();

        assert!(emit_output("{}", Some(&target)).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "preserve");

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn output_files_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let fixture =
            env::temp_dir().join(format!("apollyon-output-mode-test-{}", std::process::id()));
        let target = fixture.join("report.json");
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir(&fixture).unwrap();

        emit_output("{}", Some(&target)).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn root_display_does_not_expose_parent_directories() {
        assert_eq!(
            root_display(Path::new("/private/customer/project")),
            "project"
        );
        assert_eq!(root_display(Path::new(".")), ".");
    }

    #[test]
    fn terminal_output_escapes_bidi_controls() {
        assert_eq!(safe_terminal("safe\u{202e}txt"), "safe\\u202etxt");
    }
}
