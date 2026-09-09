//! Bounded discovery, file reading, and lexical scanning.

use crate::{
    config::ScanSettings,
    display::safe_snippet,
    lexer::{language_for, lex_line, LexState},
    report::{Confidence, Engine, Finding, ScanReport},
    rules::{adoption, deserialization, exec, memory},
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(test)]
pub(crate) const MAX_FINDINGS: usize = 10_000;
pub(crate) const MAX_ERRORS: usize = 1_000;
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
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".turbo",
    ".svelte-kit",
    ".astro",
    ".output",
    ".vercel",
    ".netlify",
    ".parcel-cache",
    ".yarn",
    ".pnpm-store",
    "bower_components",
    "Pods",
    ".gradle",
    "obj",
    ".terraform",
    "_build",
    ".serverless",
    ".expo",
    ".dart_tool",
    "site-packages",
    "htmlcov",
    ".nyc_output",
    "storybook-static",
];

#[cfg(test)]
pub(crate) fn scan_file(
    path: &Path,
    display_path: &str,
    contents: &str,
    include_snippets: bool,
    finding_budget: usize,
) -> (Vec<Finding>, bool, bool) {
    let result = scan_file_settings(
        path,
        display_path,
        contents,
        &ScanSettings {
            include_snippets,
            ..Default::default()
        },
        finding_budget,
    );
    (result.findings, result.truncated, result.complete)
}

#[derive(Default)]
struct FileScan {
    parsed: bool,
    error_nodes: usize,
    findings: Vec<Finding>,
    truncated: bool,
    complete: bool,
    total: usize,
    suppressed: usize,
    disabled: usize,
}

fn scan_file_settings(
    path: &Path,
    display_path: &str,
    contents: &str,
    settings: &ScanSettings,
    finding_budget: usize,
) -> FileScan {
    let Some(language) = language_for(path) else {
        return FileScan {
            complete: true,
            ..Default::default()
        };
    };
    let component = crate::lexer::component_source(path, contents);
    let analysis_contents = component.as_deref().unwrap_or(contents);
    let parse_path = if component.is_some() {
        Path::new("component.tsx")
    } else {
        path
    };
    let ast = crate::ast::analyze(parse_path, analysis_contents, language).ok();
    let traces = ast
        .as_ref()
        .map(|analysis| {
            crate::taint::analyze(
                display_path,
                analysis_contents,
                language,
                analysis,
                settings.interprocedural,
            )
        })
        .unwrap_or_default();
    let mut result = FileScan {
        parsed: ast.is_some(),
        error_nodes: ast.as_ref().map_or(0, |a| a.error_nodes),
        complete: true,
        ..Default::default()
    };
    let mut occurrences = std::collections::BTreeMap::new();
    let mut lex_state = LexState::default();
    let mut csharp_unsafe_formatter_seen_at: Option<usize> = None;
    for (index, original_line) in analysis_contents.lines().enumerate() {
        let view = if language == crate::lexer::Language::Config {
            crate::lexer::config_line(original_line)
        } else {
            lex_line(original_line, language, &mut lex_state)
        };
        let code = &view.code;
        let mut candidates = Vec::with_capacity(4);
        memory::match_rules(code, language, &mut candidates);
        exec::match_rules(code, language, &mut candidates);
        deserialization::match_rules(
            code,
            language,
            index,
            &mut csharp_unsafe_formatter_seen_at,
            &mut candidates,
        );
        adoption::match_rules(&view, language, &mut candidates);
        crate::rules::web::match_rules(&view, language, &mut candidates);
        for (&(line, id), _) in traces.range((index + 1, "")..=(index + 1, "ZZZ")) {
            if line == index + 1 && !candidates.iter().any(|r| r.id == id) {
                candidates.push(crate::rules::rule_info(id));
            }
        }
        if ast
            .as_ref()
            .is_some_and(|a| a.command_calls.contains_key(&(index + 1)))
            && !candidates.iter().any(|r| r.id == "APO005")
        {
            candidates.push(crate::rules::rule_info("APO005"));
        }
        if language == crate::lexer::Language::Config {
            candidates.retain(|r| {
                [
                    "APO007", "APO013", "APO014", "APO017", "APO018", "APO019", "APO020",
                ]
                .contains(&r.id)
            });
        }
        let sensitive_line = candidates.iter().any(|r| r.id == "APO007");
        for rule in candidates {
            if ast
                .as_ref()
                .is_some_and(|analysis| !analysis.allows(index + 1, rule.id))
            {
                continue;
            }
            if ["APO012", "APO015", "APO016", "APO021"].contains(&rule.id)
                && !traces.contains_key(&(index + 1, rule.id))
            {
                continue;
            }
            let base = crate::fingerprint::finding(rule.id, display_path, original_line);
            let ordinal = occurrences.entry(base.clone()).or_insert(0usize);
            let fingerprint = if *ordinal == 0 {
                base.clone()
            } else {
                crate::fingerprint::sha256(format!("{base}\0{ordinal}").as_bytes())
            };
            *ordinal += 1;
            result.total += 1;
            if !settings.enabled(rule.id) {
                result.disabled += 1;
                continue;
            }
            if crate::suppression::ignores(&view.comments, rule.id) {
                result.suppressed += 1;
                continue;
            }
            if result.findings.len() == finding_budget {
                result.truncated = true;
                continue;
            }
            let trace = traces
                .get(&(index + 1, rule.id))
                .cloned()
                .unwrap_or_default();
            result.findings.push(Finding {
                rule_id: rule.id,
                severity: settings.severity.get(rule.id).copied().unwrap_or_else(|| {
                    if rule.id == "APO005" {
                        if let Some(shell) =
                            ast.as_ref().and_then(|a| a.command_calls.get(&(index + 1)))
                        {
                            return if *shell {
                                crate::Severity::High
                            } else {
                                crate::Severity::Info
                            };
                        }
                        if language == crate::lexer::Language::Python {
                            let compact = view.code.split_whitespace().collect::<String>();
                            if compact.contains("shell=True")
                                || compact.contains("os.system(")
                                || compact.contains("os.popen(")
                            {
                                return crate::Severity::High;
                            }
                            if compact.contains("([") {
                                return crate::Severity::Info;
                            }
                        }
                    }
                    rule.severity
                }),
                message: rule.message,
                path: display_path.to_owned(),
                line: index + 1,
                snippet: (settings.include_snippets && !sensitive_line)
                    .then(|| safe_snippet(original_line)),
                fingerprint,
                engine: if ast.as_ref().is_some_and(|a| a.reliable(index + 1)) {
                    Engine::Ast
                } else {
                    Engine::Lexical
                },
                confidence: if trace.steps.is_empty() {
                    Confidence::Candidate
                } else if trace.remote {
                    Confidence::Tainted
                } else {
                    Confidence::Reachable
                },
                trace_depth: trace.depth,
                trace: trace.steps,
                case_refs: Vec::new(),
            });
        }
    }
    let lexically_complete = lex_state.block_comment_depth == 0
        && lex_state.quote.is_none()
        && lex_state.triple_quote.is_none()
        && lex_state.rust_raw_hashes.is_none()
        && !lex_state.slash_regex_unterminated;
    result.complete = lexically_complete;
    result
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
            crate::ignore::glob(exclude, &relative) || relative.starts_with(&format!("{exclude}/"))
        } else {
            name.is_some_and(|n| crate::ignore::glob(exclude, n))
        }
    })
}

fn should_ignore_directory(root: &Path, path: &Path, settings: &ScanSettings) -> bool {
    let name = path.file_name().and_then(|name| name.to_str());
    name.is_some_and(|name| {
        (!settings.no_default_ignores && DEFAULT_IGNORED_DIRECTORIES.contains(&name))
            || settings.ignore_directories.iter().any(|n| n == name)
    }) || matches_custom_exclude(root, path, &settings.excludes)
}

#[derive(Default)]
struct Discovery {
    files: Vec<PathBuf>,
    skipped_symlinks: usize,
    excluded_files: usize,
    excluded_directories: usize,
    errors: Vec<String>,
    notes: Vec<String>,
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

#[cfg(test)]
fn discover_files(root: &Path, excludes: &[String]) -> Discovery {
    discover_files_settings(
        root,
        &ScanSettings {
            excludes: excludes.to_vec(),
            ..Default::default()
        },
    )
}
fn discover_files_settings(root: &Path, settings: &ScanSettings) -> Discovery {
    let excludes = &settings.excludes;
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

    let mut stack = vec![(root.to_path_buf(), std::sync::Arc::new(Vec::new()))];
    let mut ignore_rule_count = 0;
    let mut discovered_entries = 0;
    'walk: while let Some((directory, inherited)) = stack.pop() {
        let mut ignore_rules = inherited;
        if !settings.no_gitignore {
            match crate::ignore::load(root, &directory) {
                Ok((rules, notes)) if ignore_rule_count + rules.len() <= 1000 => {
                    let label = relative_display(root, &directory.join(".gitignore"));
                    for note in notes {
                        if discovery.notes.len() < MAX_ERRORS {
                            discovery.notes.push(format!("{label}: {note}"));
                        }
                    }
                    ignore_rule_count += rules.len();
                    if !rules.is_empty() {
                        let mut combined = (*ignore_rules).clone();
                        combined.extend(rules);
                        ignore_rules = std::sync::Arc::new(combined);
                    }
                }
                Ok(_) => {
                    discovery.add_error("aggregate .gitignore limit of 1000 rules exceeded".into())
                }
                Err(error) => discovery.add_error(format!(
                    "{}: {error}",
                    relative_display(root, &directory.join(".gitignore"))
                )),
            }
        }
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
            if discovered_entries > settings.max_entries {
                discovery.add_error(format!(
                    "discovery stopped after {} filesystem entries",
                    settings.max_entries
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
                if should_ignore_directory(root, &path, settings)
                    || crate::ignore::ignored(&ignore_rules, &relative_display(root, &path), true)
                {
                    discovery.excluded_directories += 1;
                } else {
                    stack.push((path, ignore_rules.clone()));
                }
            } else if file_type.is_file() && language_for(&path).is_some() {
                if matches_custom_exclude(root, &path, excludes)
                    || crate::ignore::ignored(&ignore_rules, &relative_display(root, &path), false)
                {
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

pub(crate) fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    read_regular_file_limit(path, MAX_FILE_BYTES)
}
fn read_regular_file_limit(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
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
    if opened.len() > maximum {
        return Err(format!("file exceeds {maximum} bytes"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err(format!("file exceeded {maximum} bytes while reading"));
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

pub fn scan_path(root: &Path, include_snippets: bool, excludes: &[String]) -> ScanReport {
    scan_with_settings(
        root,
        &ScanSettings {
            include_snippets,
            excludes: excludes.to_vec(),
            ..Default::default()
        },
    )
}

pub fn scan_with_settings(root: &Path, settings: &ScanSettings) -> ScanReport {
    if let Err(message) = settings.validate() {
        let mut report = ScanReport::default();
        report.add_error(message);
        return report;
    }
    let discovery = discover_files_settings(root, settings);
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
        notes: discovery.notes,
        suppressed_errors: discovery.suppressed_errors,
        findings: Vec::new(),
        ..Default::default()
    };

    if let Some(selected) = &settings.selected_files {
        report.unsupported_selected_files = selected
            .iter()
            .filter(|p| {
                root.join(p).exists()
                    && (root.join(p).is_dir() || language_for(Path::new(p)).is_none())
            })
            .count();
        report.missing_selected_files = selected.iter().filter(|p| !root.join(p).exists()).count();
    }
    if report.supported_files == 0 && report.errors.is_empty() && settings.selected_files.is_none()
    {
        report.add_error("no supported source files were discovered".to_owned());
    }

    let mut finding_limit_reported = false;
    let mut input_exhausted = false;
    for batch in discovery.files.chunks(settings.jobs) {
        let mut prepared = Vec::new();
        for path in batch {
            let display_path = relative_display(root, path);
            if settings
                .selected_files
                .as_ref()
                .is_some_and(|files| !files.contains(&display_path))
            {
                report.unselected_files += 1;
                continue;
            }
            let resolved_before = match fs::canonicalize(path) {
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
            let bytes = match read_regular_file_limit(path, settings.max_file_bytes) {
                Ok(bytes) => bytes,
                Err(error) => {
                    report.skipped_files += 1;
                    report.add_error(format!("cannot read {display_path}: {error}"));
                    continue;
                }
            };
            if fs::canonicalize(path).ok().as_ref() != Some(&resolved_before) {
                report.skipped_files += 1;
                report.add_error(format!("skipped {display_path}: path changed during read"));
                continue;
            }
            if report.total_bytes.saturating_add(bytes.len()) > settings.max_total_bytes {
                report.add_error(format!(
                    "scan stopped at the aggregate input limit of {} bytes",
                    settings.max_total_bytes
                ));
                input_exhausted = true;
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
            prepared.push((path.clone(), display_path, contents));
        }
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = prepared
                .iter()
                .map(|(path, display, contents)| {
                    scope.spawn(move || {
                        scan_file_settings(
                            path,
                            display,
                            contents,
                            &settings.for_path(display),
                            settings.max_findings,
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join())
                .collect::<Vec<_>>()
        });
        for ((path, display_path, _), result) in prepared.iter().zip(results) {
            let Ok(mut result) = result else {
                report.add_error(format!("analysis worker failed for {display_path}"));
                continue;
            };
            let remaining = settings.max_findings.saturating_sub(report.findings.len());
            if result.findings.len() > remaining {
                result.findings.truncate(remaining);
                result.truncated = true;
            }
            report.error_nodes += result.error_nodes;
            if result.error_nodes > 0 && report.notes.len() < MAX_ERRORS {
                report.notes.push(format!("{display_path}: {} parser error node(s); affected expressions use lexical analysis", result.error_nodes));
            }
            if result.parsed {
                report.ast_files += 1;
            } else {
                report.lexical_files += 1;
                if language_for(path) != Some(crate::lexer::Language::Config) {
                    report.parse_fallback_files += 1;
                }
            }
            report.truncated_findings +=
                result.total - result.suppressed - result.disabled - result.findings.len();
            report.total_findings += result.total;
            report.suppressed_findings += result.suppressed;
            report.disabled_findings += result.disabled;
            report.findings.extend(result.findings);
            if !result.complete {
                report.add_error(format!(
                    "lexical scan of {display_path} ended inside a comment or string"
                ));
            }
            if result.truncated && !finding_limit_reported {
                report.add_error(format!(
                "finding output stopped at the limit of {}; remaining files were still analyzed", settings.max_findings
            ));
                finding_limit_reported = true;
            }
        }
        if input_exhausted {
            break;
        }
    }
    report.errors.sort();
    report.notes.sort();
    report
        .findings
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.line.cmp(&right.line)));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{render::render_text, rules::deserialization::CSHARP_FORMATTER_PROXIMITY_LINES};
    use std::env;
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
    fn root_display_does_not_expose_parent_directories() {
        assert_eq!(
            root_display(Path::new("/private/customer/project")),
            "project"
        );
        assert_eq!(root_display(Path::new(".")), ".");
    }
}
