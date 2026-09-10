//! CLI parsing, usage text, and create-new output handling.

use crate::rules::Severity;
use std::{
    fs,
    io::{ErrorKind, Write as _},
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Text,
    Json,
    Sarif,
    Markdown,
    Github,
    Gitlab,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScanOptions {
    pub(crate) path: PathBuf,
    pub(crate) format: OutputFormat,
    pub(crate) include_snippets: bool,
    pub(crate) fail_on: Option<Severity>,
    pub(crate) output: Option<PathBuf>,
    pub(crate) excludes: Vec<String>,
    pub(crate) controls: Controls,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Controls {
    pub baseline: Option<PathBuf>,
    pub write_baseline: Option<PathBuf>,
    pub changed_files: Option<PathBuf>,
    pub diff: Option<String>,
    pub no_gitignore: bool,
    pub fail_on_explicit: bool,
    pub enable_rules: Vec<String>,
    pub disable_rules: Vec<String>,
    pub severities: Vec<(String, Severity)>,
    pub interprocedural: bool,
    pub cases_dir: Option<PathBuf>,
    pub authorized: bool,
    pub repository: Option<String>,
    pub revision: Option<String>,
    pub numbers: Vec<(String, usize)>,
    pub only: Option<Vec<String>>,
    pub min_severity: Option<Severity>,
    pub no_default_ignores: bool,
    pub no_auto_baseline: bool,
    pub production_only: bool,
    pub quiet: bool,
    pub color: Option<String>,
    pub watch: bool,
    pub watch_count: Option<usize>,
    pub fix: bool,
    pub fix_dry_run: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Rules,
    Version,
    Explain(String),
    Dependencies(PathBuf, Option<PathBuf>),
    Init(PathBuf, bool, bool),
    Scan(Box<ScanOptions>),
}

pub(crate) fn usage() -> &'static str {
    include_str!("../docs/CLI.txt")
}

pub(crate) fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.first().is_some_and(|a| a == "deps") {
        let root = args.get(1).ok_or("deps requires a project path")?;
        let db = match args.len() {
            2 => None,
            4 if args[2] == "--database" => Some(PathBuf::from(&args[3])),
            _ => return Err("deps <path> [--database <OSV JSON>]".into()),
        };
        return Ok(Command::Dependencies(root.into(), db));
    }
    if matches!(
        args.first().map(String::as_str),
        Some("explain" | "--explain")
    ) {
        if args.len() != 2 {
            return Err("explain requires one rule ID".into());
        }
        crate::config::check_rule(&args[1])?;
        return Ok(Command::Explain(args[1].clone()));
    }
    if args.first().is_some_and(|a| a == "init") {
        let mut root = PathBuf::from(".");
        let mut explicit = false;
        let mut action = false;
        let mut hook = false;
        for arg in &args[1..] {
            match arg.as_str() {
                "--github-action" => action = true,
                "--pre-commit" => hook = true,
                value if !value.starts_with('-') && !explicit => {
                    root = value.into();
                    explicit = true;
                }
                _ => return Err("init accepts [path] [--github-action] [--pre-commit]".into()),
            }
        }
        return Ok(Command::Init(root, action, hook));
    }
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
        controls: Controls::default(),
    };
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--jobs" | "--max-findings" | "--max-file-bytes" | "--max-total-bytes"
            | "--max-entries" | "--watch-count" => {
                let flag = args[index].as_str();
                let maximum = match flag {
                    "--jobs" => 32,
                    "--max-findings" => 1_000_000,
                    "--max-file-bytes" => 32 * 1024 * 1024,
                    "--max-total-bytes" => 2 * 1024 * 1024 * 1024,
                    "--max-entries" => 2_000_000,
                    _ => 10_000,
                };
                let value = crate::config::bounded_number(
                    args.get(index + 1)
                        .ok_or("numeric option requires a value")?,
                    maximum,
                )?;
                if flag == "--watch-count" {
                    options.controls.watch_count = Some(value);
                } else {
                    options
                        .controls
                        .numbers
                        .push((flag.trim_start_matches("--").replace('-', "_"), value));
                }
                index += 2;
            }
            "--only" | "--min-severity" | "--color" => {
                let flag = args[index].as_str();
                let value = args.get(index + 1).ok_or("option requires a value")?;
                match flag {
                    "--only" => {
                        let ids: Vec<_> = value.split(',').map(str::to_owned).collect();
                        for id in &ids {
                            crate::config::check_rule(id)?;
                        }
                        options.controls.only = Some(ids);
                    }
                    "--min-severity" => {
                        options.controls.min_severity = Some(
                            crate::config::severity(value)?
                                .ok_or("min-severity cannot be never")?,
                        )
                    }
                    _ => {
                        if !["auto", "always", "never"].contains(&value.as_str()) {
                            return Err("color must be auto, always, or never".into());
                        }
                        options.controls.color = Some(value.clone());
                    }
                }
                index += 2;
            }
            "--no-auto-baseline" => {
                options.controls.no_auto_baseline = true;
                index += 1;
            }
            "--json" => {
                options.format = OutputFormat::Json;
                index += 1;
            }
            "--no-default-ignores" => {
                options.controls.no_default_ignores = true;
                index += 1;
            }
            "--production-only" => {
                options.controls.production_only = true;
                index += 1;
            }
            "--include-tests" => {
                options.controls.production_only = false;
                index += 1;
            }
            "--quiet" => {
                options.controls.quiet = true;
                index += 1;
            }
            "--stats" => {
                index += 1;
            }
            "--watch" => {
                options.controls.watch = true;
                index += 1;
            }
            "--fix" => {
                options.controls.fix = true;
                index += 1;
            }
            "--fix-dry-run" => {
                options.controls.fix_dry_run = true;
                index += 1;
            }
            "--baseline" | "--write-baseline" | "--changed-files" | "--diff" | "--enable-rule"
            | "--disable-rule" | "--severity" | "--cases-dir" | "--repository" | "--revision" => {
                let flag = args[index].as_str();
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match flag {
                    "--baseline" => options.controls.baseline = Some(value.into()),
                    "--write-baseline" => options.controls.write_baseline = Some(value.into()),
                    "--changed-files" => options.controls.changed_files = Some(value.into()),
                    "--diff" => options.controls.diff = Some(value.clone()),
                    "--cases-dir" => options.controls.cases_dir = Some(value.into()),
                    "--repository" => options.controls.repository = Some(value.clone()),
                    "--revision" => options.controls.revision = Some(value.clone()),
                    "--enable-rule" | "--disable-rule" => {
                        crate::config::check_rule(value)?;
                        if flag == "--enable-rule" {
                            options.controls.enable_rules.push(value.clone());
                        } else {
                            options.controls.disable_rules.push(value.clone());
                        }
                    }
                    "--severity" => {
                        let (id, level) = value
                            .split_once('=')
                            .ok_or("--severity requires APOxxx=info|medium|high")?;
                        crate::config::check_rule(id)?;
                        let level = crate::config::severity(level)?
                            .ok_or("rule severity cannot be never")?;
                        options.controls.severities.push((id.into(), level));
                    }
                    _ => unreachable!(),
                }
                index += 2;
            }
            "--interprocedural" => {
                options.controls.interprocedural = true;
                index += 1;
            }
            "--authorized" => {
                options.controls.authorized = true;
                index += 1;
            }
            "--no-gitignore" => {
                options.controls.no_gitignore = true;
                index += 1;
            }
            "--format" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--format requires text, json, or sarif".to_owned())?;
                options.format = match value.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    "sarif" => OutputFormat::Sarif,
                    "markdown" => OutputFormat::Markdown,
                    "github" => OutputFormat::Github,
                    "gitlab" => OutputFormat::Gitlab,
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
                options.controls.fail_on_explicit = true;
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
    if options.controls.diff.is_some() && options.controls.changed_files.is_some() {
        return Err("--diff and --changed-files are mutually exclusive".into());
    }
    let case_metadata = options.controls.authorized
        || options.controls.repository.is_some()
        || options.controls.revision.is_some();
    if options.controls.cases_dir.is_some() && !options.controls.authorized {
        return Err("--cases-dir requires explicit --authorized target scope".into());
    }
    if options.controls.cases_dir.is_none() && case_metadata {
        return Err("--authorized, --repository, and --revision require --cases-dir".into());
    }
    if options.controls.watch
        && (options.output.is_some()
            || options.controls.write_baseline.is_some()
            || options.controls.cases_dir.is_some()
            || options.controls.fix
            || options.controls.fix_dry_run)
    {
        return Err(
            "watch is incompatible with file output, case/baseline writing, and fixes".into(),
        );
    }
    if options.controls.watch_count.is_some() && !options.controls.watch {
        return Err("watch-count requires watch".into());
    }
    Ok(Command::Scan(Box::new(options)))
}

pub(crate) fn normalize_exclude(value: &str) -> Result<String, String> {
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

pub(crate) fn emit_output(rendered: &str, output_path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = output_path.filter(|p| *p != Path::new("-")) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

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
            Command::Scan(Box::new(ScanOptions {
                path: PathBuf::from("src"),
                format: OutputFormat::Json,
                include_snippets: true,
                fail_on: Some(Severity::High),
                output: None,
                excludes: Vec::new(),
                controls: Controls {
                    fail_on_explicit: true,
                    ..Default::default()
                },
            }))
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
}
