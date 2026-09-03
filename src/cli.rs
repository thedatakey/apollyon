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
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Rules,
    Version,
    Scan(Box<ScanOptions>),
}

pub(crate) fn usage() -> &'static str {
    "Apollyon — bounded, evidence-first source assessment\n\n\
Usage:\n  apollyon scan <path> [--format text|json|sarif] [--output <file>] [--exclude <path>]...\n                       [--include-snippets] [--fail-on info|medium|high|never]\n                       [--baseline <file>] [--write-baseline <file>]\n                       [--diff <git-ref> | --changed-files <file>] [--no-gitignore]\n                       [--enable-rule <id>] [--disable-rule <id>] [--severity <id>=<level>] [--interprocedural]\n  apollyon rules\n  apollyon --version\n  apollyon --help\n\n\
Exit codes: 0 complete, 1 finding met --fail-on, 2 invocation/output error, 3 incomplete scan."
}

pub(crate) fn parse_args(args: &[String]) -> Result<Command, String> {
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
            "--baseline" | "--write-baseline" | "--changed-files" | "--diff" | "--enable-rule"
            | "--disable-rule" | "--severity" => {
                let flag = args[index].as_str();
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match flag {
                    "--baseline" => options.controls.baseline = Some(value.into()),
                    "--write-baseline" => options.controls.write_baseline = Some(value.into()),
                    "--changed-files" => options.controls.changed_files = Some(value.into()),
                    "--diff" => options.controls.diff = Some(value.clone()),
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
