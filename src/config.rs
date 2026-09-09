//! A deliberately bounded, single-line subset of TOML; unknown syntax is an error.
use crate::{
    rules::{Severity, RULES},
    scanner::read_bounded_regular_file,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSettings {
    pub include_snippets: bool,
    pub excludes: Vec<String>,
    pub no_gitignore: bool,
    pub enabled_rules: Option<BTreeSet<String>>,
    pub disabled_rules: BTreeSet<String>,
    pub severity: BTreeMap<String, Severity>,
    pub selected_files: Option<BTreeSet<String>>,
    pub interprocedural: bool,
    pub jobs: usize,
    pub max_findings: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: usize,
    pub max_entries: usize,
    pub no_default_ignores: bool,
    pub ignore_directories: Vec<String>,
    pub min_severity: Option<Severity>,
    pub overrides: Vec<PathOverride>,
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PathOverride {
    pub paths: Vec<String>,
    pub disabled_rules: BTreeSet<String>,
    pub fail_on: Option<Option<Severity>>,
}
impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            include_snippets: false,
            excludes: Vec::new(),
            no_gitignore: false,
            enabled_rules: None,
            disabled_rules: BTreeSet::new(),
            severity: BTreeMap::new(),
            selected_files: None,
            interprocedural: false,
            jobs: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)),
            max_findings: 10_000,
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_entries: 100_000,
            no_default_ignores: false,
            ignore_directories: Vec::new(),
            min_severity: None,
            overrides: Vec::new(),
        }
    }
}
pub(crate) fn bounded_number(value: &str, maximum: usize) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|n| *n > 0 && *n <= maximum)
        .ok_or_else(|| format!("expected integer in 1..={maximum}"))
}
impl ScanSettings {
    pub(crate) fn for_path(&self, path: &str) -> Self {
        let mut settings = self.clone();
        for entry in &self.overrides {
            if entry
                .paths
                .iter()
                .any(|pattern| crate::ignore::glob(pattern, path))
            {
                settings
                    .disabled_rules
                    .extend(entry.disabled_rules.iter().cloned());
            }
        }
        settings
    }
    pub(crate) fn threshold(&self, path: &str, default: Option<Severity>) -> Option<Severity> {
        let mut threshold = default;
        for entry in &self.overrides {
            if entry
                .paths
                .iter()
                .any(|pattern| crate::ignore::glob(pattern, path))
            {
                if let Some(value) = entry.fail_on {
                    threshold = value;
                }
            }
        }
        threshold
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, n, max) in [
            ("jobs", self.jobs, 32),
            ("max_findings", self.max_findings, 1_000_000),
            (
                "max_file_bytes",
                self.max_file_bytes as usize,
                32 * 1024 * 1024,
            ),
            (
                "max_total_bytes",
                self.max_total_bytes,
                2 * 1024 * 1024 * 1024,
            ),
            ("max_entries", self.max_entries, 2_000_000),
        ] {
            if n == 0 || n > max {
                return Err(format!("{name} must be in 1..={max}"));
            }
        }
        Ok(())
    }
    pub(crate) fn enabled(&self, id: &str) -> bool {
        self.enabled_rules
            .as_ref()
            .is_none_or(|ids| ids.contains(id))
            && !self.disabled_rules.contains(id)
    }
}
#[derive(Default)]
pub(crate) struct Config {
    pub settings: ScanSettings,
    pub fail_on: Option<Severity>,
}

pub(crate) fn severity(value: &str) -> Result<Option<Severity>, String> {
    match value {
        "info" => Ok(Some(Severity::Info)),
        "medium" => Ok(Some(Severity::Medium)),
        "high" => Ok(Some(Severity::High)),
        "never" => Ok(None),
        _ => Err("invalid severity".into()),
    }
}
pub(crate) fn check_rule(id: &str) -> Result<(), String> {
    if RULES.iter().any(|r| r.id == id) {
        Ok(())
    } else {
        Err("unknown rule ID".into())
    }
}
fn string(value: &str) -> Result<String, String> {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or("expected a quoted string")?;
    let mut result = String::new();
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            if !matches!(ch, '"' | '\\') {
                return Err("unsupported string escape".into());
            }
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' || ch.is_control() {
            return Err("invalid string".into());
        } else {
            result.push(ch);
        }
    }
    if escaped {
        return Err("unterminated escape".into());
    }
    Ok(result)
}
fn array(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or("expected single-line array")?;
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escape = false;
    for (i, c) in inner.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quoted {
            escape = true;
            continue;
        }
        if c == '"' {
            quoted = !quoted;
        }
        if c == ',' && !quoted {
            parts.push(string(inner[start..i].trim())?);
            start = i + 1;
        }
    }
    let last = inner[start..].trim();
    if !last.is_empty() {
        parts.push(string(last)?);
    }
    Ok(parts)
}
fn uncomment(line: &str) -> &str {
    let mut quoted = false;
    let mut escape = false;
    for (i, c) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && quoted {
            escape = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == '#' && !quoted {
            return &line[..i];
        }
    }
    line
}
pub(crate) fn parse(source: &str) -> Result<Config, String> {
    let mut line = 1;
    parse_lines(source, &mut line).map_err(|error| format!("apollyon.toml line {line}: {error}"))
}
fn parse_lines(source: &str, current_line: &mut usize) -> Result<Config, String> {
    let mut result = Config::default();
    let mut section = "";
    let mut seen = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        *current_line = index + 1;
        let line = uncomment(line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[overrides]]" {
            if result.settings.overrides.len() == 128 {
                return Err("at most 128 overrides are supported".into());
            }
            result.settings.overrides.push(PathOverride::default());
            section = "overrides";
            continue;
        }
        if line == "[severity]" {
            if !seen.insert("[severity]".to_owned()) {
                return Err("duplicate section".into());
            }
            section = "severity";
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("unsupported config syntax at line {}", index + 1))?;
        let key = key.trim();
        let value = value.trim();
        if !seen.insert(format!(
            "{section}.{}.{key}",
            result.settings.overrides.len()
        )) {
            return Err("duplicate config key".into());
        }
        if section == "overrides" {
            let entry = result
                .settings
                .overrides
                .last_mut()
                .expect("override section exists");
            match key {
                "paths" => {
                    entry.paths = array(value)?
                        .into_iter()
                        .map(|v| crate::cli::normalize_exclude(&v))
                        .collect::<Result<_, _>>()?
                }
                "disabled_rules" => {
                    let ids = array(value)?;
                    for id in &ids {
                        check_rule(id)?;
                    }
                    entry.disabled_rules = ids.into_iter().collect();
                }
                "fail_on" => entry.fail_on = Some(severity(&string(value)?)?),
                _ => return Err(format!("unknown override key at line {}", index + 1)),
            }
            continue;
        }
        if section == "severity" {
            check_rule(key)?;
            let level = severity(&string(value)?)?.ok_or("rule severity cannot be never")?;
            result.settings.severity.insert(key.into(), level);
            continue;
        }
        match key {
            "enabled_rules" | "disabled_rules" => {
                let ids = array(value)?;
                for id in &ids {
                    check_rule(id)?;
                }
                if key == "enabled_rules" {
                    result.settings.enabled_rules = Some(ids.into_iter().collect());
                } else {
                    result.settings.disabled_rules = ids.into_iter().collect();
                }
            }
            "excludes" => {
                result.settings.excludes = array(value)?
                    .into_iter()
                    .map(|v| crate::cli::normalize_exclude(&v))
                    .collect::<Result<_, _>>()?;
            }
            "jobs" => result.settings.jobs = bounded_number(value, 32)?,
            "max_findings" => result.settings.max_findings = bounded_number(value, 1_000_000)?,
            "max_file_bytes" => {
                result.settings.max_file_bytes = bounded_number(value, 32 * 1024 * 1024)? as u64
            }
            "max_total_bytes" => {
                result.settings.max_total_bytes = bounded_number(value, 2 * 1024 * 1024 * 1024)?
            }
            "max_entries" => result.settings.max_entries = bounded_number(value, 2_000_000)?,
            "no_default_ignores" => {
                result.settings.no_default_ignores = match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err("expected true or false".into()),
                }
            }
            "ignore_directories" => result.settings.ignore_directories = array(value)?,
            "min_severity" => result.settings.min_severity = severity(&string(value)?)?,
            "fail_on" => result.fail_on = severity(&string(value)?)?,
            _ => return Err(format!("unknown config key at line {}", index + 1)),
        }
    }
    result.settings.validate()?;
    if result.settings.overrides.iter().any(|o| o.paths.is_empty()) {
        return Err("each override requires nonempty paths".into());
    }
    Ok(result)
}
pub(crate) fn load(root: &Path) -> Result<Config, String> {
    let base = if root.is_file() {
        root.parent().unwrap_or(Path::new("."))
    } else {
        root
    };
    let path = base.join("apollyon.toml");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(_) => return Err("cannot inspect apollyon.toml".into()),
        Ok(_) => {}
    }
    let bytes = read_bounded_regular_file(&path)
        .map_err(|_| "cannot read bounded regular apollyon.toml")?;
    if bytes.len() > 65536 {
        return Err("apollyon.toml exceeds 64 KiB".into());
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| "apollyon.toml must be UTF-8")?;
    parse(source)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_validates_and_overrides() {
        let c = parse(
            "enabled_rules = [\"APO004\"]\nfail_on = \"high\"\n[severity]\nAPO004 = \"info\"",
        )
        .unwrap();
        assert!(c.settings.enabled("APO004"));
        assert!(!c.settings.enabled("APO001"));
        assert_eq!(c.settings.severity["APO004"], Severity::Info);
    }
    #[test]
    fn config_rejects_unknown_duplicate_and_unsupported() {
        for s in [
            "unknown = 1",
            "fail_on = \"high\"\nfail_on = \"info\"",
            "enabled_rules = [\"APO999\"]",
            "[wrong]",
            "excludes = [\"../outside\"]",
        ] {
            assert!(parse(s).is_err(), "{s}");
        }
    }
}
