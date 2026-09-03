//! A deliberately bounded, single-line subset of TOML; unknown syntax is an error.
use crate::{
    rules::{Severity, RULES},
    scanner::read_bounded_regular_file,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanSettings {
    pub include_snippets: bool,
    pub excludes: Vec<String>,
    pub no_gitignore: bool,
    pub enabled_rules: Option<BTreeSet<String>>,
    pub disabled_rules: BTreeSet<String>,
    pub severity: BTreeMap<String, Severity>,
    pub selected_files: Option<BTreeSet<String>>,
    pub interprocedural: bool,
}
impl ScanSettings {
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
    let mut result = Config::default();
    let mut section = "";
    let mut seen = BTreeSet::new();
    for (index, line) in source.lines().enumerate() {
        let line = uncomment(line).trim();
        if line.is_empty() {
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
        if !seen.insert(format!("{section}.{key}")) {
            return Err("duplicate config key".into());
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
            "fail_on" => result.fail_on = severity(&string(value)?)?,
            _ => return Err(format!("unknown config key at line {}", index + 1)),
        }
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
