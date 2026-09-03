//! Bounded gitignore subset: *, ?, !, anchored paths, and directory rules.
use crate::scanner::read_bounded_regular_file;
use std::path::Path;
#[derive(Clone, Debug)]
pub(crate) struct IgnoreRule {
    base: String,
    pattern: String,
    negate: bool,
    directory: bool,
    anchored: bool,
}
pub(crate) fn load(root: &Path, directory: &Path) -> Result<Vec<IgnoreRule>, String> {
    let path = directory.join(".gitignore");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("cannot inspect .gitignore".into()),
        Ok(_) => {}
    }
    let bytes = read_bounded_regular_file(&path).map_err(|_| "cannot read regular .gitignore")?;
    if bytes.len() > 65536 {
        return Err(".gitignore exceeds 64 KiB".into());
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| ".gitignore must be UTF-8")?;
    parse(
        &directory
            .strip_prefix(root)
            .unwrap_or(Path::new(""))
            .to_string_lossy()
            .replace('\\', "/"),
        source,
    )
}
fn parse(base: &str, source: &str) -> Result<Vec<IgnoreRule>, String> {
    let mut rules = Vec::new();
    for raw in source.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > 1024 || line.contains("**") || line.contains(['[', ']', '\\']) {
            return Err("unsupported .gitignore pattern (supported: *, ?, !, /)".into());
        }
        let (negate, line) = line.strip_prefix('!').map_or((false, line), |s| (true, s));
        let directory = line.ends_with('/');
        let anchored = line.starts_with('/');
        let pattern = line.trim_matches('/');
        if pattern.is_empty() || pattern.split('/').any(|p| matches!(p, "." | "..")) {
            return Err("invalid .gitignore path".into());
        }
        rules.push(IgnoreRule {
            base: base.into(),
            pattern: pattern.into(),
            negate,
            directory,
            anchored,
        });
        if rules.len() > 1000 {
            return Err(".gitignore exceeds 1000 rules".into());
        }
    }
    Ok(rules)
}
fn glob(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let (mut i, mut j) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while j < v.len() {
        if i < p.len() && (p[i] == v[j] || (p[i] == b'?' && v[j] != b'/')) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            i += 1;
            retry = j;
        } else if let Some(s) = star {
            if retry == v.len() || v[retry] == b'/' {
                return false;
            }
            retry += 1;
            j = retry;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}
pub(crate) fn ignored(rules: &[IgnoreRule], relative: &str, is_directory: bool) -> bool {
    let mut result = false;
    for rule in rules {
        if rule.directory && !is_directory {
            continue;
        }
        let local = if rule.base.is_empty() {
            relative
        } else {
            let Some(rest) = relative.strip_prefix(&format!("{}/", rule.base)) else {
                continue;
            };
            rest
        };
        let matched = if rule.anchored || rule.pattern.contains('/') {
            glob(&rule.pattern, local)
        } else {
            local
                .rsplit('/')
                .next()
                .is_some_and(|name| glob(&rule.pattern, name))
        };
        if matched {
            result = !rule.negate;
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patterns_and_negation() {
        let rules = parse("", "*.py\n!keep.py\n/cache/\nsrc/*.ts").unwrap();
        assert!(ignored(&rules, "src/app.py", false));
        assert!(!ignored(&rules, "keep.py", false));
        assert!(ignored(&rules, "cache", true));
        assert!(!ignored(&rules, "x/cache", true));
        assert!(ignored(&rules, "src/app.ts", false));
        assert!(!ignored(&rules, "src/deep/app.ts", false));
    }
    #[test]
    fn unsupported_is_explicit() {
        assert!(parse("", "**/cache").is_err());
        assert!(parse("", "[abc]").is_err());
    }
    #[test]
    fn nested_scope() {
        let r = parse("src", "/local.py").unwrap();
        assert!(ignored(&r, "src/local.py", false));
        assert!(!ignored(&r, "other/local.py", false));
    }
}
