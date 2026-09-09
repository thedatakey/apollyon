//! Bounded gitignore matching, including globstars and character classes.
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
pub(crate) fn load(
    root: &Path,
    directory: &Path,
) -> Result<(Vec<IgnoreRule>, Vec<String>), String> {
    let path = directory.join(".gitignore");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
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
fn parse(base: &str, source: &str) -> Result<(Vec<IgnoreRule>, Vec<String>), String> {
    let mut rules = Vec::new();
    let mut notes = Vec::new();
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > 1024 || line.contains('\\') {
            if line.starts_with('!') {
                return Err(format!(
                    "line {}: unsupported negation may affect coverage",
                    index + 1
                ));
            }
            if notes.len() < 1000 {
                notes.push(format!(
                    "line {}: unsupported ignore rule skipped; matching files remain in scope",
                    index + 1
                ));
            }
            continue;
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
    Ok((rules, notes))
}
// Rolling dynamic programming avoids recursive/backtracking blowups.
pub(crate) fn glob(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let mut matched = vec![false; v.len() + 1];
    matched[0] = true;
    let mut i = 0;
    while i < p.len() {
        let mut next = vec![false; v.len() + 1];
        if p[i] == b'*' {
            let start = i;
            while i < p.len() && p[i] == b'*' {
                i += 1;
            }
            let cross = i - start >= 2
                && (start == 0 || p[start - 1] == b'/')
                && (i == p.len() || p[i] == b'/');
            if cross && i < p.len() && p[i] == b'/' {
                // **/ matches zero or more whole directory components.
                let mut reachable = false;
                for j in 0..=v.len() {
                    reachable |= matched[j];
                    next[j] = matched[j] || (j > 0 && v[j - 1] == b'/' && reachable);
                }
                i += 1;
            } else {
                next[0] = matched[0];
                for j in 1..=v.len() {
                    next[j] = matched[j] || (next[j - 1] && (cross || v[j - 1] != b'/'));
                }
            }
        } else {
            let class_end = if p[i] == b'[' {
                p[i + 1..]
                    .iter()
                    .position(|c| *c == b']')
                    .map(|n| i + 1 + n)
            } else {
                None
            };
            for j in 1..=v.len() {
                let character = v[j - 1];
                let accepts = if let Some(end) = class_end {
                    let mut k = i + 1;
                    let negate = k < end && matches!(p[k], b'!' | b'^');
                    if negate {
                        k += 1;
                    }
                    let mut found = false;
                    while k < end {
                        if k + 2 < end && p[k + 1] == b'-' {
                            found |= p[k] <= character && character <= p[k + 2];
                            k += 3;
                        } else {
                            found |= p[k] == character;
                            k += 1;
                        }
                    }
                    character != b'/' && found != negate
                } else {
                    p[i] == character || (p[i] == b'?' && character != b'/')
                };
                next[j] = matched[j - 1] && accepts;
            }
            i = class_end.map_or(i + 1, |end| end + 1);
        }
        matched = next;
    }
    matched[v.len()]
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
        let rules = parse("", "*.py\n!keep.py\n/cache/\nsrc/*.ts").unwrap().0;
        assert!(ignored(&rules, "src/app.py", false));
        assert!(!ignored(&rules, "keep.py", false));
        assert!(ignored(&rules, "cache", true));
        assert!(!ignored(&rules, "x/cache", true));
        assert!(ignored(&rules, "src/app.ts", false));
        assert!(!ignored(&rules, "src/deep/app.ts", false));
    }
    #[test]
    fn unsupported_is_explicit() {
        assert!(glob("**/cache", "cache"));
        assert!(glob("**/cache", "a/b/cache"));
        assert!(glob("*.py[cod]", "a.pyc"));
        assert!(!glob("*.py[cod]", "a.py"));
        assert!(glob("a/**/b", "a/b"));
        assert!(glob("a/**/b", "a/x/y/b"));
        assert!(!glob("a/*/b", "a/x/y/b"));
        assert!(glob("[!a-c]", "d"));
        assert!(!glob("[!a-c]", "b"));
    }
    #[test]
    fn nested_scope() {
        let r = parse("src", "/local.py").unwrap().0;
        assert!(ignored(&r, "src/local.py", false));
        assert!(!ignored(&r, "other/local.py", false));
    }
}
