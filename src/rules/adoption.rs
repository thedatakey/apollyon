//! Phase 1 lexical rules use literal metadata without treating comments as code.
use super::{patterns::*, rule_info, RuleInfo};
use crate::lexer::{Language, LineView};
fn literal_value(value: &str) -> &str {
    value.trim_matches(['\'', '"', '`', '#'])
}
pub(crate) fn secret_name(name: &str) -> bool {
    let mut segmented = String::new();
    let mut previous_lower = false;
    for ch in name.chars() {
        if ch.is_uppercase() && previous_lower {
            segmented.push('_');
        }
        previous_lower = ch.is_lowercase();
        segmented.extend(ch.to_lowercase());
    }
    segmented
        .split(|c: char| !c.is_alphanumeric())
        .any(|part| SECRET_NAMES.contains(&part))
        || segmented.ends_with("api_key")
        || segmented == "service_role"
}
fn placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "changeme"
            | "password"
            | "your-key-here"
            | "example"
            | "test"
            | "test key"
            | "secret_key"
            | "dummy"
            | "redacted"
    ) || lower.starts_with(['<'])
        || lower.contains("${")
        || lower.contains("{{")
        || value.chars().all(|c| value.starts_with(c))
}
pub(crate) fn secret_assignment(view: &LineView) -> bool {
    view.literals.iter().any(|raw| {
        let value = literal_value(raw);
        let prefix = super::secrets::provider(value);
        // Only the assignment's immediate literal value qualifies. Literal keys
        // inside calls/subscripts are not credentials assigned to the target.
        let named = view
            .visible
            .split_once('=')
            .or_else(|| view.visible.split_once(':'))
            .is_some_and(|(left, right)| {
                let target = left.split_whitespace().last().unwrap_or("");
                let right = right.trim_start();
                secret_name(target)
                    && right.strip_prefix(raw).is_some_and(|tail| {
                        tail.trim().is_empty() || tail.trim_start().starts_with([';', ',', '}'])
                    })
            })
            && value.len() >= 8
            && !placeholder(value);
        let private_key = value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----");
        prefix || named || private_key
    })
}
fn flag_value(code: &str, name: &str, value: &str) -> bool {
    for (i, _) in code.match_indices(name) {
        if i > 0
            && code[..i]
                .chars()
                .next_back()
                .is_some_and(crate::lexer::is_identifier_character)
        {
            continue;
        }
        let after = code[i + name.len()..].trim_start();
        if let Some(rest) = after
            .strip_prefix('=')
            .or_else(|| after.strip_prefix(':'))
            .or_else(|| after.strip_prefix(','))
        {
            let rest = rest.trim_start();
            if let Some(tail) = rest.strip_prefix(value) {
                if !tail
                    .chars()
                    .next()
                    .is_some_and(crate::lexer::is_identifier_character)
                {
                    return true;
                }
            }
        }
    }
    false
}
fn variable_path(view: &LineView) -> bool {
    PATH_APIS.iter().any(|api| {
        if !contains_call(&view.code, api) {
            return false;
        }
        view.masked.match_indices(api).any(|(i, _)| {
            if i > 0
                && view.masked[..i]
                    .chars()
                    .next_back()
                    .is_some_and(crate::lexer::is_identifier_character)
            {
                return false;
            }
            if *api == "open"
                && i > 0
                && view.masked[..i].ends_with('.')
                && !view.masked[..i].ends_with("File.")
            {
                return false;
            }
            let after = view.visible[i + api.len()..].trim_start();
            let Some(args) = after.strip_prefix('(') else {
                return false;
            };
            let masked_after = view.masked[i + api.len()..].trim_start();
            let masked_args = masked_after.strip_prefix('(').unwrap_or("");
            let mut depth = 0usize;
            let end = masked_args
                .char_indices()
                .find_map(|(position, ch)| {
                    match ch {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' if depth > 0 => depth -= 1,
                        ',' | ')' if depth == 0 => return Some(position),
                        _ => {}
                    }
                    None
                })
                .unwrap_or(masked_args.len());
            let expression = masked_args[..end].trim();
            let literal = args.trim_start().starts_with(['\'', '\"', '`'])
                || ["r\"", "r'", "b\"", "b'", "@\""]
                    .iter()
                    .any(|p| args.trim_start().starts_with(p));
            !(expression.is_empty() || literal && matches!(expression, "r" | "b" | "@"))
                && expression
                    .chars()
                    .any(|c| c.is_alphabetic() || matches!(c, '_' | '$'))
        })
    })
}
pub(crate) fn match_rules(
    view: &LineView,
    language: Language,
    candidates: &mut Vec<&'static RuleInfo>,
) {
    if secret_assignment(view) {
        candidates.push(rule_info("APO007"));
    }
    let weak = WEAK_CRYPTO.iter().any(|p| contains_token(&view.code, p))
        || (contains_any_call(&view.code, CRYPTO_FACTORIES)
            && view.literals.iter().any(|s| {
                WEAK_CRYPTO.iter().any(|p| {
                    literal_value(s)
                        .split('/')
                        .any(|piece| piece.eq_ignore_ascii_case(p))
                })
            }));
    if weak && !(language == Language::Python && flag_value(&view.code, "usedforsecurity", "False"))
    {
        candidates.push(rule_info("APO008"));
    }
    let random = match language {
        Language::JavaScript => RANDOM_JS,
        Language::CFamily => RANDOM_C,
        Language::Python => RANDOM_PY,
        Language::Jvm => RANDOM_JVM,
        Language::Php => RANDOM_PHP,
        _ => &[],
    };
    if contains_any_call(&view.code, random) {
        candidates.push(rule_info("APO009"));
    }
    let tls = TLS_FLAGS
        .iter()
        .any(|(name, value)| flag_value(&view.code, name, value))
        || contains_token(&view.code, "SSL_VERIFY_NONE")
        || ((contains_token(&view.code, "NODE_TLS_REJECT_UNAUTHORIZED")
            || contains_token(&view.code, "process.env"))
            && view.visible.contains("NODE_TLS_REJECT_UNAUTHORIZED")
            && view
                .visible
                .split_once('=')
                .or_else(|| view.visible.split_once(':'))
                .is_some_and(|(_, v)| {
                    v.trim()
                        .trim_end_matches(';')
                        .trim_matches(['\'', '"'])
                        .trim()
                        == "0"
                }))
        || (contains_token(&view.code, "HostnameVerifier") && view.code.contains("return true"))
        || (contains_call(&view.code, "checkServerTrusted")
            && view
                .code
                .split_once(')')
                .is_some_and(|(_, body)| body.split_whitespace().collect::<String>() == "{}"));
    if tls {
        candidates.push(rule_info("APO010"));
    }
    let sql = view.literals.iter().any(|s| {
        SQL_KEYWORDS.iter().any(|kw| {
            literal_value(s)
                .trim_start()
                .to_ascii_uppercase()
                .starts_with(kw)
        })
    });
    let interpolation = view.visible.contains("${")
        || view.visible.contains("f\"")
        || view.visible.contains("f'")
        || view.visible.contains("$\"");
    if sql
        && contains_any_call(&view.code, SQL_APIS)
        && (view.code.contains('+')
            || view.code.contains('%')
            || interpolation
            || (language == Language::Php && view.code.contains(" . ")))
    {
        candidates.push(rule_info("APO011"));
    }
    if variable_path(view) {
        candidates.push(rule_info("APO012"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::{lex_line, LexState};
    fn ids(source: &str, language: Language) -> Vec<&'static str> {
        let view = lex_line(source, language, &mut LexState::default());
        let mut rules = Vec::new();
        match_rules(&view, language, &mut rules);
        rules.iter().map(|r| r.id).collect()
    }
    #[test]
    fn cross_language_positive_and_negative_patterns() {
        for (language, positive, negative, id) in [
            (
                Language::JavaScript,
                "crypto.createHash('md5')",
                "crypto.createHash('sha256')",
                "APO008",
            ),
            (
                Language::Jvm,
                "MessageDigest.getInstance(\"SHA-1\")",
                "MessageDigest.getInstance(\"SHA-256\")",
                "APO008",
            ),
            (
                Language::JavaScript,
                "Math.random()",
                "crypto.randomUUID()",
                "APO009",
            ),
            (Language::CFamily, "rand()", "arc4random()", "APO009"),
            (
                Language::Jvm,
                "new java.util.Random()",
                "new SecureRandom()",
                "APO009",
            ),
            (Language::Php, "mt_rand()", "random_int(0,100)", "APO009"),
            (
                Language::Go,
                "InsecureSkipVerify: true",
                "InsecureSkipVerify: false",
                "APO010",
            ),
            (
                Language::JavaScript,
                "rejectUnauthorized: false",
                "rejectUnauthorized: true",
                "APO010",
            ),
            (
                Language::JavaScript,
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",
                "let text = 'NODE_TLS_REJECT_UNAUTHORIZED=0'",
                "APO010",
            ),
            (
                Language::Php,
                "curl_setopt(c, CURLOPT_SSL_VERIFYPEER, false)",
                "curl_setopt(c, CURLOPT_SSL_VERIFYPEER, true)",
                "APO010",
            ),
            (
                Language::JavaScript,
                "db.query(`SELECT id FROM items WHERE x=${x}`)",
                "db.query('SELECT id FROM items WHERE x=?', [x])",
                "APO011",
            ),
            (
                Language::Python,
                "cursor.execute(f'SELECT id FROM items WHERE x={x}')",
                "cursor.execute('SELECT id FROM items WHERE x=?',(x,))",
                "APO011",
            ),
            (
                Language::Rust,
                "File::open(user_path)",
                "File::open(\"fixed.txt\")",
                "APO012",
            ),
            (
                Language::CFamily,
                "fopen(path, mode)",
                "fopen(\"fixed.txt\", \"r\")",
                "APO012",
            ),
            (
                Language::JavaScript,
                "readFile(userPath)",
                "const s='readFile(userPath)'; readFile('fixed.txt')",
                "APO012",
            ),
            (
                Language::Python,
                "password = 'fixture-only-password'",
                "password = get_value()",
                "APO007",
            ),
        ] {
            assert!(
                ids(positive, language).contains(&id),
                "missing {id}: {positive}"
            );
            assert!(
                !ids(negative, language).contains(&id),
                "false {id}: {negative}"
            );
        }
    }
    #[test]
    fn comments_and_literal_calls_do_not_trigger_rules() {
        for language in [
            Language::JavaScript,
            Language::CFamily,
            Language::Rust,
            Language::Jvm,
            Language::Go,
        ] {
            assert!(ids(
                "// MD5 rand() InsecureSkipVerify: true open(path)",
                language
            )
            .is_empty());
        }
        assert!(ids("text = 'open(path)'", Language::Python).is_empty());
    }
    #[test]
    fn secret_thresholds_and_prefixes() {
        assert!(ids("password = 'short'", Language::Python).is_empty());
        assert!(ids("key = 'AKIA0000000000000000'", Language::Python).contains(&"APO007"));
        assert!(!ids("key = 'AKIAshort'", Language::Python).contains(&"APO007"));
    }
}
