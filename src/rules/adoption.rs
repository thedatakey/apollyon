//! Phase 1 lexical rules use literal metadata without treating comments as code.
use super::{patterns::*, rule_info, RuleInfo};
use crate::lexer::{Language, LineView};
fn literal_value(value: &str) -> &str {
    value.trim_matches(['\'', '"', '`', '#'])
}
fn entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in value.bytes() {
        counts[b as usize] += 1;
    }
    let n = value.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}
fn hardcoded_secret(view: &LineView) -> bool {
    view.literals.iter().any(|raw| {
        let value = literal_value(raw);
        let prefix = SECRET_PREFIXES.iter().any(|(p, n)| {
            value.starts_with(p)
                && value.len() >= *n
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-/+=.".contains(&b))
        });
        let named = SECRET_NAMES
            .iter()
            .any(|name| contains_token(&view.code.to_ascii_lowercase(), name))
            && view.code.contains('=')
            && value.len() >= 8;
        let private_key = value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----");
        let high_entropy = value.len() >= 32
            && value.len() <= 512
            && value.is_ascii()
            && !value.contains(char::is_whitespace)
            && entropy(value) >= 4.5;
        prefix || named || private_key || high_entropy
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
    if hardcoded_secret(view) {
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
    if weak {
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
            && view.visible.split_once('=').is_some_and(|(_, v)| {
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
