//! Shared lexical token and call matching.

use crate::lexer::is_identifier_character;

pub(super) fn contains_token(code: &str, token: &str) -> bool {
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

pub(super) fn contains_call(code: &str, function: &str) -> bool {
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

pub(super) fn contains_any_call(code: &str, functions: &[&str]) -> bool {
    functions
        .iter()
        .any(|function| contains_call(code, function))
}

pub(super) fn contains_ruby_command(code: &str, name: &str) -> bool {
    for (start, _) in code.match_indices(name) {
        let end = start + name.len();
        let left_ok = !matches!(
            code[..start].chars().next_back(),
            Some(character) if is_identifier_character(character)
        );
        let right_ok = !matches!(
            code[end..].chars().next(),
            Some(character) if is_identifier_character(character)
        );
        if !left_ok || !right_ok {
            continue;
        }

        let statement_prefix = code[..start]
            .rsplit_once(';')
            .map_or(&code[..start], |(_, suffix)| suffix)
            .trim_start();
        if statement_prefix.starts_with("def ") || code[..start].trim_end().ends_with(':') {
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

pub(super) fn contains_any_ruby_command(code: &str, names: &[&str]) -> bool {
    names.iter().any(|name| contains_ruby_command(code, name))
}

// Phase 1 pattern tables. These are lexical review boundaries, not verdicts.
pub(super) const SECRET_NAMES: &[&str] =
    &["password", "passwd", "api_key", "apikey", "secret", "token"];
pub(super) const SECRET_PREFIXES: &[(&str, usize)] = &[
    ("AKIA", 20),
    ("ghp_", 36),
    ("xoxb-", 20),
    ("xoxa-", 20),
    ("xoxp-", 20),
    ("xoxr-", 20),
    ("xoxs-", 20),
    ("sk-", 32),
    ("AIza", 35),
];
pub(super) const WEAK_CRYPTO: &[&str] = &[
    "MD5",
    "md5",
    "SHA1",
    "sha1",
    "SHA-1",
    "DES",
    "TripleDES",
    "3DES",
    "RC4",
    "rc4",
    "ECB",
    "MODE_ECB",
];
pub(super) const CRYPTO_FACTORIES: &[&str] = &[
    "MessageDigest.getInstance",
    "Cipher.getInstance",
    "crypto.createHash",
    "createHash",
    "hashlib.new",
];
pub(super) const SQL_APIS: &[&str] = &[
    "execute",
    "executemany",
    "query",
    "rawQuery",
    "createStatement",
];
pub(super) const SQL_KEYWORDS: &[&str] = &["SELECT ", "INSERT ", "UPDATE ", "DELETE "];
pub(super) const PATH_APIS: &[&str] = &[
    "open",
    "fopen",
    "readFile",
    "readFileSync",
    "File",
    "File.open",
    "File::open",
    "read_to_string",
    "file_get_contents",
];
pub(super) const RANDOM_JS: &[&str] = &["Math.random"];
pub(super) const RANDOM_C: &[&str] = &["rand", "srand"];
pub(super) const RANDOM_PY: &[&str] = &["random.random", "random.randint", "random.randrange"];
pub(super) const RANDOM_JVM: &[&str] = &["java.util.Random", "Random"];
pub(super) const RANDOM_PHP: &[&str] = &["mt_rand", "rand"];
pub(super) const TLS_FLAGS: &[(&str, &str)] = &[
    ("verify", "False"),
    ("rejectUnauthorized", "false"),
    ("InsecureSkipVerify", "true"),
    ("check_hostname", "False"),
    ("CURLOPT_SSL_VERIFYPEER", "false"),
    ("CURLOPT_SSL_VERIFYHOST", "0"),
];
