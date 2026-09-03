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
