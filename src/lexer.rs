//! Language recognition and stateful comment, string, and regex sanitizing.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    CFamily,
    CSharp,
    Go,
    JavaScript,
    Jvm,
    Php,
    Python,
    Ruby,
    Rust,
    Swift,
}

#[derive(Default)]
pub(crate) struct LexState {
    pub(crate) block_comment_depth: usize,
    pub(crate) quote: Option<char>,
    pub(crate) csharp_verbatim_quote: bool,
    pub(crate) triple_quote: Option<char>,
    pub(crate) rust_raw_hashes: Option<usize>,
    pub(crate) slash_regex_unterminated: bool,
}

pub(crate) fn language_for(path: &Path) -> Option<Language> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" => Some(Language::CFamily),
        "cs" => Some(Language::CSharp),
        "go" => Some(Language::Go),
        "java" | "kt" | "kts" => Some(Language::Jvm),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Some(Language::JavaScript),
        "php" | "phtml" => Some(Language::Php),
        "py" | "pyw" => Some(Language::Python),
        "rb" | "rake" => Some(Language::Ruby),
        "rs" => Some(Language::Rust),
        "swift" => Some(Language::Swift),
        _ => None,
    }
}

fn rust_raw_string_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if chars.get(cursor) == Some(&'b') {
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'r') {
        return None;
    }
    cursor += 1;
    let mut hashes = 0;
    while chars.get(cursor) == Some(&'#') {
        hashes += 1;
        cursor += 1;
    }
    (chars.get(cursor) == Some(&'"')).then_some((cursor + 1, hashes))
}

fn is_rust_lifetime(chars: &[char], index: usize) -> bool {
    if chars.get(index) != Some(&'\'') {
        return false;
    }
    let Some(first) = chars.get(index + 1) else {
        return false;
    };
    if !(first.is_alphabetic() || *first == '_') {
        return false;
    }
    let mut cursor = index + 2;
    while chars
        .get(cursor)
        .is_some_and(|character| character.is_alphanumeric() || *character == '_')
    {
        cursor += 1;
    }
    chars.get(cursor) != Some(&'\'')
}

fn uses_slash_comments(language: Language) -> bool {
    !matches!(language, Language::Python | Language::Ruby)
}

fn uses_hash_comments(language: Language) -> bool {
    matches!(language, Language::Php | Language::Python | Language::Ruby)
}

fn supports_nested_block_comments(language: Language) -> bool {
    matches!(language, Language::Rust | Language::Swift)
}

fn supports_backtick_strings(language: Language) -> bool {
    matches!(language, Language::Go | Language::JavaScript)
}

fn supports_triple_quotes(language: Language) -> bool {
    matches!(
        language,
        Language::CSharp | Language::Jvm | Language::Python | Language::Swift
    )
}

fn starts_triple_quote(chars: &[char], index: usize, quote: char) -> bool {
    chars.get(index) == Some(&quote)
        && chars.get(index + 1) == Some(&quote)
        && chars.get(index + 2) == Some(&quote)
}

fn slash_regex_can_start(code_before_slash: &str) -> bool {
    let trimmed = code_before_slash.trim_end();
    let Some(last) = trimmed.chars().next_back() else {
        return true;
    };
    if matches!(
        last,
        '(' | '['
            | '{'
            | ':'
            | ','
            | ';'
            | '='
            | '!'
            | '?'
            | '&'
            | '|'
            | '+'
            | '-'
            | '*'
            | '%'
            | '^'
            | '~'
            | '<'
            | '>'
    ) {
        return true;
    }
    [
        "await", "case", "delete", "in", "instanceof", "new", "of", "return", "throw",
        "typeof", "void", "yield",
    ]
    .iter()
    .any(|keyword| {
        trimmed.strip_suffix(keyword).is_some_and(|prefix| {
            !matches!(prefix.chars().next_back(), Some(character) if is_identifier_character(character))
        })
    })
}

fn slash_regex_end(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    let mut in_character_class = false;
    while index < chars.len() {
        match chars[index] {
            '\\' => index = (index + 2).min(chars.len()),
            '[' if !in_character_class => {
                in_character_class = true;
                index += 1;
            }
            ']' if in_character_class => {
                in_character_class = false;
                index += 1;
            }
            '/' if !in_character_class => {
                index += 1;
                while chars
                    .get(index)
                    .is_some_and(|character| character.is_alphabetic())
                {
                    index += 1;
                }
                return Some(index);
            }
            _ => index += 1,
        }
    }
    None
}

pub(crate) struct LineView {
    pub code: String,
    pub visible: String,
    pub masked: String,
    pub literals: Vec<String>,
    pub comments: String,
}

pub(crate) fn lex_line(line: &str, language: Language, state: &mut LexState) -> LineView {
    let chars: Vec<char> = line.chars().collect();
    let mut output = String::with_capacity(line.len());
    let mut kinds = vec![0u8; chars.len()];
    let mut index = 0;
    while index < chars.len() {
        let start = index;
        if let Some(hashes) = state.rust_raw_hashes {
            if chars[index] == '"'
                && (0..hashes).all(|offset| chars.get(index + 1 + offset) == Some(&'#'))
            {
                state.rust_raw_hashes = None;
                index += 1 + hashes;
            } else {
                index += 1;
            }
            output.push(' ');
            kinds[start..index].fill(1);
            continue;
        }
        if let Some(quote) = state.triple_quote {
            if starts_triple_quote(&chars, index, quote) {
                state.triple_quote = None;
                index += 3;
            } else if chars[index] == '\\' {
                index = (index + 2).min(chars.len());
            } else {
                index += 1;
            }
            output.push(' ');
            kinds[start..index].fill(1);
            continue;
        }
        if let Some(quote) = state.quote {
            if state.csharp_verbatim_quote
                && chars[index] == quote
                && chars.get(index + 1) == Some(&quote)
            {
                index += 2;
            } else if state.csharp_verbatim_quote && chars[index] == quote {
                state.quote = None;
                state.csharp_verbatim_quote = false;
                index += 1;
            } else if chars[index] == '\\'
                && !(language == Language::Go && quote == '`')
                && !state.csharp_verbatim_quote
            {
                index = (index + 2).min(chars.len());
            } else {
                if chars[index] == quote {
                    state.quote = None;
                }
                index += 1;
            }
            output.push(' ');
            kinds[start..index].fill(1);
            continue;
        }
        if state.block_comment_depth > 0 {
            if supports_nested_block_comments(language)
                && chars[index] == '/'
                && chars.get(index + 1) == Some(&'*')
            {
                state.block_comment_depth += 1;
                index += 2;
            } else if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                state.block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            output.push(' ');
            kinds[start..index].fill(2);
            continue;
        }
        if uses_hash_comments(language) && chars[index] == '#' {
            output.push(' ');
            kinds[index..].fill(2);
            break;
        }
        if uses_slash_comments(language)
            && chars[index] == '/'
            && chars.get(index + 1) == Some(&'/')
        {
            output.push(' ');
            kinds[index..].fill(2);
            break;
        }
        if uses_slash_comments(language)
            && chars[index] == '/'
            && chars.get(index + 1) == Some(&'*')
        {
            state.block_comment_depth = 1;
            output.push(' ');
            index += 2;
            kinds[start..index].fill(2);
            continue;
        }
        if matches!(language, Language::JavaScript | Language::Ruby)
            && chars[index] == '/'
            && chars.get(index + 1) != Some(&'=')
            && slash_regex_can_start(&output)
        {
            if let Some(end) = slash_regex_end(&chars, index) {
                index = end;
            } else {
                state.slash_regex_unterminated = true;
                index = chars.len();
            }
            output.push(' ');
            kinds[start..index].fill(3);
            continue;
        }
        if language == Language::Rust {
            if let Some((content_start, hashes)) = rust_raw_string_start(&chars, index) {
                state.rust_raw_hashes = Some(hashes);
                output.push(' ');
                index = content_start;
                kinds[start..index].fill(1);
                continue;
            }
            if is_rust_lifetime(&chars, index) {
                output.push(chars[index]);
                index += 1;
                kinds[start..index].fill(0);
                continue;
            }
        }
        if supports_triple_quotes(language)
            && (chars[index] == '"' || (language == Language::Python && chars[index] == '\''))
            && starts_triple_quote(&chars, index, chars[index])
        {
            state.triple_quote = Some(chars[index]);
            output.push(' ');
            index += 3;
            kinds[start..index].fill(1);
            continue;
        }
        if matches!(chars[index], '"' | '\'')
            || (chars[index] == '`' && supports_backtick_strings(language))
        {
            let previous = index
                .checked_sub(1)
                .and_then(|position| chars.get(position));
            let two_before = index
                .checked_sub(2)
                .and_then(|position| chars.get(position));
            state.csharp_verbatim_quote = language == Language::CSharp
                && chars[index] == '"'
                && (previous == Some(&'@') || (two_before == Some(&'@') && previous == Some(&'$')));
            state.quote = Some(chars[index]);
            output.push(' ');
            index += 1;
            kinds[start..index].fill(1);
            continue;
        }
        output.push(chars[index]);
        index += 1;
    }
    let mut visible = String::with_capacity(line.len());
    let mut masked = String::with_capacity(line.len());
    for (ch, kind) in chars.iter().zip(&kinds) {
        if *kind < 2 {
            visible.push(*ch);
        } else {
            visible.extend(std::iter::repeat_n(' ', ch.len_utf8()));
        }
        if *kind == 0 {
            masked.push(*ch);
        } else {
            masked.extend(std::iter::repeat_n(' ', ch.len_utf8()));
        }
    }
    let mut literals = Vec::new();
    let mut comments = String::new();
    let mut cursor = 0;
    while cursor < chars.len() {
        let kind = kinds[cursor];
        let start = cursor;
        while cursor < chars.len() && kinds[cursor] == kind {
            cursor += 1;
        }
        if kind == 1 {
            literals.push(chars[start..cursor].iter().collect());
        }
        if kind == 2 {
            comments.extend(&chars[start..cursor]);
            comments.push(' ');
        }
    }
    LineView {
        code: output,
        visible,
        masked,
        literals,
        comments,
    }
}

pub(crate) fn is_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_major_manual_project_languages() {
        for path in [
            "code.c",
            "code.cpp",
            "code.cs",
            "code.go",
            "code.java",
            "code.kt",
            "code.js",
            "code.tsx",
            "code.php",
            "code.py",
            "code.rb",
            "code.rs",
            "code.swift",
        ] {
            assert!(
                language_for(Path::new(path)).is_some(),
                "unsupported: {path}"
            );
        }
        assert!(language_for(Path::new("notes.txt")).is_none());
    }
}
