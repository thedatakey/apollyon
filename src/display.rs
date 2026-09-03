//! Bounded source snippets and terminal-safe escaping.

use std::fmt::Write as _;

const MAX_SNIPPET_CHARS: usize = 180;

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
        )
}

fn push_terminal_character(output: &mut String, character: char) {
    if is_unsafe_display_character(character) {
        let _ = write!(output, "\\u{:04x}", character as u32);
    } else {
        output.push(character);
    }
}

pub(crate) fn safe_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let mut output = String::new();
    let mut truncated = false;
    for (index, character) in trimmed.chars().enumerate() {
        if index == MAX_SNIPPET_CHARS {
            truncated = true;
            break;
        }
        push_terminal_character(&mut output, character);
    }
    if truncated {
        output.push('…');
    }
    output
}

pub(crate) fn safe_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        push_terminal_character(&mut output, character);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_output_escapes_bidi_controls() {
        assert_eq!(safe_terminal("safe\u{202e}txt"), "safe\\u202etxt");
    }
}
