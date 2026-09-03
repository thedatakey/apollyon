//! Directives are interpreted only in comment spans supplied by the lexer.
pub(crate) fn ignores(comments: &str, rule: &str) -> bool {
    for (index, _) in comments.match_indices("apollyon:ignore") {
        if index > 0
            && comments[..index]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let rest = &comments[index + "apollyon:ignore".len()..];
        if let Some(ids) = rest.strip_prefix('[') {
            if let Some((id, tail)) = ids.split_once(']') {
                if id == rule
                    && (tail.is_empty()
                        || tail.starts_with(char::is_whitespace)
                        || tail.starts_with("*/"))
                {
                    return true;
                }
            }
        } else if rest.is_empty() || rest.starts_with(char::is_whitespace) || rest.starts_with("*/")
        {
            return true;
        }
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directive_boundaries() {
        assert!(ignores("// apollyon:ignore[APO004] reason", "APO004"));
        assert!(!ignores("// apollyon:ignore[APO005]", "APO004"));
        assert!(!ignores("// apollyon:ignore[bad]", "APO004"));
        assert!(!ignores("// apollyon:ignored", "APO004"));
        assert!(ignores("# apollyon:ignore reason", "APO004"));
    }
}
