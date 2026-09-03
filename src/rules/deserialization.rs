//! Deserialization boundaries, including the bounded C# formatter window (APO006).

use super::{
    patterns::{contains_any_call, contains_call, contains_ruby_command},
    rule_info, RuleInfo,
};
use crate::lexer::Language;

pub(crate) const CSHARP_FORMATTER_PROXIMITY_LINES: usize = 20;

pub(crate) fn match_rules(
    code: &str,
    language: Language,
    index: usize,
    csharp_unsafe_formatter_seen_at: &mut Option<usize>,
    candidates: &mut Vec<&'static RuleInfo>,
) {
    if language == Language::CSharp
        && [
            "new BinaryFormatter",
            "new LosFormatter",
            "new ObjectStateFormatter",
        ]
        .iter()
        .any(|constructor| code.contains(constructor))
    {
        *csharp_unsafe_formatter_seen_at = Some(index);
    }
    let unsafe_deserialization = match language {
        Language::CSharp => {
            csharp_unsafe_formatter_seen_at.is_some_and(|seen_at| {
                index.saturating_sub(seen_at) <= CSHARP_FORMATTER_PROXIMITY_LINES
            }) && contains_call(code, "Deserialize")
        }
        Language::Jvm => contains_call(code, "readObject"),
        Language::Php => contains_call(code, "unserialize"),
        Language::Python => contains_any_call(code, &["pickle.load", "pickle.loads", "yaml.load"]),
        Language::Ruby => contains_ruby_command(code, "Marshal.load"),
        _ => false,
    };
    if unsafe_deserialization {
        candidates.push(rule_info("APO006"));
    }
}
