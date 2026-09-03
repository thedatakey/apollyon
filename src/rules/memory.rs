//! C/C++ memory operations and Rust unsafe boundaries (APO001–APO003).

use super::{
    patterns::{contains_any_call, contains_token},
    rule_info, RuleInfo,
};
use crate::lexer::Language;

pub(crate) fn match_rules(code: &str, language: Language, candidates: &mut Vec<&'static RuleInfo>) {
    if language == Language::CFamily
        && contains_any_call(code, &["gets", "strcpy", "strcat", "sprintf", "vsprintf"])
    {
        candidates.push(rule_info("APO001"));
    }
    if language == Language::CFamily && contains_any_call(code, &["memcpy", "memmove"]) {
        candidates.push(rule_info("APO002"));
    }
    if language == Language::Rust && contains_token(code, "unsafe") {
        candidates.push(rule_info("APO003"));
    }
}
