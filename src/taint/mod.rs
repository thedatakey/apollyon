//! Bounded, same-file taint analysis. Unknown operations preserve taint.
use crate::{
    ast::Analysis,
    lexer::{lex_line, Language, LexState},
    report::TraceStep,
    rules::{adoption, deserialization, exec, memory},
};
use std::collections::{BTreeMap, BTreeSet};
const SOURCES: &[&str] = &[
    "request.args",
    "request.form",
    "request.json",
    "request.body",
    "request.headers",
    "req.query",
    "req.body",
    "req.params",
    "r.URL.Query",
    "r.FormValue",
    "os.environ",
    "process.env",
    "std::env::args",
    "env::args",
    "stdin",
    "sys.argv",
    "input(",
    "readLine(",
    "open(",
    "readFile(",
    "os.ReadFile(",
    "File.read",
    "read_to_string",
    "readObject(",
    "pickle.load",
    "yaml.load",
];
const DIRECT_SOURCES: &[&str] = &[
    "request.args",
    "request.form",
    "request.json",
    "request.body",
    "request.headers",
    "req.query",
    "req.body",
    "req.params",
    "r.URL.Query",
    "r.FormValue",
    "os.environ",
    "process.env",
    "std::env::args",
    "env::args",
    "stdin",
    "sys.argv",
    "input(",
    "readLine(",
];
const INTEGER_SANITIZERS: &[&str] = &[
    "int(",
    "parseInt(",
    "Number(",
    "Integer.parseInt(",
    "strconv.Atoi(",
];
const SINK_RULES: &[&str] = &["APO004", "APO005", "APO006", "APO011", "APO012"];
#[derive(Clone)]
struct Value {
    steps: Vec<TraceStep>,
    cleared: BTreeSet<&'static str>,
}
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() || matches!(c, '_' | '$') {
            token.push(c);
        } else if !token.is_empty() {
            out.push(std::mem::take(&mut token));
        }
    }
    if !token.is_empty() {
        out.push(token);
    }
    out
}
fn lhs(line: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if right.starts_with('=') || left.ends_with(['!', '<', '>', '=']) {
        return None;
    }
    tokens(left)
        .pop()
        .map(|v| v.trim_start_matches('$').to_owned())
}
fn source(text: &str) -> bool {
    SOURCES.iter().any(|s| text.contains(s))
}
fn apply_allowlist_guard(line: &str, values: &mut BTreeMap<String, Value>) {
    let guarded = line.contains("return")
        && ((line.contains(" not in ") && line.contains("if "))
            || line.contains(".includes(")
            || (line.contains('!') && line.contains('[')));
    if guarded {
        for token in tokens(line) {
            if values.contains_key(&token) {
                values.remove(&token);
            }
        }
    }
}
fn direct_source(text: &str) -> bool {
    DIRECT_SOURCES.iter().any(|source| text.contains(source))
}

fn rules(
    line: &str,
    language: Language,
    state: &mut LexState,
    csharp: &mut Option<usize>,
    index: usize,
) -> Vec<&'static str> {
    let view = lex_line(line, language, state);
    let mut result = Vec::new();
    memory::match_rules(&view.code, language, &mut result);
    exec::match_rules(&view.code, language, &mut result);
    deserialization::match_rules(&view.code, language, index, csharp, &mut result);
    adoption::match_rules(&view, language, &mut result);
    result
        .into_iter()
        .map(|r| r.id)
        .filter(|r| SINK_RULES.contains(r))
        .collect()
}
pub(crate) fn analyze(
    path: &str,
    source_text: &str,
    language: Language,
    ast: &Analysis,
    interprocedural: bool,
) -> BTreeMap<(usize, &'static str), Vec<TraceStep>> {
    let lines: Vec<_> = source_text.lines().collect();
    let mut states: BTreeMap<(usize, usize), BTreeMap<String, Value>> = BTreeMap::new();
    let mut result = BTreeMap::new();
    let mut lex = LexState::default();
    let mut source_lex = LexState::default();
    let mut csharp = None;
    for (offset, line) in lines.iter().enumerate() {
        let line_no = offset + 1;
        let scope = ast.scope(line_no);
        let values = states.entry(scope).or_default();
        let source_view = lex_line(line, language, &mut source_lex);
        let source_line = source_view.masked.as_str();
        apply_allowlist_guard(source_line, values);
        let right = source_line.split_once('=').map_or(source_line, |(_, r)| r);
        let mut incoming: Option<Value> = None;
        if source(right) {
            incoming = Some(Value {
                steps: vec![TraceStep {
                    path: path.into(),
                    line: line_no,
                    kind: "source".into(),
                }],
                cleared: BTreeSet::new(),
            });
        }
        for token in tokens(right) {
            if let Some(value) = values.get(token.trim_start_matches('$')) {
                let take = incoming
                    .as_ref()
                    .is_none_or(|old| value.steps.len() < old.steps.len());
                if take {
                    incoming = Some(value.clone());
                }
            }
        }
        if let Some(name) = lhs(source_line) {
            if INTEGER_SANITIZERS.iter().any(|s| right.contains(s)) {
                values.remove(&name);
            } else if let Some(mut value) = incoming.clone() {
                if right.contains("shlex.quote(") {
                    value.cleared.insert("APO005");
                }
                if value.steps.last().is_none_or(|s| s.line != line_no) {
                    value.steps.push(TraceStep {
                        path: path.into(),
                        line: line_no,
                        kind: "propagation".into(),
                    });
                }
                value.steps.truncate(8);
                values.insert(name, value);
            }
        }
        for rule in rules(line, language, &mut lex, &mut csharp, offset) {
            if !ast.allows(line_no, rule) {
                continue;
            }
            let mut evidence = if direct_source(source_line) {
                Some(Value {
                    steps: vec![TraceStep {
                        path: path.into(),
                        line: line_no,
                        kind: "source".into(),
                    }],
                    cleared: BTreeSet::new(),
                })
            } else {
                None
            };
            for token in tokens(source_line) {
                if let Some(value) = values.get(token.trim_start_matches('$')) {
                    if !value.cleared.contains(rule) {
                        evidence = Some(value.clone());
                        break;
                    }
                }
            }
            if let Some(mut value) = evidence {
                value.steps.push(TraceStep {
                    path: path.into(),
                    line: line_no,
                    kind: "sink".into(),
                });
                value.steps.truncate(10);
                result.insert((line_no, rule), value.steps);
            }
        }
    }
    if interprocedural {
        for call in &ast.calls {
            let Some(caller) = states.get(&call.scope) else {
                continue;
            };
            let Some((position, value)) =
                call.arguments
                    .iter()
                    .enumerate()
                    .find_map(|(position, argument)| {
                        caller.get(argument).map(|value| (position, value))
                    })
            else {
                continue;
            };
            let Some(function) = ast.functions.iter().find(|f| f.name == call.name) else {
                continue;
            };
            let Some(parameter) = function.parameters.get(position) else {
                continue;
            };
            for line_no in function.start..=function.end {
                let line = lines.get(line_no - 1).copied().unwrap_or("");
                if !tokens(line).contains(parameter) {
                    continue;
                }
                let mut state = LexState::default();
                let mut seen = None;
                for rule in rules(line, language, &mut state, &mut seen, line_no - 1) {
                    if ast.allows(line_no, rule) {
                        let mut steps = value.steps.clone();
                        steps.push(TraceStep {
                            path: path.into(),
                            line: call.line,
                            kind: "call".into(),
                        });
                        steps.push(TraceStep {
                            path: path.into(),
                            line: line_no,
                            kind: "sink".into(),
                        });
                        steps.truncate(10);
                        result.insert((line_no, rule), steps);
                    }
                }
            }
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intra_and_sanitized_flows() {
        let src="def bad():\n value = request.args['x']\n eval(value)\ndef safe():\n value = request.args['n']\n value = int(value)\n eval(value)\n";
        let ast = crate::ast::analyze(std::path::Path::new("a.py"), src, Language::Python).unwrap();
        let r = analyze("a.py", src, Language::Python, &ast, false);
        assert!(r.contains_key(&(3, "APO004")));
        assert!(!r.contains_key(&(7, "APO004")));
    }
    #[test]
    fn file_reads_taint_returns_and_single_line_allowlists_clear_values() {
        let src = "def f():\n data = open('input.txt').read()\n eval(data)\ndef g():\n value = request.args['x']\n if value not in ALLOWED: return\n eval(value)\n";
        let ast = crate::ast::analyze(std::path::Path::new("a.py"), src, Language::Python).unwrap();
        let found = analyze("a.py", src, Language::Python, &ast, false);
        assert!(found.contains_key(&(3, "APO004")));
        assert!(!found.contains_key(&(7, "APO004")));
    }
    #[test]
    fn source_names_inside_literals_do_not_taint() {
        let src = "def f():\n value = 'request.args'\n eval(value)\n";
        let ast = crate::ast::analyze(std::path::Path::new("a.py"), src, Language::Python).unwrap();
        assert!(!analyze("a.py", src, Language::Python, &ast, false).contains_key(&(3, "APO004")));
    }
    #[test]
    fn bounded_interprocedural_flow() {
        let src="def sink(value):\n eval(value)\ndef caller():\n item = request.args['x']\n sink(item)\n";
        let ast = crate::ast::analyze(std::path::Path::new("a.py"), src, Language::Python).unwrap();
        let r = analyze("a.py", src, Language::Python, &ast, true);
        assert!(r.contains_key(&(2, "APO004")));
        assert!(!analyze("a.py", src, Language::Python, &ast, false).contains_key(&(2, "APO004")));
    }
}
