//! Tree-sitter parsing and AST validation for lexical candidates.
use crate::{
    lexer::{lex_line, Language, LexState},
    rules::{adoption, deserialization, exec, memory},
};
use std::{collections::BTreeSet, path::Path};
use tree_sitter::{Language as TsLanguage, Node, Parser};
const MAX_AST_NODES: usize = 1_000_000;
const MAX_INSPECTED_AST_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Debug)]
pub(crate) struct Function {
    pub name: String,
    pub parameters: Vec<String>,
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Debug)]
pub(crate) struct Call {
    pub name: String,
    pub arguments: Vec<String>,
    pub line: usize,
    pub scope: (usize, usize),
}
#[derive(Debug)]
pub(crate) struct Analysis {
    allowed: BTreeSet<(usize, &'static str)>,
    pub scopes: Vec<(usize, usize)>,
    pub functions: Vec<Function>,
    pub calls: Vec<Call>,
}
impl Analysis {
    pub fn allows(&self, line: usize, rule: &str) -> bool {
        self.allowed.contains(&(
            line,
            RULE_IDS.iter().copied().find(|r| *r == rule).unwrap_or(""),
        ))
    }
    pub fn scope(&self, line: usize) -> (usize, usize) {
        self.scopes
            .iter()
            .copied()
            .filter(|(a, b)| *a <= line && line <= *b)
            .min_by_key(|(a, b)| b - a)
            .unwrap_or((1, usize::MAX))
    }
}
const RULE_IDS: [&str; 12] = [
    "APO001", "APO002", "APO003", "APO004", "APO005", "APO006", "APO007", "APO008", "APO009",
    "APO010", "APO011", "APO012",
];
fn grammar(path: &Path) -> Option<TsLanguage> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "c" | "h" => tree_sitter_c::LANGUAGE.into(),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => tree_sitter_cpp::LANGUAGE.into(),
        "cs" => tree_sitter_c_sharp::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "kt" | "kts" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "js" | "jsx" | "mjs" | "cjs" => tree_sitter_javascript::LANGUAGE.into(),
        "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "php" | "phtml" => tree_sitter_php::LANGUAGE_PHP_ONLY.into(),
        "py" | "pyw" => tree_sitter_python::LANGUAGE.into(),
        "rb" | "rake" => tree_sitter_ruby::LANGUAGE.into(),
        "rs" => tree_sitter_rust::LANGUAGE.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        _ => return None,
    })
}
fn slice<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}
fn function_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "function_declaration"
            | "method_definition"
            | "method_declaration"
            | "local_function_statement"
    )
}
fn call_kind(kind: &str) -> bool {
    kind.contains("call")
        || kind.contains("invocation")
        || matches!(kind, "command" | "object_creation_expression")
}
fn structured_kind(kind: &str) -> bool {
    matches!(
        kind,
        "assignment"
            | "assignment_expression"
            | "augmented_assignment"
            | "variable_declarator"
            | "init_declarator"
            | "pair"
            | "keyword_argument"
            | "named_argument"
            | "keyed_element"
            | "field_initializer"
    )
}

fn first_identifier(node: Node, source: &str) -> Option<String> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier" | "simple_identifier" | "variable_name"
        ) {
            return Some(slice(node, source).trim_start_matches('$').to_owned());
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    None
}
fn list_identifiers(node: Node, source: &str) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter_map(|child| first_identifier(child, source))
        .collect()
}

fn parameter_identifiers(node: Node, source: &str) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter_map(|child| {
            child
                .child_by_field_name("name")
                .or_else(|| child.child_by_field_name("declarator"))
                .and_then(|name| first_identifier(name, source))
                .or_else(|| first_identifier(child, source))
        })
        .collect()
}

fn lexical_ids(text: &str, language: Language) -> BTreeSet<&'static str> {
    let view = lex_line(text, language, &mut LexState::default());
    let mut rules = Vec::new();
    memory::match_rules(&view.code, language, &mut rules);
    exec::match_rules(&view.code, language, &mut rules);
    let mut seen = None;
    deserialization::match_rules(&view.code, language, 0, &mut seen, &mut rules);
    adoption::match_rules(&view, language, &mut rules);
    rules.into_iter().map(|r| r.id).collect()
}
pub(crate) fn analyze(path: &Path, source: &str, language: Language) -> Result<Analysis, String> {
    let grammar = grammar(path).ok_or("no grammar")?;
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
        .map_err(|_| "grammar ABI mismatch")?;
    #[allow(deprecated)]
    parser.set_timeout_micros(2_000_000);
    let tree = parser.parse(source, None).ok_or("parser timed out")?;
    if tree.root_node().has_error() {
        return Err("tree-sitter reported syntax errors".into());
    }
    let mut nodes = vec![tree.root_node()];
    let mut allowed = BTreeSet::new();
    let mut scopes = Vec::new();
    let mut functions = Vec::new();
    let mut raw_calls = Vec::new();
    let mut visited = 0;
    let mut inspected_bytes = 0usize;
    while let Some(node) = nodes.pop() {
        visited += 1;
        if visited > MAX_AST_NODES {
            return Err("AST node limit exceeded".into());
        }
        let line = node.start_position().row + 1;
        let kind = node.kind();
        let text = slice(node, source);
        let inspect = call_kind(kind)
            || structured_kind(kind)
            || kind.contains("unsafe")
            || kind.contains("identifier");
        let ids = if inspect {
            inspected_bytes = inspected_bytes.saturating_add(text.len());
            if inspected_bytes > MAX_INSPECTED_AST_BYTES {
                return Err("AST inspection text limit exceeded".into());
            }
            lexical_ids(text, language)
        } else {
            BTreeSet::new()
        };
        for id in ids {
            let valid = match id {
                "APO003" => kind.contains("unsafe"),
                "APO007" => structured_kind(kind),
                "APO008" => call_kind(kind) || kind.contains("identifier") || structured_kind(kind),
                "APO010" => call_kind(kind) || structured_kind(kind),
                _ => call_kind(kind),
            };
            if valid {
                allowed.insert((line, id));
            }
        }
        if id_line(text, "Deserialize") && call_kind(kind) {
            allowed.insert((line, "APO006"));
        }
        if function_kind(kind) {
            let start = line;
            let end = node.end_position().row + 1;
            scopes.push((start, end));
            if let (Some(name), Some(params)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("parameters"),
            ) {
                let parameters = parameter_identifiers(params, source);
                functions.push(Function {
                    name: slice(name, source).to_owned(),
                    parameters,
                    start,
                    end,
                });
            }
        }
        if call_kind(kind) {
            if let (Some(function), Some(arguments)) = (
                node.child_by_field_name("function")
                    .or_else(|| node.child_by_field_name("name")),
                node.child_by_field_name("arguments"),
            ) {
                let args = list_identifiers(arguments, source);
                raw_calls.push((
                    slice(function, source)
                        .rsplit(['.', ':'])
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    args,
                    line,
                ));
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            nodes.push(child);
        }
    }
    let calls = raw_calls
        .into_iter()
        .map(|(name, arguments, line)| {
            let scope = scopes
                .iter()
                .copied()
                .filter(|(a, b)| *a <= line && line <= *b)
                .min_by_key(|(a, b)| b - a)
                .unwrap_or((1, usize::MAX));
            Call {
                name,
                arguments,
                line,
                scope,
            }
        })
        .collect();
    Ok(Analysis {
        allowed,
        scopes,
        functions,
        calls,
    })
}
fn id_line(text: &str, id: &str) -> bool {
    text.match_indices(id).any(|(i, _)| {
        !text[..i]
            .chars()
            .next_back()
            .is_some_and(crate::lexer::is_identifier_character)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_priority_languages_and_filters_definitions() {
        for (path, src, lang) in [
            ("a.py", "def f(x):\n return eval(x)\n", Language::Python),
            (
                "a.js",
                "function f(x) { return eval(x); }",
                Language::JavaScript,
            ),
            (
                "a.go",
                "package p\nfunc f(x string){ exec.Command(x) }",
                Language::Go,
            ),
            ("a.c", "void f(char*x){system(x);}", Language::CFamily),
        ] {
            let a = analyze(Path::new(path), src, lang).unwrap();
            let rule = if path == "a.py" || path == "a.js" {
                "APO004"
            } else {
                "APO005"
            };
            assert!(
                a.allows(
                    if path == "a.py" || path == "a.go" {
                        2
                    } else {
                        1
                    },
                    rule
                ),
                "{path}"
            );
        }
        let a = analyze(
            Path::new("a.c"),
            "int system(int); int main(){return 0;}",
            Language::CFamily,
        )
        .unwrap();
        assert!(!a.allows(1, "APO005"));
    }
    #[test]
    fn syntax_error_requests_fallback() {
        assert!(analyze(Path::new("a.py"), "def broken(:", Language::Python).is_err());
    }
}
