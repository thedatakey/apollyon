//! Tree-sitter parsing and AST validation for lexical candidates.
use crate::lexer::Language;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use tree_sitter::{Language as TsLanguage, Node, Parser};
const MAX_CAPTURED_AST_BYTES: usize = 16 * 1024 * 1024;
const MAX_AST_NODES: usize = 1_000_000;

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
    pub first_argument: String,
    pub qualified_name: String,
    pub line: usize,
    pub scope: (usize, usize),
}
#[derive(Debug)]
pub(crate) struct Analysis {
    allowed: BTreeSet<(usize, &'static str)>,
    scope_lines: Vec<(usize, usize)>,
    pub functions: Vec<Function>,
    pub calls: Vec<Call>,
    pub command_calls: BTreeMap<usize, bool>,
    shadowed_commands: BTreeSet<usize>,
    pub error_nodes: usize,
    pub interpolations: BTreeMap<usize, Vec<String>>,
    pub tls_fix_ranges: Vec<std::ops::Range<usize>>,
    uncertain: Vec<(usize, usize)>,
}
impl Analysis {
    pub fn allows(&self, line: usize, rule: &str) -> bool {
        !(rule == "APO005" && self.shadowed_commands.contains(&line))
            && (!self.reliable(line) || self.allowed.contains(&(line, rule)))
    }
    pub fn reliable(&self, line: usize) -> bool {
        !self
            .uncertain
            .iter()
            .any(|(start, end)| *start <= line && line <= *end)
    }
    pub fn calls_on_line(&self, line: usize) -> &[Call] {
        let start = self.calls.partition_point(|call| call.line < line);
        let end = self.calls.partition_point(|call| call.line <= line);
        &self.calls[start..end]
    }
    pub fn scope(&self, line: usize) -> (usize, usize) {
        self.scope_lines
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or((1, usize::MAX))
    }
}
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
        || matches!(
            kind,
            "command" | "object_creation_expression" | "new_expression"
        )
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
            | "var_spec"
            | "const_spec"
            | "short_var_declaration"
            | "let_declaration"
            | "const_item"
            | "static_item"
            | "property_declaration"
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
        .map(|child| first_identifier(child, source).unwrap_or_default())
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

fn child_process_module(node: Node, source: &str) -> bool {
    matches!(
        slice(node, source).trim_matches(['\'', '"']),
        "child_process" | "node:child_process"
    )
}
fn require_child_process(node: Node, source: &str) -> bool {
    node.child_by_field_name("function")
        .is_some_and(|n| slice(n, source) == "require")
        && node.child_by_field_name("arguments").is_some_and(|args| {
            args.named_child(0)
                .is_some_and(|n| child_process_module(n, source))
        })
}
fn command_api(name: &str) -> Option<bool> {
    match name {
        "exec" | "execSync" => Some(true),
        "spawn" | "spawnSync" | "execFile" | "execFileSync" | "fork" => Some(false),
        _ => None,
    }
}
pub(crate) fn analyze(path: &Path, source: &str, language: Language) -> Result<Analysis, String> {
    let grammar = grammar(path).ok_or("no grammar")?;
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
        .map_err(|_| "grammar ABI mismatch")?;
    let started = std::time::Instant::now();
    let mut progress =
        |_: &tree_sitter::ParseState| started.elapsed() > std::time::Duration::from_secs(2);
    let mut input = |offset: usize, _: tree_sitter::Point| &source.as_bytes()[offset..];
    let tree = parser
        .parse_with_options(
            &mut input,
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        )
        .ok_or("parser timed out")?;
    let mut nodes = vec![tree.root_node()];
    let mut allowed = BTreeSet::new();
    let mut scopes = Vec::new();
    let mut functions = Vec::new();
    let mut raw_calls = Vec::new();
    let mut bindings = BTreeMap::new();
    let mut declarations = Vec::new();
    let mut shadowed_commands = BTreeSet::new();
    let mut command_calls = BTreeMap::new();
    let mut visited = 0;
    let mut captured_bytes = 0usize;
    let mut uncertain = Vec::new();
    let mut error_nodes = 0;
    let mut interpolations: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut tls_fix_ranges = Vec::new();

    while let Some(node) = nodes.pop() {
        visited += 1;
        if visited > MAX_AST_NODES {
            return Err("AST node limit exceeded".into());
        }
        let line = node.start_position().row + 1;
        let kind = node.kind();
        let text = slice(node, source);
        if matches!(kind, "interpolation" | "template_substitution") && !node.has_error() {
            interpolations
                .entry(line)
                .or_default()
                .push(text.to_owned());
        }
        if language == Language::Python && kind == "keyword_argument" {
            if let (Some(name), Some(value), Some(call)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
                node.parent().and_then(|arguments| arguments.parent()),
            ) {
                let requests = call
                    .child_by_field_name("function")
                    .is_some_and(|function| {
                        [
                            "requests.get",
                            "requests.post",
                            "requests.put",
                            "requests.patch",
                            "requests.delete",
                            "requests.head",
                            "requests.options",
                            "requests.request",
                        ]
                        .contains(&slice(function, source))
                    });
                if requests
                    && !call.has_error()
                    && slice(name, source) == "verify"
                    && slice(value, source) == "False"
                {
                    tls_fix_ranges.push(value.byte_range());
                }
            }
        }
        if node.is_error() || node.is_missing() {
            error_nodes += 1;
            uncertain.push((line, node.end_position().row + 1));
        } else if node.has_error() && (call_kind(kind) || structured_kind(kind)) {
            uncertain.push((line, node.end_position().row + 1));
        }
        if language == Language::JavaScript {
            if matches!(kind, "variable_declarator" | "assignment_expression") {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("left"))
                {
                    if name.kind() == "identifier" {
                        let imported = node
                            .child_by_field_name("value")
                            .or_else(|| node.child_by_field_name("right"))
                            .is_some_and(|v| require_child_process(v, source));
                        declarations.push((slice(name, source).to_owned(), line, imported));
                    }
                }
            }
            if kind == "variable_declarator" {
                if let (Some(name), Some(value)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ) {
                    if require_child_process(value, source) {
                        if name.kind() == "identifier" {
                            bindings.insert(slice(name, source).to_owned(), "*".to_owned());
                        } else if name.kind() == "object_pattern" {
                            let mut cursor = name.walk();
                            for entry in name.named_children(&mut cursor) {
                                let key = entry.child_by_field_name("key").unwrap_or(entry);
                                let alias = entry.child_by_field_name("value").unwrap_or(key);
                                if command_api(slice(key, source)).is_some() {
                                    bindings.insert(
                                        slice(alias, source).to_owned(),
                                        slice(key, source).to_owned(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if kind == "import_statement"
                && node
                    .child_by_field_name("source")
                    .is_some_and(|n| child_process_module(n, source))
            {
                let mut entries = vec![node];
                while let Some(entry) = entries.pop() {
                    if entry.kind() == "import_specifier" {
                        if let Some(name) = entry.child_by_field_name("name") {
                            let alias = entry.child_by_field_name("alias").unwrap_or(name);
                            bindings.insert(
                                slice(alias, source).to_owned(),
                                slice(name, source).to_owned(),
                            );
                        }
                    } else if entry.kind() == "namespace_import" {
                        if let Some(name) = first_identifier(entry, source) {
                            bindings.insert(name, "*".into());
                        }
                    } else {
                        let mut cursor = entry.walk();
                        entries.extend(entry.named_children(&mut cursor));
                    }
                }
            }
            if let Some(function) = node.child_by_field_name("function") {
                if let (Some(object), Some(property)) = (
                    function.child_by_field_name("object"),
                    function.child_by_field_name("property"),
                ) {
                    if require_child_process(object, source) {
                        if let Some(shell) = command_api(slice(property, source)) {
                            command_calls.insert(line, shell);
                        }
                    }
                }
            }
        }
        let inspect = call_kind(kind)
            || structured_kind(kind)
            || kind.contains("unsafe")
            || kind.contains("identifier");
        for rule in crate::rules::RULES.iter().filter(|_| inspect) {
            let id = rule.id;
            let valid = match id {
                "APO003" => kind.contains("unsafe"),
                "APO007" => structured_kind(kind),
                "APO008" => call_kind(kind) || kind.contains("identifier") || structured_kind(kind),
                "APO010" | "APO013" | "APO014" | "APO015" | "APO017" | "APO018" | "APO019"
                | "APO020" | "APO021" => call_kind(kind) || structured_kind(kind),
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
            captured_bytes = captured_bytes.saturating_add(text.len());
            if captured_bytes > MAX_CAPTURED_AST_BYTES {
                return Err("AST capture text limit exceeded".into());
            }
            if let (Some(function), Some(arguments)) = (
                node.child_by_field_name("function")
                    .or_else(|| node.child_by_field_name("name")),
                node.child_by_field_name("arguments"),
            ) {
                let args = list_identifiers(arguments, source);
                raw_calls.push((
                    slice(function, source).to_owned(),
                    args,
                    arguments
                        .named_child(0)
                        .map(|n| slice(n, source).to_owned())
                        .unwrap_or_default(),
                    line,
                ));
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            nodes.push(child);
        }
    }
    let line_count = source.lines().count();
    if line_count > 1_000_000 {
        return Err("AST line index limit exceeded".into());
    }
    let mut starts = scopes.clone();
    starts.sort();
    let mut ends = scopes.clone();
    ends.sort_by_key(|(a, b)| (*b, *a));
    let (mut begin, mut end) = (0, 0);
    let mut active = BTreeSet::new();
    let mut scope_lines = Vec::with_capacity(line_count);
    for line in 1..=line_count {
        while begin < starts.len() && starts[begin].0 <= line {
            let (a, b) = starts[begin];
            active.insert((b - a, a, b));
            begin += 1;
        }
        while end < ends.len() && ends[end].1 < line {
            let (a, b) = ends[end];
            active.remove(&(b - a, a, b));
            end += 1;
        }
        scope_lines.push(active.first().map_or((1, usize::MAX), |(_, a, b)| (*a, *b)));
    }
    let mut calls: Vec<Call> = raw_calls
        .into_iter()
        .map(|(name, arguments, first_argument, line)| {
            if language == Language::JavaScript {
                let root_name = name.split('.').next().unwrap_or(&name);
                let innermost = functions
                    .iter()
                    .filter(|f| f.start <= line && line <= f.end)
                    .min_by_key(|f| f.end - f.start);
                let shadowed = innermost.is_some_and(|f| {
                    f.parameters.iter().any(|p| {
                        p == root_name || (root_name.starts_with("require(") && p == "require")
                    })
                }) || declarations
                    .iter()
                    .filter(|(n, at, _)| {
                        n == root_name
                            && *at <= line
                            && scopes
                                .iter()
                                .filter(|(a, b)| *a <= *at && *at <= *b)
                                .all(|(a, b)| *a <= line && line <= *b)
                    })
                    .max_by_key(|(_, at, _)| *at)
                    .is_some_and(|(_, _, imported)| !*imported);
                let resolved = if let Some((receiver, method)) = name.split_once('.') {
                    (bindings.get(receiver).is_some_and(|b| b == "*")).then_some(method)
                } else {
                    bindings.get(&name).map(String::as_str)
                };
                if !shadowed {
                    if let Some(shell) = resolved.and_then(command_api) {
                        command_calls.insert(line, shell);
                    }
                } else {
                    shadowed_commands.insert(line);
                    command_calls.remove(&line);
                }
            }
            let qualified_name = name.clone();
            let name = name.rsplit(['.', ':']).next().unwrap_or("").to_owned();
            let scope = scope_lines
                .get(line - 1)
                .copied()
                .unwrap_or((1, usize::MAX));
            Call {
                name,
                arguments,
                first_argument,
                qualified_name,
                line,
                scope,
            }
        })
        .collect();
    calls.sort_by_key(|call| call.line);
    Ok(Analysis {
        allowed,
        scope_lines,
        functions,
        calls,
        command_calls,
        shadowed_commands,
        error_nodes,
        interpolations,
        tls_fix_ranges,
        uncertain,
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
    fn syntax_error_preserves_recovered_tree() {
        let a = analyze(
            Path::new("a.py"),
            "eval(value)\ndef broken(:",
            Language::Python,
        )
        .unwrap();
        assert!(a.error_nodes > 0);
        assert!(a.reliable(1));
        assert!(!a.reliable(2));
    }
}
