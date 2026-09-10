use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "review-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn scan(&self, name: &str, source: &str) -> apollyon::ScanReport {
        fs::write(self.0.join(name), source).unwrap();
        apollyon::scan_path(&self.0.join(name), false, &[])
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn credential_declarations_across_languages() {
    let w = Workspace::new();
    let key = format!("AKIA{}", "0".repeat(16));
    let mut missed = Vec::new();
    for (name, source) in [
        ("a.c", "const char *x = \"KEY\";"),
        ("a.cpp", "const char *x = \"KEY\";"),
        ("a.cs", "class A { string x = \"KEY\"; }"),
        ("a.java", "class A { String x = \"KEY\"; }"),
        ("a.js", "const x = \"KEY\";"),
        ("a.ts", "const x: string = \"KEY\";"),
        ("a.py", "x = \"KEY\""),
        ("a.rb", "x = \"KEY\""),
        ("a.php", "$x = \"KEY\";"),
        ("var.go", "package p\nvar x = \"KEY\""),
        ("const.go", "package p\nconst x = \"KEY\""),
        ("short.go", "package p\nfunc f() { x := \"KEY\" }"),
        ("let.rs", "fn main() { let x = \"KEY\"; }"),
        ("const.rs", "const X: &str = \"KEY\";"),
        ("static.rs", "static X: &str = \"KEY\";"),
        ("val.kt", "val x = \"KEY\""),
        ("var.kt", "var x = \"KEY\""),
        ("let.swift", "let x = \"KEY\""),
        ("var.swift", "var x = \"KEY\""),
    ] {
        let r = w.scan(name, &source.replace("KEY", &key));
        assert!(r.complete && r.error_nodes == 0, "{name}: {r:?}");
        let safe = w.scan(name, &source.replace("KEY", "example"));
        assert!(
            !safe.findings.iter().any(|f| f.rule_id == "APO007"),
            "{name}"
        );
        if !r.findings.iter().any(|f| f.rule_id == "APO007") {
            missed.push(name);
        }
    }
    assert!(missed.is_empty(), "missed declarations: {missed:?}");
}
#[test]
fn jdbc_query_and_update_sinks() {
    let w = Workspace::new();
    for sink in ["executeQuery", "executeUpdate"] {
        let source = format!("class A {{ void f() throws Exception {{\nString id = request.getParameter(\"id\");\ns.{sink}(\"SELECT * FROM users WHERE id=\" + id);\nString sql = \"DELETE FROM users WHERE id=\" + id;\ns.{sink}(sql);\n}} }}");
        let r = w.scan("A.java", &source);
        let lines: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.rule_id == "APO011")
            .map(|f| (f.line, f.confidence))
            .collect();
        assert_eq!(
            lines,
            vec![
                (3, apollyon::Confidence::Tainted),
                (5, apollyon::Confidence::Tainted)
            ],
            "{sink}"
        );
    }
}
#[test]
fn express_html_send() {
    let w = Workspace::new();
    let r = w.scan("app.js", "app.get('/', (req, res) => {\nres.send('<b>' + req.query.q + '</b>');\nres.send('constant');\nres.redirect(req.query.next);\n});");
    let lines: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == "APO015")
        .map(|f| f.line)
        .collect();
    assert_eq!(lines, vec![2]);
    assert!(!r.findings.iter().any(|f| f.rule_id == "APO016"));
}

#[test]
fn jdbc_bound_values_and_constant_html_remain_unflagged() {
    let w = Workspace::new();
    let r = w.scan("A.java", "class A { void f() throws Exception {\nString id = request.getParameter(\"id\");\nPreparedStatement s = connection.prepareStatement(\"SELECT * FROM users WHERE id=?\");\ns.setString(1, id);\ns.executeQuery();\n} }");
    assert!(!r.findings.iter().any(|f| f.rule_id == "APO011"));
    let r = w.scan("app.js", "const q = req.query.q; res.send('<b>' + 'constant');\nclient.send('<b>' + req.query.q);\nres.json({q: req.query.q});\n");
    assert!(!r.findings.iter().any(|f| f.rule_id == "APO015"));
}
