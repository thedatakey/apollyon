use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static N: AtomicUsize = AtomicUsize::new(0);
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "apollyon-phase2-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn write(&self, n: &str, s: &str) {
        fs::write(self.0.join(n), s).unwrap();
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn every_supported_language_uses_an_ast_for_valid_source() {
    let w = Workspace::new();
    for(name,source)in[
("a.c","void f(char *command){ system(command); }"),("a.cpp","void f(char *command){ system(command); }"),("a.cs","class A { void F(string command){ System.Diagnostics.Process.Start(command); } }"),("a.go","package p\nimport \"os/exec\"\nfunc f(command string){ exec.Command(command) }"),("a.java","class A { void f(String command) throws Exception { Runtime.getRuntime().exec(command); } }"),("a.kt","fun f(command: String) { Runtime.getRuntime().exec(command) }"),("a.js","function f(command) { child_process.exec(command); }"),("a.ts","function f(command: string): void { child_process.exec(command); }"),("a.php","function f($value) { eval($value); }"),("a.py","def f(value):\n    return eval(value)\n"),("a.rb","def f(value)\n eval(value)\nend\n"),("a.rs","fn f(){ unsafe { call(); } }"),("a.swift","func f() { let task = Process() }")]{w.write(name,source);}
    let report = apollyon::scan_path(&w.0, false, &[]);
    assert!(report.complete, "{:?}", report.errors);
    assert_eq!(report.ast_files, 13);
    assert_eq!(report.lexical_files, 0);
    assert_eq!(report.parse_fallback_files, 0);
    assert!(report
        .findings
        .iter()
        .all(|f| f.engine == apollyon::Engine::Ast));
}
#[test]
fn tainted_and_sanitized_flows_have_bounded_evidence() {
    let w = Workspace::new();
    w.write("flows.py","def bad():\n    value = request.args['x']\n    eval(value)\n\ndef safe():\n    value = request.args['n']\n    value = int(value)\n    eval(value)\n");
    let report = apollyon::scan_path(&w.0, false, &[]);
    let evals: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "APO004")
        .collect();
    assert_eq!(evals.len(), 2);
    assert_eq!(evals[0].confidence, apollyon::Confidence::Tainted);
    assert_eq!(
        evals[0]
            .trace
            .iter()
            .map(|s| s.kind.as_str())
            .collect::<Vec<_>>(),
        ["source", "sink"]
    );
    assert_eq!(evals[1].confidence, apollyon::Confidence::Candidate);
    assert!(evals[1].trace.is_empty());
    let json = apollyon::render_json(&report);
    assert!(json.contains("\"schema\":\"apollyon.findings/v2\""));
    assert!(json.contains("\"engine\":\"ast\""));
    assert!(json.contains("\"confidence\":\"tainted\""));
    assert!(json.contains("\"trace\":[{"));
}
#[test]
fn interprocedural_mode_is_opt_in_and_one_boundary() {
    let w = Workspace::new();
    w.write("calls.py","def sink(value):\n    eval(value)\ndef caller():\n    item = request.args['x']\n    sink(item)\n");
    let base = apollyon::scan_path(&w.0, false, &[]);
    assert_eq!(base.findings[0].confidence, apollyon::Confidence::Candidate);
    let settings = apollyon::ScanSettings {
        interprocedural: true,
        ..Default::default()
    };
    let report = apollyon::scan_with_settings(&w.0, &settings);
    assert_eq!(report.findings[0].confidence, apollyon::Confidence::Tainted);
    assert!(report.findings[0].trace.iter().any(|s| s.kind == "call"));
}
#[test]
fn parse_failures_fall_back_without_claiming_ast_coverage() {
    let w = Workspace::new();
    w.write("broken.py", "eval(value)\ndef broken(:\n");
    let report = apollyon::scan_path(&w.0, false, &[]);
    assert!(report.complete);
    assert_eq!(report.ast_files, 0);
    assert_eq!(report.lexical_files, 1);
    assert_eq!(report.parse_fallback_files, 1);
    assert_eq!(report.findings[0].engine, apollyon::Engine::Lexical);
    assert_eq!(
        report.findings[0].confidence,
        apollyon::Confidence::Candidate
    );
}
#[test]
fn ast_filter_removes_function_definition_substring_candidates() {
    let w = Workspace::new();
    w.write("definitions.py", "def eval(value):\n    return value\n");
    let report = apollyon::scan_path(&w.0, false, &[]);
    assert!(report.complete);
    assert_eq!(report.ast_files, 1);
    assert!(report.findings.is_empty());
}
