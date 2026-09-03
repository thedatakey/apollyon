use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "apollyon-phase1-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, contents: &str) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    fn scan(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_apollyon"))
            .arg("scan")
            .arg(&self.0)
            .args(["--format", "json"])
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn json(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn count(output: &Output, key: &str) -> usize {
    let text = json(output);
    let prefix = format!("\"{key}\":");
    text.split_once(&prefix)
        .unwrap()
        .1
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
#[test]
fn new_rules_have_positive_and_negative_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase1");
    let positive = apollyon::scan_path(&root.join("positive.py"), false, &[]);
    assert!(positive.complete);
    assert_eq!(
        positive
            .findings
            .iter()
            .map(|f| f.rule_id)
            .collect::<Vec<_>>(),
        ["APO007", "APO008", "APO009", "APO010", "APO011", "APO012"]
    );
    let negative = apollyon::scan_path(&root.join("negative.py"), false, &[]);
    assert!(negative.complete);
    assert!(negative.findings.is_empty(), "{:?}", negative.findings);
}
#[test]
fn suppressions_are_comment_only_and_counted() {
    let w = Workspace::new();
    w.write("app.py","eval(value) # apollyon:ignore[APO004] reviewed\neval('apollyon:ignore')\nopen(path) # apollyon:ignore reason\n");
    let out = w.scan(&[]);
    assert!(out.status.success());
    assert_eq!(count(&out, "suppressed_findings"), 2);
    assert_eq!(count(&out, "new"), 1);
    assert_eq!(count(&out, "total"), 3);
    w.write(
        "app.py",
        "text = \"\"\"\napollyon:ignore\n\"\"\"\neval(value)\n",
    );
    let out = w.scan(&[]);
    assert_eq!(count(&out, "suppressed_findings"), 0);
    assert_eq!(count(&out, "new"), 1);
}
#[test]
fn secret_lines_are_redacted_even_for_other_rules_and_disabled_secret_detection() {
    let w = Workspace::new();
    w.write(
        "app.py",
        "password = 'fixture-only-password'; eval(value)\n",
    );
    let out = w.scan(&["--include-snippets", "--disable-rule", "APO007"]);
    assert!(out.status.success());
    assert!(!json(&out).contains("fixture-only-password"));
    assert_eq!(count(&out, "disabled_findings"), 1);
    assert_eq!(count(&out, "new"), 1);
}
#[test]
fn baseline_survives_line_insertions_and_counts_new_findings() {
    let w = Workspace::new();
    w.write("app.py", "eval(value)\n");
    let baseline = w.0.join("baseline.json");
    let path = baseline.to_str().unwrap();
    let out = w.scan(&["--write-baseline", path]);
    assert!(out.status.success());
    assert!(!fs::read_to_string(&baseline).unwrap().contains("eval"));
    w.write(
        "app.py",
        "# unrelated inserted comment\n\neval(value)\nopen(path)\n",
    );
    let out = w.scan(&["--baseline", path]);
    assert!(out.status.success());
    assert_eq!(count(&out, "baselined"), 1);
    assert_eq!(count(&out, "new"), 1);
    assert_eq!(count(&out, "total"), 2);
    let refuse = w.scan(&["--write-baseline", path]);
    assert_eq!(refuse.status.code(), Some(2));
    w.write("bad.json", "{}");
    let out = w.scan(&["--baseline", w.0.join("bad.json").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
}
#[test]
fn incomplete_scan_does_not_write_baseline() {
    let w = Workspace::new();
    w.write("broken.py", "value = '''unterminated");
    let target = w.0.join("baseline.json");
    let out = w.scan(&["--write-baseline", target.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!target.exists());
}
#[test]
fn changed_files_accounts_for_unselected_and_deleted_paths() {
    let w = Workspace::new();
    w.write("a.py", "eval(a)\n");
    w.write("b.py", "eval(b)\n");
    w.write("changes.txt", "b.py\ndeleted.py\n");
    let out = w.scan(&["--changed-files", w.0.join("changes.txt").to_str().unwrap()]);
    assert!(out.status.success());
    assert_eq!(count(&out, "scanned_files"), 1);
    assert_eq!(count(&out, "unselected_files"), 1);
    assert_eq!(count(&out, "missing_selected_files"), 1);
    w.write("changes.txt", "../outside.py\n");
    assert_eq!(
        w.scan(&["--changed-files", w.0.join("changes.txt").to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
}
#[test]
fn gitignore_nested_negation_and_override_are_counted() {
    let w = Workspace::new();
    w.write(".gitignore", "*.py\n!keep.py\n");
    w.write("keep.py", "eval(a)");
    w.write("skip.py", "eval(b)");
    w.write("src/.gitignore", "!nested.py\n");
    w.write("src/nested.py", "eval(c)");
    let out = w.scan(&[]);
    assert!(out.status.success());
    assert_eq!(count(&out, "excluded_files"), 1);
    assert_eq!(count(&out, "scanned_files"), 2);
    let out = w.scan(&["--no-gitignore"]);
    assert_eq!(count(&out, "scanned_files"), 3);
    w.write(".gitignore", "**/something\n");
    assert_eq!(w.scan(&[]).status.code(), Some(3));
}
#[test]
fn config_precedence_and_invalid_syntax() {
    let w = Workspace::new();
    w.write("app.py", "eval(value)\nopen(path)\n");
    w.write(
        "apollyon.toml",
        "disabled_rules = [\"APO004\"]\nfail_on = \"high\"\n[severity]\nAPO012 = \"high\"\n",
    );
    let out = w.scan(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(count(&out, "disabled_findings"), 1);
    let out = w.scan(&[
        "--enable-rule",
        "APO004",
        "--severity",
        "APO012=info",
        "--fail-on",
        "never",
    ]);
    assert!(out.status.success());
    assert_eq!(count(&out, "new"), 2);
    assert_eq!(count(&out, "disabled_findings"), 0);
    w.write("apollyon.toml", "misspelled = true");
    assert_eq!(w.scan(&[]).status.code(), Some(2));
}
#[test]
fn diff_selects_worktree_changes_and_handles_errors() {
    let w = Workspace::new();
    w.write("a.py", "eval(a)\n");
    w.write("b.py", "eval(b)\n");
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
    ] {
        let out = Command::new("git")
            .current_dir(&w.0)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{:?}", out.stderr);
    }
    w.write("b.py", "eval(changed)\n");
    let out = w.scan(&["--diff", "HEAD"]);
    assert!(out.status.success(), "{:?}", out.stderr);
    assert_eq!(count(&out, "scanned_files"), 1);
    assert_eq!(count(&out, "unselected_files"), 1);
    assert_eq!(w.scan(&["--diff", "missing-ref"]).status.code(), Some(2));
    assert_eq!(w.scan(&["--diff", "--help"]).status.code(), Some(2));
}

#[test]
fn path_expressions_and_unsupported_selected_files_are_explicit() {
    let w = Workspace::new();
    w.write(
        "paths.py",
        "open('base/' + name)\nopen(f'{name}.txt')\nopen('fixed.txt')\n",
    );
    let out = w.scan(&[]);
    assert!(out.status.success());
    assert_eq!(count(&out, "new"), 2);
    w.write("README.md", "documentation");
    w.write("changes.txt", "README.md\n");
    let out = w.scan(&["--changed-files", w.0.join("changes.txt").to_str().unwrap()]);
    assert!(out.status.success());
    assert_eq!(count(&out, "unsupported_selected_files"), 1);
    assert_eq!(count(&out, "scanned_files"), 0);
}
#[test]
fn slash_block_comments_and_strings_have_distinct_suppression_scope() {
    let w = Workspace::new();
    w.write("app.js", "eval(value); // apollyon:ignore[APO004] reviewed\neval(value); /* apollyon:ignore reviewed */\nconst directive = 'apollyon:ignore'; eval(value);\n");
    let out = w.scan(&[]);
    assert!(out.status.success());
    assert_eq!(count(&out, "suppressed_findings"), 2);
    assert_eq!(count(&out, "new"), 1);
}
