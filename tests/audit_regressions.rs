//! Inert source fixtures for the external audit's precision and recall cases.
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "apollyon-audit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, source: &str) {
        fs::write(self.0.join(name), source).unwrap();
    }
    fn scan(&self) -> apollyon::ScanReport {
        apollyon::scan_path(&self.0, false, &[])
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn audit_seven_case_recall() {
    let f = Fixture::new();
    f.write(
        "app.py",
        &r#"STRIPE_KEY = "SYNTHETIC_STRIPE_FIXTURE"
name = request.args.get("name")
q = "SELECT * FROM users WHERE name = '" + name + "'"
DB.execute(q)
subprocess.check_output("ping -c1 " + host, shell=True)
open("/var/data/" + request.args["f"])
"#
        .replace(
            "SYNTHETIC_STRIPE_FIXTURE",
            &format!("sk_live_{}", "0".repeat(32)),
        ),
    );
    f.write(
        "app.js",
        r#"const JWT_SECRET = "supersecret";
require('child_process').execSync(`convert ${req.query.file}`);
new Function('return ' + req.body.expr)();
"#,
    );
    let r = f.scan();
    assert!(r.complete, "{:?}", r.errors);
    let actual: Vec<_> = r
        .findings
        .iter()
        .map(|x| (x.path.as_str(), x.line, x.rule_id))
        .collect();
    assert_eq!(
        actual,
        [
            ("app.js", 1, "APO007"),
            ("app.js", 2, "APO005"),
            ("app.js", 3, "APO004"),
            ("app.py", 1, "APO007"),
            ("app.py", 4, "APO011"),
            ("app.py", 5, "APO005"),
            ("app.py", 6, "APO012")
        ]
    );
    assert!(r
        .findings
        .iter()
        .filter(|x| x.rule_id == "APO005")
        .all(|x| x.severity == apollyon::Severity::High));
    assert!(r
        .findings
        .iter()
        .filter(|x| x.rule_id == "APO007")
        .all(|x| x.snippet.is_none()));
}
#[test]
fn precision_and_parameterized_sql() {
    let f = Fixture::new();
    f.write(
        "safe.py",
        r#"password = request.form["password"]
r.headers["Authorization"] = _basic_auth_str(self.username, self.password)
secret = os.getenv("JWT_SECRET")
password = "changeme"
hashlib.md5(data, usedforsecurity=False)
open(path)
client.open(request.args["builder"])
name = request.args["name"]
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
open("fixed.txt", name)
q = request.args["q"]
q = "SELECT 1"
cursor.execute(q)
"#,
    );
    let r = f.scan();
    assert!(r.complete);
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}
#[test]
fn command_imports_and_argv_severity() {
    let f = Fixture::new();
    f.write("app.js", "const { execSync: run } = require('node:child_process');\nrun(command);\nconst cp = require('child_process');\ncp.exec(command);\nimport { exec as execute } from 'node:child_process';\nexecute(command);\nimport * as child from 'child_process';\nchild.spawn('ls', [path]);\nconst other = { exec: f };\nother.exec(command);\n");
    f.write("app.py", "subprocess.run(['ls', path])\n");
    let r = f.scan();
    assert!(r.complete);
    assert_eq!(r.findings.len(), 5, "{:?}", r.findings);
    let actual: Vec<_> = r.findings.iter().map(|x| x.severity).collect();
    use apollyon::Severity::{High, Info};
    assert_eq!(actual, [High, High, High, Info, Info]);
}
#[test]
fn ignores_keep_supported_rules_and_expose_notes() {
    let f = Fixture::new();
    f.write("app.py", "eval(value)");
    f.write("skip.py", "eval(value)");
    f.write(".gitignore", "unsupported\\ pattern\nskip.py\n");
    let r = f.scan();
    assert!(r.complete);
    assert_eq!(r.scanned_files, 1);
    assert_eq!(r.notes.len(), 1);
    assert!(r.notes[0].starts_with(".gitignore: line 1:"));
    assert!(apollyon::render_json(&r).contains("\"notes\""));
    assert!(apollyon::render_sarif(&r).contains("\"level\":\"note\""));
    f.write(".gitignore", "!unsupported\\ pattern\nskip.py\n");
    assert!(!f.scan().complete); // An unsupported re-inclusion can hide source.
}
#[test]
fn duplicate_fingerprints_remain_distinct_after_line_insertions() {
    let f = Fixture::new();
    f.write("app.py", "eval(value)\neval(value)\n");
    let before = f.scan();
    assert_ne!(
        before.findings[0].fingerprint,
        before.findings[1].fingerprint
    );
    f.write("app.py", "# comment\neval(value)\n\neval(value)\n");
    let after = f.scan();
    assert_eq!(
        before
            .findings
            .iter()
            .map(|x| &x.fingerprint)
            .collect::<Vec<_>>(),
        after
            .findings
            .iter()
            .map(|x| &x.fingerprint)
            .collect::<Vec<_>>()
    );
}
#[test]
fn usage_is_readable_but_untrusted_newlines_are_escaped() {
    let binary = env!("CARGO_BIN_EXE_apollyon");
    let output = std::process::Command::new(binary)
        .arg("scan")
        .output()
        .unwrap();
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("\nUsage:\n"));
    assert!(!text.contains("\\u000a"));
    let output = std::process::Command::new(binary)
        .args(["scan", ".", "--bad\nINJECTED\u{1b}[2J"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(!text.contains("\nINJECTED"));
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn finding_cap_does_not_skip_later_files_or_hide_truncation() {
    let f = Fixture::new();
    f.write("a.py", &"eval(value)\n".repeat(10001));
    f.write("z.py", "eval(other)\n");
    let r = f.scan();
    assert_eq!(r.scanned_files, 2);
    assert_eq!(r.findings.len(), 10000);
    assert_eq!(r.total_findings, 10002);
    assert_eq!(r.truncated_findings, 2);
    assert!(!r.complete);
    assert_eq!(r.errors.len(), 1);
}

#[test]
fn credential_names_and_trailing_comments() {
    let f = Fixture::new();
    f.write("app.js", "const DB_PASSWORD = 'a-real-looking-value'; // comment\nconst stripeSecretKey = 'another-literal-value';\nconst apiToken = 'a-third-literal-value';\nconst secretary = 'unrelated-string-value';\n");
    f.write("app.py", "JWT_SECRET = 'supersecret'  # comment\n");
    let r = f.scan();
    assert_eq!(r.findings.len(), 4, "{:?}", r.findings);
    assert!(r.findings.iter().all(|x| x.rule_id == "APO007"));
}
