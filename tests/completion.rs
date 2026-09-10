//! Bounded regressions for the audit completion work.
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static N: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "apollyon-completion-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn put(&self, p: &str, s: &str) {
        let p = self.0.join(p);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }
    fn scan(&self) -> apollyon::ScanReport {
        apollyon::scan_path(&self.0, false, &[])
    }
    fn cli(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_apollyon"))
            .arg("scan")
            .arg(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn serial_parallel_outputs_and_limits() {
    let f = Fixture::new();
    for i in 0..25 {
        f.put(&format!("{i}.py"), "eval(value)\n");
    }
    let mut s = apollyon::ScanSettings {
        jobs: 1,
        max_findings: 7,
        ..Default::default()
    };
    let a = apollyon::scan_with_settings(&f.0, &s);
    s.jobs = 8;
    let b = apollyon::scan_with_settings(&f.0, &s);
    assert_eq!(apollyon::render_json(&a), apollyon::render_json(&b));
    assert_eq!(b.scanned_files, 25);
    assert_eq!(b.truncated_findings, 18);
    assert!(!b.complete);
    assert_eq!(f.cli(&["--jobs", "0"]).status.code(), Some(2));
}
#[test]
fn overrides_filters_and_globs() {
    let f = Fixture::new();
    f.put("src/app.py", "eval(value)\n");
    f.put("tests/app.py", "eval(value)\n");
    f.put("static.min.js", "eval(value)\n");
    f.put("apollyon.toml","fail_on = \"high\"\njobs = 2\n[[overrides]]\npaths = [\"tests/**\"]\ndisabled_rules = [\"APO004\"]\n");
    let o = f.cli(&["--json", "--exclude", "*.min.js", "--only", "APO004"]);
    assert_eq!(o.status.code(), Some(1));
    let t = String::from_utf8(o.stdout).unwrap();
    assert!(t.contains("\"disabled_findings\":1"));
    assert!(t.contains("\"new\":1"));
}
#[test]
fn local_remote_scope_and_trace_depth() {
    let f = Fixture::new();
    let mut s=String::from("user = sys.argv[1]\ndef local():\n    eval(user)\ndef remote():\n    x0 = request.args['q']\n");
    for i in 1..15 {
        s.push_str(&format!("    x{i} = x{}\n", i - 1));
    }
    s.push_str("    eval(x14)\n");
    f.put("app.py", &s);
    let r = f.scan();
    let e: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == "APO004")
        .collect();
    assert_eq!(e[0].confidence, apollyon::Confidence::Reachable);
    assert_eq!(e[1].confidence, apollyon::Confidence::Tainted);
    assert!(e[1].trace_depth > e[1].trace.len());
    assert_eq!(e[1].trace.first().unwrap().line, 5);
    assert_eq!(e[1].trace.last().unwrap().kind, "sink");
}
#[test]
fn new_web_rules_and_negative_flows() {
    let f = Fixture::new();
    f.put("app.py","url = request.args['url']\nrequests.get(url)\nrequests.get('https://fixed.example')\napp.run(debug=True)\njwt.decode(token, verify=False)\nrender_template_string(request.args['template'])\n");
    f.put("app.js","const NEXT_PUBLIC_SECRET = 'a-real-looking-credential';\nconst SERVICE_ROLE = 'a-real-looking-credential';\nconst config = {origin: '*', credentials: true};\nres.cookie('session', value, {secure: false});\ncollection.find(req.body);\nnew PythonREPLTool();\n");
    let r = f.scan();
    let ids: Vec<_> = r.findings.iter().map(|x| x.rule_id).collect();
    for id in [
        "APO013", "APO014", "APO015", "APO016", "APO017", "APO018", "APO019", "APO020", "APO021",
        "APO022",
    ] {
        assert!(ids.contains(&id), "{id}: {ids:?}");
    }
    assert_eq!(
        r.findings.iter().filter(|x| x.rule_id == "APO016").count(),
        1
    );
}
#[test]
fn config_secrets_and_safe_configuration() {
    let f = Fixture::new();
    f.put(".env.local","JWT_SECRET=really-secret-value\nDATABASE_URL=postgres://user:password-value@localhost/db\n");
    let r = f.scan();
    assert!(r.complete);
    assert_eq!(
        r.findings.iter().filter(|x| x.rule_id == "APO007").count(),
        2
    );
    f.put(".env.local", "JWT_SECRET=${JWT_SECRET}\n");
    assert!(f.scan().findings.is_empty());
}
#[test]
fn formats_init_explain_watch_and_fix() {
    let f = Fixture::new();
    f.put("app.py", "requests.get(url, verify=False)\n");
    for format in ["markdown", "github", "gitlab"] {
        assert!(f
            .cli(&["--format", format, "--output", "-"])
            .status
            .success());
    }
    let e = Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .args(["explain", "APO011"])
        .output()
        .unwrap();
    assert!(String::from_utf8(e.stdout).unwrap().contains("name=?"));
    assert!(f
        .cli(&["--watch", "--watch-count", "1", "--quiet"])
        .status
        .success());
    assert!(f.cli(&["--fix-dry-run"]).status.success());
    assert!(fs::read_to_string(f.0.join("app.py"))
        .unwrap()
        .contains("False"));
    assert!(f.cli(&["--fix"]).status.success());
    assert!(f.0.join("app.py.apollyon.bak").exists());
    assert!(fs::read_to_string(f.0.join("app.py"))
        .unwrap()
        .contains("True"));
    let o = Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .arg("init")
        .arg(&f.0)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(!Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .arg("init")
        .arg(&f.0)
        .output()
        .unwrap()
        .status
        .success());
}
#[test]
fn modern_syntax_preserves_ast() {
    let f = Fixture::new();
    for (path,src) in [("app.ts","using resource = acquire();\nconst input = req.body.expr;\neval(input);"),("app.py","type Pair[T] = tuple[T, T]\ndef f():\n    value = request.args['x']\n    eval(value)\n"),("app.kt","data object State\nfun f() { Runtime.getRuntime().exec(command) }\n")]{f.put(path,src);}
    let r = f.scan();
    assert_eq!(r.ast_files, 3);
    assert_eq!(r.lexical_files, 0);
}
#[test]
fn pinned_upstream_precision() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benchmarks/upstream");
    let settings = apollyon::ScanSettings {
        enabled_rules: Some(["APO007".to_string(), "APO012".to_string()].into()),
        ..Default::default()
    };
    let r = apollyon::scan_with_settings(&root, &settings);
    assert!(r.complete, "{:?}", r.errors);
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}
#[test]
fn command_binding_shadowing() {
    let f = Fixture::new();
    f.put("app.js","const cp = require('child_process');\ncp.exec(command);\nfunction safe(cp) { cp.exec(command); }\ncp = other;\ncp.exec(command);\n");
    let r = f.scan();
    assert_eq!(
        r.findings.iter().filter(|f| f.rule_id == "APO005").count(),
        1,
        "{:?}",
        r.findings
    );
}
#[test]
fn raw_orm_and_explicit_deserialization() {
    let f = Fixture::new();
    f.put("app.py","query = request.args['sql']\ndb.execute(text(query))\nyaml.unsafe_load(payload)\ntorch.load(path, weights_only=False)\ntorch.load(path, weights_only=True)\n");
    let r = f.scan();
    assert_eq!(
        r.findings.iter().filter(|f| f.rule_id == "APO011").count(),
        1,
        "{:?}",
        r.findings
    );
    assert_eq!(
        r.findings.iter().filter(|f| f.rule_id == "APO006").count(),
        2
    );
}

#[test]
fn fix_backup_is_byte_exact() {
    let f = Fixture::new();
    let original = "requests.get(url, verify=False)";
    f.put("app.py", original);
    assert!(f.cli(&["--fix"]).status.success());
    assert_eq!(
        fs::read(f.0.join("app.py.apollyon.bak")).unwrap(),
        original.as_bytes()
    );
    assert_eq!(
        fs::read_to_string(f.0.join("app.py")).unwrap(),
        "requests.get(url, verify=True)"
    );
    assert!(f.scan().findings.iter().all(|v| v.rule_id != "APO010"));
}
#[test]
fn dependency_snapshot_boundaries() {
    let f = Fixture::new();
    f.put("requirements.txt", "requests==2.19.0\n");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_apollyon"))
            .arg("deps")
            .arg(&f.0)
            .output()
            .unwrap()
    };
    let o = run();
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    f.put("requirements.txt", "requests==2.32.5\n");
    let clean = run();
    assert!(clean.status.success());
    let report: serde_json::Value = serde_json::from_slice(&clean.stdout).unwrap();
    assert_eq!(report["database_records"], 4);
    assert_eq!(report["database_retrieved"], "2026-09-08");
    assert!(report["scope"]
        .as_str()
        .unwrap()
        .contains("absence is not proof"));
    f.put("requirements.txt", "requests>=2.0\n");
    assert_eq!(run().status.code(), Some(3));
}
#[test]
fn automatic_baseline_can_be_disabled() {
    let f = Fixture::new();
    f.put("app.py", "eval(value)\n");
    let baseline = f.0.join("apollyon-baseline.json");
    assert!(f
        .cli(&["--write-baseline", baseline.to_str().unwrap()])
        .status
        .success());
    let o = f.cli(&["--json"]);
    assert!(String::from_utf8(o.stdout)
        .unwrap()
        .contains("\"baselined\":1"));
    let o = f.cli(&["--json", "--no-auto-baseline"]);
    assert!(String::from_utf8(o.stdout).unwrap().contains("\"new\":1"));
}

#[test]
fn sql_interpolation_and_component_scripts() {
    let f = Fixture::new();
    f.put("app.py", "name = request.args['name']\nquery = f'SELECT * FROM users WHERE name={name}'\ndb.execute(query)\n");
    f.put("app.vue", "<template><p>eval(text)</p></template>\n<script setup lang=\"ts\">\nconst input = req.body.code;\neval(input);\n</script>\n");
    f.put(
        "app.astro",
        "---\nconst input = req.body.code;\neval(input);\n---\n<p>eval(text)</p>\n",
    );
    let r = f.scan();
    assert_eq!(r.ast_files, 3);
    assert_eq!(
        r.findings.iter().filter(|v| v.rule_id == "APO011").count(),
        1
    );
    let calls: Vec<_> = r
        .findings
        .iter()
        .filter(|v| v.rule_id == "APO004")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .all(|v| v.confidence == apollyon::Confidence::Tainted));
}

#[test]
fn cli_help_documents_every_parser_flag() {
    let source = include_str!("../src/cli.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let help = include_str!("../docs/CLI.txt");
    for text in source
        .split('"')
        .filter(|s| s.starts_with("--") && s.chars().all(|c| c == '-' || c.is_ascii_lowercase()))
    {
        assert!(help.contains(text), "undocumented flag {text}");
    }
}
#[test]
fn malformed_dependency_inventory_is_incomplete() {
    let f = Fixture::new();
    f.put(
        "Cargo.lock",
        r#"version = 4
[[package]]
name = "missing-version"
"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .arg("deps")
        .arg(&f.0)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn fixes_only_real_requests_keyword_arguments() {
    let f = Fixture::new();
    f.put("app.py", "other(verify=False); requests.get(url, verify=False)\ntext = 'requests.get(url, verify=False)'\nrequests.get(url, myverify=False)\n");
    assert!(f.cli(&["--fix"]).status.success());
    assert_eq!(fs::read_to_string(f.0.join("app.py")).unwrap(),"other(verify=False); requests.get(url, verify=True)\ntext = 'requests.get(url, verify=False)'\nrequests.get(url, myverify=False)\n");
}

#[test]
fn node_shebang_is_not_an_unterminated_regex() {
    let f = Fixture::new();
    f.put(
        "app.cjs",
        "#!/usr/bin/env node\nconst input = req.body.code;\neval(input);\n",
    );
    let r = f.scan();
    assert!(r.complete, "{:?}", r.errors);
    assert_eq!(r.ast_files, 1);
    assert_eq!(
        r.findings.iter().filter(|f| f.rule_id == "APO004").count(),
        1
    );
}
