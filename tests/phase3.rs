use std::{fs, path::PathBuf, process::Command};

fn workspace(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("apollyon-phase3-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(path.join("source")).unwrap();
    path
}

#[test]
fn tainted_findings_create_authorized_candidate_cases_and_references() {
    let root = workspace("cases");
    fs::write(
        root.join("source/app.py"),
        "from flask import request\ndef calculate():\n    expression = request.args.get('expression')\n    return eval(expression)\n",
    )
    .unwrap();
    let cases = root.join("cases");
    let output = Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .args([
            "scan",
            root.join("source").to_str().unwrap(),
            "--format",
            "json",
            "--cases-dir",
            cases.to_str().unwrap(),
            "--authorized",
            "--repository",
            "fixture/phase3",
            "--revision",
            "test-revision",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("\"confidence\":\"tainted\""));
    assert!(report.contains("\"case_refs\":["));

    let case_path = fs::read_dir(&cases)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let case = fs::read_to_string(case_path).unwrap();
    assert!(case.contains("\"schema\":\"apollyon.case/v1\""));
    assert!(case.contains("\"status\":\"candidate\""));
    assert!(case.contains("\"authorized\":true"));
    assert!(case.contains("\"repository\":\"fixture/phase3\""));
    assert!(case.contains("\"revision\":\"test-revision\""));
    assert!(case.contains("\"reproducer\":null"));
    assert!(!case.contains("request.args.get('expression')"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn case_generation_requires_explicit_authorization() {
    let root = workspace("authorization");
    fs::write(root.join("source/app.py"), "eval(input())\n").unwrap();
    let cases = root.join("cases");
    let output = Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .args([
            "scan",
            root.join("source").to_str().unwrap(),
            "--cases-dir",
            cases.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires explicit --authorized"));
    assert!(!cases.exists());
    fs::remove_dir_all(root).unwrap();
}
