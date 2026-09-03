//! Exact CLI snapshots based on d1dc52e, with reviewed Phase 1 additions.

use std::{path::Path, process::Command};

fn assert_golden(format: &str, extra: &[&str], expected: &[u8]) {
    let output = Command::new(env!("CARGO_BIN_EXE_apollyon"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["scan", "tests/fixtures/manual-project", "--format", format])
        .args(extra)
        .output()
        .expect("run Apollyon");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(output.stdout, expected);
}

macro_rules! golden {
    ($name:ident, $format:literal, $extra:expr, $snapshot:literal) => {
        #[test]
        fn $name() {
            assert_golden($format, $extra, include_bytes!($snapshot));
        }
    };
}

golden!(manual_text, "text", &[], "fixtures/golden/manual.text");
golden!(manual_json, "json", &[], "fixtures/golden/manual.json");
golden!(manual_sarif, "sarif", &[], "fixtures/golden/manual.sarif");
golden!(
    excluded_text,
    "text",
    &["--exclude", "generated"],
    "fixtures/golden/excluded.text"
);
golden!(
    excluded_json,
    "json",
    &["--exclude", "generated"],
    "fixtures/golden/excluded.json"
);
golden!(
    excluded_sarif,
    "sarif",
    &["--exclude", "generated"],
    "fixtures/golden/excluded.sarif"
);
golden!(
    snippets_text,
    "text",
    &["--include-snippets"],
    "fixtures/golden/snippets.text"
);
golden!(
    snippets_json,
    "json",
    &["--include-snippets"],
    "fixtures/golden/snippets.json"
);
golden!(
    snippets_sarif,
    "sarif",
    &["--include-snippets"],
    "fixtures/golden/snippets.sarif"
);

#[test]
fn cli_exit_codes_preserve_threshold_invocation_and_incomplete_contracts() {
    for (arguments, expected) in [
        (
            vec!["scan", "tests/fixtures/manual-project", "--fail-on", "high"],
            1,
        ),
        (vec!["--not-an-option"], 2),
        (vec!["scan", "tests/fixtures/manual-project/README.md"], 3),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_apollyon"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(arguments)
            .output()
            .expect("run Apollyon");
        assert_eq!(output.status.code(), Some(expected));
    }
}

#[test]
fn library_rendering_matches_the_cli_snapshot() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manual-project");
    let report = apollyon::scan_path(&root, false, &[]);
    assert!(report.complete);
    assert_eq!(
        apollyon::render_text(&report).as_bytes(),
        include_bytes!("fixtures/golden/manual.text")
    );
    assert_eq!(
        format!("{}\n", apollyon::render_json(&report)).as_bytes(),
        include_bytes!("fixtures/golden/manual.json")
    );
    assert_eq!(
        format!("{}\n", apollyon::render_sarif(&report)).as_bytes(),
        include_bytes!("fixtures/golden/manual.sarif")
    );
}
