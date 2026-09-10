//! User workflows. No fixture, hook, or scanned source is executed.
use crate::{
    display::safe_terminal,
    report::ScanReport,
    rules::{rule_info, Severity},
};
use std::{
    fs,
    io::IsTerminal,
    path::{Path, PathBuf},
};

pub(crate) fn classification(path: &str) -> &'static str {
    let p = path.to_ascii_lowercase();
    let components: Vec<_> = p.split('/').collect();
    if components
        .iter()
        .any(|s| ["vendor", "node_modules", "third_party", "deps"].contains(s))
    {
        "vendored"
    } else if p.contains(".min.") || p.contains(".generated.") || components.contains(&"generated")
    {
        "generated"
    } else if components
        .iter()
        .any(|s| ["examples", "example", "samples"].contains(s))
    {
        "example"
    } else if components
        .iter()
        .any(|s| ["test", "tests", "spec", "__tests__", "fixtures"].contains(s))
        || p.ends_with("_test.go")
        || p.contains(".test.")
        || p.contains(".spec.")
        || components
            .last()
            .is_some_and(|s| s.starts_with("test_") || *s == "conftest.py")
    {
        "test"
    } else {
        "production"
    }
}
fn safe_parent(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let normalized = crate::cli::normalize_exclude(relative)?;
    let mut parent = root.to_path_buf();
    if fs::symlink_metadata(root)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("root must not be a symlink".into());
    }
    let parts: Vec<_> = normalized.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        parent.push(part);
        match fs::symlink_metadata(&parent) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&parent).map_err(|e| e.to_string())?
            }
            _ => return Err("output parent must be a real directory".into()),
        }
    }
    Ok(parent.join(parts.last().unwrap()))
}
pub(crate) fn init(root: &Path, action: bool, hook: bool) -> Result<(), String> {
    if !root.is_dir() {
        return Err("init requires an existing project directory".into());
    }
    let stack = if root.join("package.json").is_file() {
        "JavaScript/TypeScript"
    } else if root.join("pyproject.toml").is_file() || root.join("requirements.txt").is_file() {
        "Python"
    } else if root.join("Cargo.toml").is_file() {
        "Rust"
    } else {
        "mixed source"
    };
    let mut files = vec![("apollyon.toml", format!("# Apollyon configuration for {stack}\n# Findings are review candidates.\nfail_on = \"high\"\njobs = 4\nmax_findings = 10000\n# Add project-specific exclusions explicitly.\nexcludes = []\n"))];
    if action {
        files.push((".github/workflows/apollyon.yml", "name: Apollyon\non: [push, pull_request]\npermissions:\n  contents: read\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          persist-credentials: false\n      - name: Scan with an administrator-installed trusted Apollyon binary\n        run: apollyon scan . --fail-on high\n".into()));
    }
    if hook {
        files.push((".pre-commit-config.apollyon.yaml", "# Merge this reviewed fragment into your pre-commit configuration.\nrepos:\n  - repo: local\n    hooks:\n      - id: apollyon\n        name: Apollyon source scan\n        entry: apollyon scan . --fail-on high\n        language: system\n        pass_filenames: false\n".into()));
    }
    let outputs: Vec<_> = files
        .iter()
        .map(|(name, _)| safe_parent(root, name))
        .collect::<Result<_, _>>()?;
    if outputs.iter().any(|p| fs::symlink_metadata(p).is_ok()) {
        return Err("init refuses to overwrite existing configuration".into());
    }
    for ((_, contents), path) in files.iter().zip(outputs) {
        crate::cli::emit_output(contents, Some(&path))?;
        println!("Created {}", safe_terminal(&path.display().to_string()));
    }
    Ok(())
}
pub(crate) fn explain(id: &str) -> String {
    let rule = rule_info(id);
    let (risky, safe) = match id {
        "APO001" => (
            "strcpy(dst, input);",
            "Check capacity and use a length-aware copy API.",
        ),
        "APO002" => (
            "memcpy(dst, src, n);",
            "Validate n against source and destination bounds.",
        ),
        "APO003" => (
            "unsafe { pointer.read() }",
            "Document validity, alignment, lifetime, and aliasing invariants.",
        ),
        "APO004" => (
            "eval(request.args['expression'])",
            "Parse a constrained data format or dispatch allowed operations.",
        ),
        "APO005" => (
            "subprocess.run('tool ' + value, shell=True)",
            "subprocess.run(['tool', '--', value], check=True)",
        ),
        "APO006" => ("yaml.unsafe_load(payload)", "yaml.safe_load(payload)"),
        "APO007" => (
            "JWT_SECRET = '<embedded credential>'",
            "JWT_SECRET = os.environ['JWT_SECRET']; rotate exposed credentials.",
        ),
        "APO008" => (
            "hashlib.md5(secret)",
            "Choose a modern algorithm for the actual security purpose.",
        ),
        "APO009" => (
            "token = Math.random()",
            "Use the platform cryptographic random generator.",
        ),
        "APO010" => (
            "requests.get(url, verify=False)",
            "requests.get(url, verify=True)",
        ),
        "APO011" => (
            "db.execute('SELECT * FROM users WHERE name=' + name)",
            "db.execute('SELECT * FROM users WHERE name=?', (name,))",
        ),
        "APO012" => (
            "open(request.args['path'])",
            "Resolve the path and enforce confinement to an allowed directory.",
        ),
        "APO013" => (
            "NEXT_PUBLIC_API_SECRET = '<credential>'",
            "Keep server credentials in server-only configuration.",
        ),
        "APO014" => (
            "app.run(debug=True)",
            "Disable interactive debugging in deployed environments.",
        ),
        "APO015" => (
            "element.innerHTML = req.body.content",
            "Use textContent for text, or a maintained HTML sanitizer.",
        ),
        "APO016" => (
            "requests.get(request.args['url'])",
            "Allowlist destinations and check addresses across redirects.",
        ),
        "APO017" => (
            "jwt.decode(token, verify=False)",
            "Verify signatures with fixed allowed algorithms, issuer, and audience.",
        ),
        "APO018" => (
            "{origin: '*', credentials: true}",
            "Use an explicit trusted-origin allowlist.",
        ),
        "APO019" => (
            "res.cookie('session', token, {secure: false})",
            "Set Secure, HttpOnly, and an appropriate SameSite policy.",
        ),
        "APO020" => (
            "SERVICE_ROLE = '<credential>'",
            "Keep privileged credentials server-side and rotate exposed values.",
        ),
        "APO021" => (
            "collection.find(req.body)",
            "Build allowed query fields from validated scalar inputs.",
        ),
        "APO022" => (
            "PythonREPLTool()",
            "Prefer constrained tools and isolate authorized execution with strict limits.",
        ),
        _ => (
            "Untrusted input reaches a sensitive operation or insecure configuration.",
            "Constrain input and use the platform's safe configuration/API.",
        ),
    };
    format!("{} — {}\n{}\n\nReview example:\n  {}\nSafer approach:\n  {}\n\nThis is bounded review guidance, not a vulnerability verdict.\n", rule.id, rule.name, rule.message, risky, safe)
}
pub(crate) fn text(report: &ScanReport, quiet: bool, color: Option<&str>) -> String {
    if quiet {
        return format!(
            "{}: {} findings; {}/{} files scanned\n",
            if report.complete {
                "complete"
            } else {
                "incomplete"
            },
            report.findings.len(),
            report.scanned_files,
            report.supported_files
        );
    }
    let mut output = crate::render_text(report);
    let colored = color == Some("always")
        || (color != Some("never")
            && std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none());
    if colored {
        output = output
            .replace("[HIGH]", "\u{1b}[31m[HIGH]\u{1b}[0m")
            .replace("[MEDIUM]", "\u{1b}[33m[MEDIUM]\u{1b}[0m");
    }
    output
}
fn md(value: &str) -> String {
    safe_terminal(value)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
}
pub(crate) fn markdown(report: &ScanReport) -> String {
    let mut output = format!("# Apollyon: {}\n\n{} findings; {}/{} files scanned. Findings require review.\n\n| Severity | Rule | Location | Review |\n| --- | --- | --- | --- |\n", if report.complete {"scan complete"}else{"scan incomplete"},report.findings.len(),report.scanned_files,report.supported_files);
    for f in &report.findings {
        output.push_str(&format!(
            "| {} | {} | {}:{} | {} |\n",
            f.severity.as_str(),
            f.rule_id,
            md(&f.path),
            f.line,
            md(f.message)
        ));
    }
    for error in &report.errors {
        output.push_str(&format!("\nCoverage error: {}\n", md(error)));
    }
    output
}
fn annotation(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}
pub(crate) fn annotations(report: &ScanReport, gitlab: bool) -> String {
    if gitlab {
        let mut out = String::from("[");
        for (i, f) in report.findings.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"description\":");
            crate::render::json_string(&mut out, f.message);
            out.push_str(",\"check_name\":");
            crate::render::json_string(&mut out, f.rule_id);
            out.push_str(",\"fingerprint\":");
            crate::render::json_string(&mut out, &f.fingerprint);
            out.push_str(",\"severity\":");
            crate::render::json_string(
                &mut out,
                if f.severity == Severity::High {
                    "critical"
                } else {
                    "minor"
                },
            );
            out.push_str(",\"location\":{\"path\":");
            crate::render::json_string(&mut out, &f.path);
            out.push_str(&format!(",\"lines\":{{\"begin\":{}}}}}}}", f.line));
        }
        out.push(']');
        return out;
    }
    let mut out = String::new();
    for f in &report.findings {
        out.push_str(&format!(
            "::{} file={},line={},title={}::{}\n",
            if f.severity == Severity::High {
                "error"
            } else {
                "warning"
            },
            annotation(&f.path),
            f.line,
            f.rule_id,
            annotation(f.message)
        ));
    }
    for error in &report.errors {
        out.push_str(&format!(
            "::error title=Apollyon coverage::{}\n",
            annotation(error)
        ));
    }
    out
}
pub(crate) fn fixes(root: &Path, report: &ScanReport, apply: bool) -> Result<(), String> {
    let base = if root.is_file() {
        root.parent().unwrap_or(Path::new("."))
    } else {
        root
    };
    let mut paths = std::collections::BTreeSet::new();
    let mut count = 0;
    for finding in &report.findings {
        if finding.rule_id != "APO010"
            || !finding.path.ends_with(".py")
            || !paths.insert(finding.path.clone())
        {
            continue;
        }
        let path = base.join(&finding.path);
        let original = crate::scanner::read_bounded_regular_file(&path)?;
        let source = std::str::from_utf8(&original).map_err(|_| "fix requires UTF-8")?;
        let analysis = crate::ast::analyze(&path, source, crate::lexer::Language::Python)?;
        let mut ranges = analysis.tls_fix_ranges;
        ranges.sort_by_key(|range| range.start);
        let mut changed = source.to_owned();
        for range in ranges.into_iter().rev() {
            changed.replace_range(range, "True");
        }
        if changed == source {
            continue;
        }
        count += 1;
        println!(
            "{} {}: enable requests certificate verification",
            if apply { "Fix" } else { "Proposed fix" },
            safe_terminal(&finding.path)
        );
        if apply {
            if crate::scanner::read_bounded_regular_file(&path)? != original {
                return Err("source changed during fix planning".into());
            }
            let backup = path.with_file_name(format!(
                "{}.apollyon.bak",
                path.file_name().unwrap().to_string_lossy()
            ));
            write_exact(&backup, &original)?;
            let temporary = path.with_file_name(format!(
                "{}.apollyon.new",
                path.file_name().unwrap().to_string_lossy()
            ));
            write_exact(&temporary, changed.as_bytes())?;
            fs::set_permissions(
                &temporary,
                fs::metadata(&path)
                    .map_err(|e| e.to_string())?
                    .permissions(),
            )
            .map_err(|e| e.to_string())?;
            fs::rename(temporary, path).map_err(|e| e.to_string())?;
        }
    }
    println!(
        "{count} file(s) {}; only the documented mechanical TLS fix is supported.",
        if apply {
            "updated with backups"
        } else {
            "proposed"
        }
    );
    Ok(())
}

fn write_exact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}
