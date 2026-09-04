//! Candidate case records for Phase 3 evidence workflows.

use crate::{render::json_string, Confidence, ScanReport};
use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseOptions {
    pub directory: PathBuf,
    pub repository: String,
    pub revision: String,
}

fn case_id(fingerprint: &str) -> String {
    let suffix: String = fingerprint
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(16)
        .collect();
    format!("APO-{}", suffix.to_ascii_uppercase())
}

fn render_case(finding: &crate::Finding, repository: &str, revision: &str, id: &str) -> String {
    let mut output = String::from("{\"schema\":\"apollyon.case/v1\",\"case_id\":");
    json_string(&mut output, id);
    output.push_str(
        ",\"status\":\"candidate\",\"transitions\":[\"candidate\"],\"scope\":{\"repository\":",
    );
    json_string(&mut output, repository);
    output.push_str(",\"revision\":");
    json_string(&mut output, revision);
    output.push_str(",\"authorized\":true},\"claim\":{\"summary\":");
    json_string(
        &mut output,
        &format!(
            "{} reached a modeled source-to-sink boundary; validate only under recorded assumptions",
            finding.rule_id
        ),
    );
    output.push_str(",\"affected_locations\":[{\"path\":");
    json_string(&mut output, &finding.path);
    let _ = write!(output, ",\"line\":{}}}]}}", finding.line);
    output.push_str(",\"evidence\":{\"discovery\":[{\"rule_id\":");
    json_string(&mut output, finding.rule_id);
    output.push_str(",\"fingerprint\":");
    json_string(&mut output, &finding.fingerprint);
    output.push_str(",\"engine\":");
    json_string(&mut output, finding.engine.as_str());
    output.push_str(",\"confidence\":");
    json_string(&mut output, finding.confidence.as_str());
    output.push_str(",\"trace\":[");
    for (index, step) in finding.trace.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"path\":");
        json_string(&mut output, &step.path);
        let _ = write!(output, ",\"line\":{},\"kind\":", step.line);
        json_string(&mut output, &step.kind);
        output.push('}');
    }
    output.push_str("]}],\"reproducer\":null,\"assumptions\":[\"Phase 2 bounded taint model only\",\"No target code has been executed\"]},\"remediation\":{\"patch\":null,\"regression_tests\":[]},\"verification\":{\"method\":null,\"command\":null,\"bounds\":[],\"tool_versions\":[],\"result\":\"not_run\"},\"limitations\":[\"Taint evidence is not proof of exploitability\",\"Validation requires a separately invoked isolated sandbox adapter\"]}");
    output
}

fn create_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        format!(
            "cannot create new case directory {}: {error}",
            path.display()
        )
    })
}

fn create_file(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create case record {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| format!("cannot write case record {}: {error}", path.display()))
}

pub(crate) fn write_candidates(
    report: &mut ScanReport,
    options: &CaseOptions,
) -> Result<usize, String> {
    create_directory(&options.directory)?;
    let result = (|| {
        let mut written = 0;
        for finding in &mut report.findings {
            if finding.confidence != Confidence::Tainted {
                continue;
            }
            let id = case_id(&finding.fingerprint);
            let filename = format!("{id}.json");
            let path = options.directory.join(&filename);
            let case = render_case(finding, &options.repository, &options.revision, &id);
            create_file(&path, &case)?;
            finding.case_refs.push(path.to_string_lossy().into_owned());
            written += 1;
        }
        Ok(written)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&options.directory);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Engine, Finding, Severity, TraceStep};

    #[test]
    fn writes_only_tainted_cases_into_a_new_private_directory() {
        let directory =
            std::env::temp_dir().join(format!("apollyon-case-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let mut report = ScanReport {
            complete: true,
            findings: vec![Finding {
                rule_id: "APO004",
                severity: Severity::High,
                message: "Dynamic execution requires review",
                path: "app.py".into(),
                line: 2,
                snippet: None,
                engine: Engine::Ast,
                confidence: Confidence::Tainted,
                trace: vec![TraceStep {
                    path: "app.py".into(),
                    line: 1,
                    kind: "source".into(),
                }],
                fingerprint: "0123456789abcdef0123".into(),
                case_refs: Vec::new(),
            }],
            ..ScanReport::default()
        };
        let options = CaseOptions {
            directory: directory.clone(),
            repository: "owner/repo".into(),
            revision: "working-tree".into(),
        };
        assert_eq!(write_candidates(&mut report, &options), Ok(1));
        let path = directory.join("APO-0123456789ABCDEF.json");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"schema\":\"apollyon.case/v1\""));
        assert!(contents.contains("\"authorized\":true"));
        assert!(contents.contains("\"reproducer\":null"));
        assert_eq!(report.findings[0].case_refs, vec![path.to_string_lossy()]);
        assert!(write_candidates(&mut report, &options).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
