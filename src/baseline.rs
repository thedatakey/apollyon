//! Bounded baseline files contain identifiers only, never source text.
use crate::{report::ScanReport, scanner::read_bounded_regular_file};
use std::{collections::BTreeSet, path::Path};
pub(crate) fn render(report: &ScanReport) -> String {
    let values: BTreeSet<_> = report
        .findings
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    format!(
        "{{\"schema\":\"apollyon.baseline/v1\",\"fingerprints\":[{}]}}",
        values
            .into_iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub(crate) fn parse(source: &str) -> Result<BTreeSet<String>, String> {
    // The writer emits a fixed schema. Accept whitespace only outside strings.
    let mut compact = String::new();
    let mut quoted = false;
    for c in source.chars() {
        if c == '"' {
            quoted = !quoted;
        }
        if quoted || !c.is_ascii_whitespace() {
            compact.push(c);
        }
    }
    let inner = compact
        .strip_prefix("{\"schema\":\"apollyon.baseline/v1\",\"fingerprints\":[")
        .and_then(|s| s.strip_suffix("]}"))
        .ok_or("unsupported baseline schema or syntax")?;
    let mut result = BTreeSet::new();
    if inner.is_empty() {
        return Ok(result);
    }
    for item in inner.split(',') {
        let value = item
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or("invalid baseline fingerprint")?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid baseline fingerprint".into());
        }
        result.insert(value.to_owned());
        if result.len() > 10000 {
            return Err("baseline exceeds 10000 entries".into());
        }
    }
    Ok(result)
}
pub(crate) fn load(path: &Path) -> Result<BTreeSet<String>, String> {
    let bytes =
        read_bounded_regular_file(path).map_err(|_| "cannot read bounded regular baseline file")?;
    parse(std::str::from_utf8(&bytes).map_err(|_| "baseline must be UTF-8")?)
}
pub(crate) fn apply(report: &mut ScanReport, baseline: &BTreeSet<String>) {
    report.findings.retain(|f| {
        if baseline.contains(&f.fingerprint) {
            report.baselined_findings += 1;
            false
        } else {
            true
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_baselines() {
        for s in [
            "{}",
            "[]",
            "{\"schema\":\"apollyon.baseline/v2\",\"fingerprints\":[]}",
            "{\"schema\":\"apollyon.baseline/v1\",\"fingerprints\":[\"secret\"]}",
        ] {
            assert!(parse(s).is_err());
        }
    }
    #[test]
    fn accepts_empty() {
        assert!(
            parse(" { \"schema\" : \"apollyon.baseline/v1\", \"fingerprints\": [] } ")
                .unwrap()
                .is_empty()
        );
    }
}
