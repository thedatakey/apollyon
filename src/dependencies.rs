//! Offline OSV matching. Unknown version/range syntax is reported, never assumed safe.
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path};
fn version(value: &str) -> Option<Vec<u64>> {
    let v = value.trim_start_matches('v').split('+').next()?;
    if v.contains('-') {
        return None;
    }
    let mut n = v
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if n.is_empty() || n.len() > 3 {
        return None;
    }
    while n.len() < 3 {
        n.push(0);
    }
    Some(n)
}
fn affected(record: &Value, ecosystem: &str, name: &str, v: &str) -> Result<bool, String> {
    if record.get("withdrawn").is_some() {
        return Ok(false);
    }
    let mut matched = false;
    for item in record["affected"]
        .as_array()
        .ok_or("advisory lacks affected array")?
    {
        if item["package"]["ecosystem"] != ecosystem || item["package"]["name"] != name {
            continue;
        }
        if item["versions"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == v))
        {
            matched = true;
            continue;
        }
        for range in item["ranges"].as_array().into_iter().flatten() {
            if !["SEMVER", "ECOSYSTEM"].contains(&range["type"].as_str().unwrap_or("")) {
                return Err(format!("unsupported advisory range for {name}"));
            }
            let current =
                version(v).ok_or_else(|| format!("unsupported version syntax for {name}"))?;
            let mut active = false;
            for event in range["events"]
                .as_array()
                .ok_or("advisory lacks range events")?
            {
                if let Some(start) = event["introduced"].as_str() {
                    active = start == "0"
                        || current >= version(start).ok_or("unsupported introduced version")?;
                } else if let Some(end) =
                    event["fixed"].as_str().or_else(|| event["limit"].as_str())
                {
                    if active && current < version(end).ok_or("unsupported fixed version")? {
                        matched = true;
                    }
                    active = false;
                } else if let Some(end) = event["last_affected"].as_str() {
                    if active
                        && current <= version(end).ok_or("unsupported last affected version")?
                    {
                        matched = true;
                    }
                    active = false;
                } else {
                    return Err("unsupported advisory event".into());
                }
            }
            matched |= active;
        }
    }
    Ok(matched)
}
fn packages(
    path: &Path,
    errors: &mut Vec<String>,
) -> Result<Vec<(String, String, String)>, String> {
    let bytes = crate::scanner::read_bounded_regular_file(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "manifest is not UTF-8")?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut out = Vec::new();
    match name {
        "package-lock.json" => {
            let data: Value =
                serde_json::from_str(text).map_err(|_| "invalid package lock JSON")?;
            let packages = data["packages"]
                .as_object()
                .ok_or("package-lock v2/v3 packages map required")?;
            for (key, p) in packages {
                if key.is_empty() {
                    continue;
                }
                if p["link"] == true {
                    errors.push(format!(
                        "npm workspace link requires explicit resolution at {key}"
                    ));
                } else if let Some(v) = p["version"].as_str() {
                    let name = p["name"]
                        .as_str()
                        .or_else(|| key.rsplit_once("node_modules/").map(|(_, n)| n));
                    if let Some(name) = name {
                        out.push(("npm".into(), name.into(), v.into()));
                    } else {
                        errors.push(format!("unresolved npm identity at {key}"));
                    }
                } else if p["link"] != true {
                    errors.push(format!("unresolved npm package at {key}"));
                }
            }
        }
        "requirements.txt" => {
            for (i, line) in text.lines().enumerate() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                if let Some((name, v)) = line.split_once("==") {
                    if !v.contains(['*', ';', ' ']) && !name.is_empty() {
                        out.push((
                            "PyPI".into(),
                            name.trim().to_ascii_lowercase().replace('_', "-"),
                            v.into(),
                        ));
                        continue;
                    }
                }
                errors.push(format!(
                    "requirements.txt:{} is not an exact supported pin",
                    i + 1
                ));
            }
        }
        "Cargo.lock" => {
            let mut name = None;
            let mut v = None;
            let mut in_package = false;
            for line in text.lines().chain(std::iter::once("[[package]]")) {
                let line = line.trim();
                if line == "[[package]]" {
                    match (name.take(), v.take()) {
                        (Some(n), Some(version)) => out.push(("crates.io".into(), n, version)),
                        _ if in_package => errors.push("incomplete Cargo package block".into()),
                        _ => {}
                    }
                    in_package = true;
                } else if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim().trim_matches('"').to_owned();
                    match key.trim() {
                        "name" => name = Some(value),
                        "version" => v = Some(value),
                        _ => {}
                    }
                }
            }
        }
        "go.mod" => {
            let mut group = false;
            for line in text.lines() {
                let line = line.split("//").next().unwrap_or("").trim();
                if line == "require (" {
                    group = true;
                    continue;
                }
                if line == ")" {
                    group = false;
                    continue;
                }
                let spec = if group {
                    Some(line)
                } else {
                    line.strip_prefix("require ")
                };
                if let Some(spec) = spec {
                    let parts: Vec<_> = spec.split_whitespace().collect();
                    if parts.len() == 2 {
                        out.push(("Go".into(), parts[0].into(), parts[1].into()));
                    } else if !spec.is_empty() {
                        errors.push("unsupported Go requirement".into());
                    }
                }
                if line.starts_with("replace ") {
                    errors
                        .push("Go replace directives require manual dependency resolution".into());
                }
            }
        }
        _ => {
            return Err(
                "supported manifests: package-lock.json, requirements.txt, Cargo.lock, go.mod"
                    .into(),
            )
        }
    }
    Ok(out)
}
pub(crate) fn run(root: &Path, database: Option<&Path>) -> Result<i32, String> {
    let bytes = if let Some(p) = database {
        crate::scanner::read_bounded_regular_file(p)?
    } else {
        include_bytes!("../data/osv-snapshot.json").to_vec()
    };
    let db: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid advisory JSON")?;
    let records = db
        .as_array()
        .or_else(|| db["records"].as_array())
        .ok_or("database requires an OSV array or records array")?;
    if records.len() > 10000 {
        return Err("advisory count exceeds 10000".into());
    }
    let mut errors = Vec::new();
    let paths = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        [
            "package-lock.json",
            "requirements.txt",
            "Cargo.lock",
            "go.mod",
        ]
        .iter()
        .map(|n| root.join(n))
        .filter(|p| fs::symlink_metadata(p).is_ok())
        .collect()
    };
    if paths.is_empty() {
        return Err("no supported dependency manifests found".into());
    }
    let mut inventory = BTreeSet::new();
    for path in &paths {
        match packages(path, &mut errors) {
            Ok(p) => inventory.extend(p),
            Err(e) => errors.push(e),
        }
    }
    let mut findings = Vec::new();
    for (ecosystem, name, v) in &inventory {
        for record in records {
            match affected(record,ecosystem,name,v){Ok(true)=>findings.push(json!({"id":record["id"],"ecosystem":ecosystem,"package":name,"version":v,"summary":record["summary"]})),Ok(false)=>{},Err(e)=>errors.push(e)}
        }
    }
    errors.sort();
    errors.dedup();
    println!(
        "{}",
        json!({"schema":"apollyon.dependencies/v1","complete":errors.is_empty(),"packages":inventory.len(),"manifests":paths.len(),"database_records":records.len(),"database_retrieved":db["retrieved"],"database_scope":db["scope"],"scope":"Matches only the supplied snapshot; absence is not proof of no vulnerable dependencies.","findings":findings,"errors":errors})
    );
    Ok(if !errors.is_empty() {
        3
    } else if !findings.is_empty() {
        1
    } else {
        0
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disjoint_ranges_and_fixed_boundary() {
        let r = json!({"affected":[{"package":{"ecosystem":"npm","name":"x"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"},{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}]}]});
        assert!(affected(&r, "npm", "x", "1.1.0").unwrap());
        assert!(!affected(&r, "npm", "x", "1.2.0").unwrap());
        assert!(affected(&r, "npm", "x", "2.0.5").unwrap());
        assert!(!affected(&r, "npm", "x", "2.1.0").unwrap());
        assert!(affected(&r, "npm", "x", "2.0.0-beta").is_err());
    }
}
