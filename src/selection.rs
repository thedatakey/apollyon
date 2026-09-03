//! File selection is read-only and treats Git output as bounded untrusted data.
use crate::scanner::read_bounded_regular_file;
use std::{
    collections::BTreeSet,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
const MAX_LIST: usize = 2 * 1024 * 1024;
fn normalize(value: &str) -> Result<String, String> {
    if value.contains(['\0', '\r']) || value.starts_with(['/', '\\']) || value.contains(':') {
        return Err("selected paths must be relative to the scan root".into());
    }
    crate::cli::normalize_exclude(value)
}
pub(crate) fn from_file(path: &Path) -> Result<BTreeSet<String>, String> {
    let bytes = read_bounded_regular_file(path).map_err(|_| "cannot read changed-files list")?;
    let source = std::str::from_utf8(&bytes).map_err(|_| "changed-files list must be UTF-8")?;
    source
        .lines()
        .filter(|line| !line.is_empty())
        .map(normalize)
        .collect()
}
pub(crate) fn from_git(root: &Path, reference: &str) -> Result<BTreeSet<String>, String> {
    if reference.is_empty() || reference.starts_with('-') || reference.contains('\0') {
        return Err("invalid git reference".into());
    }
    if !root.is_dir() {
        return Err("--diff requires a directory scan root".into());
    }
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .current_dir(root)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "--no-pager",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--relative",
            "--name-only",
            "-z",
            reference,
            "--",
            ".",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "cannot start git for --diff")?;
    let stdout = child.stdout.take().ok_or("cannot read git output")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((MAX_LIST + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = tx.send(result);
    });
    let start = Instant::now();
    let mut bytes = None;
    loop {
        if bytes.is_none() {
            if let Ok(result) = rx.try_recv() {
                bytes = Some(result.map_err(|_| "cannot read git output")?);
            }
        }
        if bytes.as_ref().is_some_and(|b| b.len() > MAX_LIST)
            || start.elapsed() > Duration::from_secs(10)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("git diff exceeded output or time bound".into());
        }
        if let Some(status) = child.try_wait().map_err(|_| "cannot wait for git")? {
            if !status.success() {
                return Err("git diff failed; check repository and reference".into());
            }
            let data = match bytes {
                Some(b) => b,
                None => rx
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| "git output unavailable")?
                    .map_err(|_| "cannot read git output")?,
            };
            if data.len() > MAX_LIST {
                return Err("git diff output exceeds bound".into());
            }
            let text = std::str::from_utf8(&data).map_err(|_| "git paths must be UTF-8")?;
            return text
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(normalize)
                .collect();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_escaping_paths() {
        for v in ["../outside", "/absolute", "C:\\outside", "a\0b"] {
            assert!(normalize(v).is_err());
        }
        assert_eq!(normalize("src/app.py").unwrap(), "src/app.py");
    }
}
