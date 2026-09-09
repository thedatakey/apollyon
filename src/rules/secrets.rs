//! Provider-shaped candidates. No network validation or credential use.
fn base62(value: &str) -> Option<u64> {
    value.bytes().try_fold(0u64, |n, c| {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'Z' => c - b'A' + 10,
            b'a'..=b'z' => c - b'a' + 36,
            _ => return None,
        };
        n.checked_mul(62)?.checked_add(digit as u64)
    })
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
pub(crate) fn provider(value: &str) -> bool {
    if value.len() > 8192 || !value.is_ascii() {
        return false;
    }
    if ["ghp_", "gho_", "ghu_", "ghr_", "npm_"]
        .iter()
        .any(|p| value.starts_with(p))
    {
        return value.len() == 40
            && value[4..34].bytes().all(|b| b.is_ascii_alphanumeric())
            && base62(&value[34..]) == Some(crc32(&value.as_bytes()[4..34]) as u64);
    }
    if let Some(suffix) = value.strip_prefix("AKIA") {
        return value.len() == 20
            && suffix
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    }
    if value.starts_with("AIza") {
        return value.len() == 39
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b));
    }
    let shapes: &[(&str, usize, usize)] = &[
        ("github_pat_", 82, 255),
        ("ghs_", 40, 4096),
        ("sk_live_", 32, 255),
        ("sk_test_", 32, 255),
        ("sk-ant-", 40, 255),
        ("sk-proj-", 40, 255),
        ("sk-", 32, 255),
        ("SG.", 60, 128),
        ("xoxb-", 20, 255),
        ("xoxp-", 20, 255),
        ("xoxa-", 20, 255),
        ("xoxr-", 20, 255),
        ("xoxs-", 20, 255),
        ("xapp-", 20, 255),
        ("shpat_", 38, 38),
        ("shpss_", 38, 38),
        ("glpat-", 26, 255),
        ("dop_v1_", 71, 71),
        ("pypi-AgEI", 32, 1024),
        ("hf_", 37, 255),
        ("sbp_", 44, 255),
    ];
    if shapes.iter().any(|(prefix, min, max)| {
        value.starts_with(prefix)
            && (*min..=*max).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-/+=.".contains(&b))
    }) {
        return true;
    }
    if [
        "postgres://",
        "postgresql://",
        "mongodb://",
        "mongodb+srv://",
    ]
    .iter()
    .any(|p| value.starts_with(p))
    {
        return value
            .split_once("://")
            .and_then(|(_, r)| r.split_once('@'))
            .and_then(|(auth, _)| auth.split_once(':'))
            .is_some_and(|(u, p)| !u.is_empty() && !p.is_empty() && !p.contains(['<', '{']));
    }
    // JWTs and Twilio account IDs alone are not proof of embedded secret material.
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_shapes() {
        assert!(provider("AKIAABCDEFGHIJKLMNOP"));
        assert!(!provider("AKIAshort"));
        // Synthetic account identifier, not an issued credential.
        assert!(!provider(&format!("AC{}", "0".repeat(32))));
        assert!(!provider("ghp_000000000000000000000000000000000000"));
        assert!(provider(
            "postgres://user:non-placeholder-password@localhost/db"
        ));
        assert!(!provider("postgres://user:<password>@localhost/db"));
    }
    #[test]
    fn valid_classic_checksum_and_mutation() {
        let body = "0123456789ABCDEFGHIJKLMNOPQRST";
        let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut value = crc32(body.as_bytes()) as usize;
        let mut encoded = [b'0'; 6];
        for index in (0..6).rev() {
            encoded[index] = alphabet[value % 62];
            value /= 62;
        }
        let token = format!("ghp_{}{}", body, std::str::from_utf8(&encoded).unwrap());
        assert!(provider(&token));
        let mut changed = token.into_bytes();
        changed[4] = b'Z';
        assert!(!provider(std::str::from_utf8(&changed).unwrap()));
    }
    #[test]
    fn checksum_vectors() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(base62("10"), Some(62));
    }
}
