//! The fixed lexical rule registry and family matchers.

pub(crate) mod deserialization;
pub(crate) mod exec;
pub(crate) mod memory;
mod patterns;

#[derive(Clone, Copy)]
pub(crate) struct RuleInfo {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) severity: Severity,
    pub(crate) message: &'static str,
    pub(crate) languages: &'static str,
}

pub(crate) const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "APO001",
        name: "unbounded-c-string-operation",
        severity: Severity::High,
        message: "Unbounded C string operation may permit memory corruption; use a length-aware API and verify destination bounds.",
        languages: "C and C++",
    },
    RuleInfo {
        id: "APO002",
        name: "manual-memory-copy-boundary",
        severity: Severity::Info,
        message: "Manual memory copy boundary requires review of source length, destination capacity, and overlap assumptions.",
        languages: "C and C++",
    },
    RuleInfo {
        id: "APO003",
        name: "rust-unsafe-boundary",
        severity: Severity::Medium,
        message: "Rust unsafe code requires a documented safety invariant and focused validation.",
        languages: "Rust",
    },
    RuleInfo {
        id: "APO004",
        name: "dynamic-code-execution",
        severity: Severity::High,
        message: "Dynamic code execution requires review of whether code or input can be influenced by an attacker.",
        languages: "JavaScript, TypeScript, Python, PHP, and Ruby",
    },
    RuleInfo {
        id: "APO005",
        name: "operating-system-command-boundary",
        severity: Severity::Medium,
        message: "Operating-system command execution requires review of argument separation, shell use, and untrusted input.",
        languages: "C, C++, C#, Go, Java, Kotlin, JavaScript, TypeScript, PHP, Python, Ruby, Rust, and Swift",
    },
    RuleInfo {
        id: "APO006",
        name: "unsafe-deserialization-boundary",
        severity: Severity::High,
        message: "Deserialization API may construct attacker-controlled objects; require a safe format, trusted input, or an explicit allowlist.",
        languages: "Python, Java, Kotlin, C#, PHP, and Ruby",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }

    pub(crate) fn sarif_level(self) -> &'static str {
        match self {
            Self::Info => "note",
            Self::Medium => "warning",
            Self::High => "error",
        }
    }
}

pub(crate) fn rule_info(id: &str) -> &'static RuleInfo {
    RULES
        .iter()
        .find(|rule| rule.id == id)
        .expect("scanner references a registered rule")
}
