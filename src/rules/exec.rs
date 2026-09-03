//! Dynamic execution and operating-system command boundaries (APO004–APO005).

use super::{
    patterns::{contains_any_call, contains_any_ruby_command, contains_call},
    rule_info, RuleInfo,
};
use crate::lexer::Language;

pub(crate) fn match_rules(code: &str, language: Language, candidates: &mut Vec<&'static RuleInfo>) {
    let dynamic_execution = match language {
        Language::JavaScript => contains_any_call(code, &["eval", "Function"]),
        Language::Python => contains_any_call(code, &["eval", "exec"]),
        Language::Php => contains_call(code, "eval"),
        Language::Ruby => contains_any_ruby_command(
            code,
            &["eval", "class_eval", "instance_eval", "module_eval"],
        ),
        _ => false,
    };
    if dynamic_execution {
        candidates.push(rule_info("APO004"));
    }
    let shell_execution = match language {
        Language::CFamily => contains_any_call(code, &["system", "popen"]),
        Language::CSharp => contains_call(code, "Process.Start"),
        Language::JavaScript => {
            contains_any_call(code, &["child_process.exec", "child_process.execSync"])
        }
        Language::Go => contains_any_call(code, &["exec.Command", "exec.CommandContext"]),
        Language::Jvm => contains_any_call(code, &["ProcessBuilder", "Runtime.getRuntime().exec"]),
        Language::Php => contains_any_call(
            code,
            &[
                "exec",
                "passthru",
                "popen",
                "proc_open",
                "shell_exec",
                "system",
            ],
        ),
        Language::Python => contains_any_call(
            code,
            &[
                "os.popen",
                "os.system",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
                "subprocess.run",
            ],
        ),
        Language::Ruby => contains_any_ruby_command(code, &["exec", "spawn", "system"]),
        Language::Rust => contains_call(code, "Command::new"),
        Language::Swift => contains_call(code, "Process"),
    };
    if shell_execution {
        candidates.push(rule_info("APO005"));
    }
}
