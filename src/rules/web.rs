//! Bounded web/configuration candidates; flow-sensitive sinks are gated by taint.
use super::{
    patterns::{contains_any_call, contains_token},
    rule_info, RuleInfo,
};
use crate::lexer::{Language, LineView};
pub(crate) fn match_rules(view: &LineView, _language: Language, out: &mut Vec<&'static RuleInfo>) {
    let compact = view.code.split_whitespace().collect::<String>();
    let visible = view.visible.as_str();
    let mut emit = |id| {
        if !out.iter().any(|r| r.id == id) {
            out.push(rule_info(id));
        }
    };
    if ["NEXT_PUBLIC_", "VITE_", "REACT_APP_"]
        .iter()
        .any(|p| view.code.contains(p))
        && super::adoption::secret_assignment(view)
    {
        emit("APO013");
    }
    if compact.contains("debug=True")
        || compact.contains("DEBUG=True")
        || compact.contains("debug:true")
        || compact.contains("DEBUG=true")
    {
        emit("APO014");
    }
    if compact.contains(".innerHTML=")
        || compact.contains("dangerouslySetInnerHTML")
        || compact.contains("v-html")
        || contains_any_call(&view.code, &["render_template_string", "document.write"])
    {
        emit("APO015");
    }
    if contains_any_call(
        &view.code,
        &[
            "requests.get",
            "requests.post",
            "requests.request",
            "fetch",
            "axios.get",
            "axios.post",
            "http.Get",
        ],
    ) {
        emit("APO016");
    }
    if (view.code.contains("jwt") || visible.contains("verify_signature"))
        && (compact.contains("verify=False")
            || compact.contains("verify:false")
            || (visible.contains("verify_signature")
                && (compact.contains("False") || compact.contains("false"))))
        || (visible.contains("algorithms")
            && view
                .literals
                .iter()
                .any(|s| s.trim_matches(['\'', '"']) == "none"))
    {
        emit("APO017");
    }
    if (visible.contains("Access-Control-Allow-Origin") || visible.contains("origin"))
        && view
            .literals
            .iter()
            .any(|s| s.trim_matches(['\'', '"']) == "*")
        && (compact.contains("credentials:true") || compact.contains("supports_credentials=True"))
    {
        emit("APO018");
    }
    if (view.code.to_ascii_lowercase().contains("cookie") || view.code.contains("session"))
        && [
            "secure:false",
            "secure=False",
            "httpOnly:false",
            "httponly=False",
            "cookie.secure=false",
        ]
        .iter()
        .any(|s| compact.contains(s))
    {
        emit("APO019");
    }
    if view.code.to_ascii_lowercase().contains("service_role")
        && super::adoption::secret_assignment(view)
    {
        emit("APO020");
    }
    if visible.contains("$where")
        || contains_any_call(
            &view.code,
            &["collection.find", "collection.findOne", "mongoose.find"],
        )
    {
        emit("APO021");
    }
    if contains_any_call(
        &view.code,
        &[
            "PythonREPLTool",
            "PythonAstREPLTool",
            "ShellTool",
            "BashProcess",
        ],
    ) {
        emit("APO022");
    }
    if contains_any_call(&view.code, &["torch.load"]) && compact.contains("weights_only=False") {
        emit("APO006");
    }
    if contains_token(&view.code, "crypto.createCipher") {
        emit("APO008");
    }
}
