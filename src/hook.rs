//! Claude Code and Codex hook protocol adapter.

use crate::{Decision, evaluate_in};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Maximum accepted hook payload size.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Process one Claude Code or Codex hook payload.
///
/// Allowed commands and unrelated tool calls return `Ok(None)`, which maps to
/// silent stdout. Denials use the minimal envelope accepted by both clients.
///
/// # Errors
///
/// Returns a JSON error when the input or generated response cannot be parsed
/// or serialized.
pub fn process(input: &str) -> Result<Option<String>, serde_json::Error> {
    let value: Value = serde_json::from_str(input.trim_start_matches('\u{feff}'))?;
    if value
        .get("tool_name")
        .or_else(|| value.get("toolName"))
        .and_then(Value::as_str)
        .is_some_and(|name| !is_shell_tool(name))
    {
        return Ok(None);
    }
    let Some(command) = extract_command(&value) else {
        return Ok(None);
    };
    let cwd = value
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let Decision::Deny { rule_id, reason } = evaluate_in(&command, &cwd) else {
        return Ok(None);
    };
    Ok(Some(denial(rule_id.as_ref(), reason.as_ref())))
}

/// Construct the shared minimal Claude/Codex denial envelope.
#[must_use]
pub fn denial(rule_id: &str, reason: &str) -> String {
    let reason = format!("BLOCKED by dcg ({rule_id}): {reason}");
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

fn is_shell_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "bash" | "shell" | "powershell" | "launch-process"
    )
}

fn extract_command(value: &Value) -> Option<String> {
    let tool_input = value.get("tool_input").or_else(|| value.get("toolInput"));
    if let Some(command) = tool_input.and_then(|input| input.get("command")) {
        return command_value(command);
    }

    let tool_args = value.get("tool_args").or_else(|| value.get("toolArgs"));
    if let Some(args) = tool_args {
        if let Some(command) = args.get("command") {
            return command_value(command);
        }
        if let Some(encoded) = args.as_str()
            && let Ok(decoded) = serde_json::from_str::<Value>(encoded)
            && let Some(command) = decoded.get("command")
        {
            return command_value(command);
        }
    }

    value.get("command").and_then(command_value)
}

fn command_value(value: &Value) -> Option<String> {
    if let Some(command) = value.as_str() {
        return Some(command.to_owned());
    }
    value.as_array().map(|parts| {
        parts
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    })
}

#[cfg(test)]
mod tests {
    use super::process;

    #[test]
    fn destructive_claude_payload_is_denied() {
        let output = process(r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#)
            .expect("valid input")
            .expect("denial");
        let json: serde_json::Value = serde_json::from_str(&output).expect("valid output");
        let specific = &json["hookSpecificOutput"];
        assert_eq!(specific.as_object().map(serde_json::Map::len), Some(3));
        assert_eq!(specific["hookEventName"], "PreToolUse");
        assert_eq!(specific["permissionDecision"], "deny");
    }

    #[test]
    fn codex_payload_uses_same_minimal_envelope() {
        let output = process(
            r#"{"turn_id":"turn-1","tool_name":"Bash","tool_input":{"command":"rm -rf src"}}"#,
        )
        .expect("valid input")
        .expect("denial");
        let json: serde_json::Value = serde_json::from_str(&output).expect("valid output");
        assert_eq!(
            json["hookSpecificOutput"]
                .as_object()
                .map(serde_json::Map::len),
            Some(3)
        );
    }

    #[test]
    fn safe_and_unrelated_inputs_are_silent() {
        assert_eq!(
            process(r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#)
                .expect("valid input"),
            None
        );
        assert_eq!(
            process(r#"{"tool_name":"Read","tool_input":{"command":"rm -rf src"}}"#)
                .expect("valid input"),
            None
        );
    }

    #[test]
    fn supported_input_shapes_extract_commands() {
        for input in [
            r#"{"toolName":"Bash","toolInput":{"command":"rm -rf src"}}"#,
            r#"{"tool_name":"Bash","tool_args":{"command":"git reset --hard"}}"#,
            r#"{"tool_name":"Bash","toolArgs":"{\"command\":\"find . -delete\"}"}"#,
            r#"{"tool_name":"Bash","tool_input":{"command":["git","clean","-fd"]}}"#,
            r#"{"command":"truncate -s 0 file"}"#,
            "\u{feff}{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"shred file\"}}",
        ] {
            assert!(
                process(input).expect("valid hook JSON").is_some(),
                "expected denial for payload: {input}"
            );
        }
    }

    #[test]
    fn malformed_and_commandless_inputs_are_handled() {
        assert!(process("not json").is_err());
        for input in [
            "{}",
            r#"{"tool_name":"Bash","tool_input":{}}"#,
            r#"{"tool_name":"Read","tool_input":{"command":"rm -rf src"}}"#,
        ] {
            assert_eq!(process(input).expect("valid hook JSON"), None);
        }
    }
}
