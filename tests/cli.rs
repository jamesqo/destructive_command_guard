use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], input: Option<&[u8]>) -> Output {
    run_in(args, input, None)
}

fn run_in(args: &[&str], input: Option<&[u8]>, cwd: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().expect("dcg test binary should start");
    if let Some(bytes) = input {
        child
            .stdin
            .take()
            .expect("piped stdin should exist")
            .write_all(bytes)
            .expect("test input should be writable");
    }
    child.wait_with_output().expect("dcg should exit")
}

fn project_directory() -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock should be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("dcg-project-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(path.join(".git")).expect("test project should be created");
    path
}

#[test]
fn test_command_has_stable_exit_and_output_contracts() {
    let allowed = run(&["test", "git status"], None);
    assert_eq!(allowed.status.code(), Some(0));
    assert_eq!(allowed.stdout, b"ALLOW\n");
    assert!(allowed.stderr.is_empty());

    let denied = run(&["test", "--json", "git reset --hard"], None);
    assert_eq!(denied.status.code(), Some(1));
    assert!(denied.stderr.is_empty());
    let json: serde_json::Value =
        serde_json::from_slice(&denied.stdout).expect("deny output should be JSON");
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["rule_id"], "git.reset-destructive");

    let missing = run(&["test"], None);
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("usage:"));
}

#[test]
fn test_command_reads_candidate_from_stdin() {
    let output = run(&["test", "--stdin", "--json"], Some(b"rm -rf src"));
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("deny output should be JSON");
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["command"], "rm -rf src");
}

#[test]
fn hook_mode_denies_destructive_commands_and_allows_safe_ones_silently() {
    let denied = run(
        &[],
        Some(br#"{"turn_id":"turn-1","tool_name":"Bash","tool_input":{"command":"rm -rf src"}}"#),
    );
    assert_eq!(denied.status.code(), Some(0));
    assert!(denied.stderr.is_empty());
    let json: serde_json::Value =
        serde_json::from_slice(&denied.stdout).expect("hook denial should be JSON");
    let specific = &json["hookSpecificOutput"];
    assert_eq!(specific.as_object().map(serde_json::Map::len), Some(3));
    assert_eq!(specific["permissionDecision"], "deny");

    for input in [
        br#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#.as_slice(),
        b"malformed hook input".as_slice(),
    ] {
        let allowed = run(&[], Some(input));
        assert_eq!(allowed.status.code(), Some(0));
        assert!(allowed.stdout.is_empty());
    }
}

#[test]
fn oversized_hook_input_fails_closed_with_valid_json() {
    let input = vec![b'x'; destructive_command_guard::hook::MAX_INPUT_BYTES + 1];
    let output = run(&[], Some(&input));
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("oversize denial should be JSON");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("input.too-large"))
    );
}

#[test]
fn help_and_version_are_available() {
    for argument in ["--help", "--version"] {
        let output = run(&[argument], None);
        assert_eq!(output.status.code(), Some(0), "failed argument: {argument}");
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn project_policy_adds_denials_to_cli_and_hook() {
    let project = project_directory();
    std::fs::write(
        project.join(".dcg.toml"),
        r#"
            [[deny]]
            id = "no-prod-deploy"
            prefix = "deploy production"
            reason = "production deploys require the release workflow"
        "#,
    )
    .expect("project policy should be writable");

    let output = run_in(
        &["test", "--json", "deploy production --sha abc123"],
        None,
        Some(&project),
    );
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("project denial should be JSON");
    assert_eq!(json["rule_id"], "project.no-prod-deploy");

    let hook_input = serde_json::json!({
        "tool_name": "Bash",
        "cwd": project,
        "tool_input": { "command": "deploy production --sha abc123" }
    })
    .to_string();
    let output = run_in(&[], Some(hook_input.as_bytes()), Some(&project));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("hook project denial should be JSON");
    assert!(
        json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("project.no-prod-deploy"))
    );

    std::fs::write(project.join(".dcg.toml"), "unknown = true")
        .expect("invalid policy fixture should be writable");
    let invalid = run_in(&["test", "--json", "git status"], None, Some(&project));
    assert_eq!(invalid.status.code(), Some(1));
    let json: serde_json::Value =
        serde_json::from_slice(&invalid.stdout).expect("invalid-policy denial should be JSON");
    assert_eq!(json["rule_id"], "project-config.invalid");

    std::fs::remove_dir_all(project).expect("test project should be removable");
}
