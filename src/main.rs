#![forbid(unsafe_code)]

use destructive_command_guard::{Decision, evaluate, hook};
use serde::Serialize;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("dcg: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        None => run_hook(),
        Some("test") => run_test(&args[1..]),
        Some("--version" | "-V" | "version") => {
            println!("dcg {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Some("--help" | "-h" | "help") => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        Some(command) => Err(format!("unknown command {command:?}; try `dcg --help`")),
    }
}

fn run_hook() -> Result<ExitCode, String> {
    let mut input = String::new();
    io::stdin()
        .take(u64::try_from(hook::MAX_INPUT_BYTES + 1).expect("input limit fits u64"))
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read hook input: {error}"))?;
    if input.len() > hook::MAX_INPUT_BYTES {
        println!(
            "{}",
            hook::denial(
                "input.too-large",
                "hook input exceeds 4 MiB and could not be evaluated"
            )
        );
        return Ok(ExitCode::SUCCESS);
    }
    if let Ok(Some(output)) = hook::process(&input) {
        println!("{output}");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_test(args: &[String]) -> Result<ExitCode, String> {
    let json = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--json" | "--format=json"))
        || args
            .windows(2)
            .any(|pair| pair[0] == "--format" && pair[1] == "json");
    let stdin = args.iter().any(|arg| arg == "--stdin");
    let mut skip_next = false;
    let positional: Vec<&str> = args
        .iter()
        .filter_map(|arg| {
            if skip_next {
                skip_next = false;
                return None;
            }
            if arg == "--format" {
                skip_next = true;
                return None;
            }
            (!matches!(arg.as_str(), "--json" | "--format=json" | "--stdin"))
                .then_some(arg.as_str())
        })
        .collect();
    let command = if stdin {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("failed to read command: {error}"))?;
        input
    } else {
        if positional.is_empty() {
            return Err("usage: dcg test [--json] <command>".to_owned());
        }
        positional.join(" ")
    };

    let decision = evaluate(&command);
    if json {
        println!(
            "{}",
            serde_json::to_string(&TestOutput::new(&command, decision))
                .expect("serializing static test output cannot fail")
        );
    } else {
        match decision {
            Decision::Allow => println!("ALLOW"),
            Decision::Deny { rule_id, reason } => {
                println!("DENY [{rule_id}] {reason}");
            }
        }
    }
    Ok(if decision.is_denied() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_help() {
    println!(
        "dcg — destructive command guard\n\n\
         Usage:\n  dcg                         Read a Claude/Codex hook payload from stdin\n  \
         dcg test [--json] <command> Evaluate a command without running it\n  \
         dcg --version               Print the version"
    );
}

#[derive(Serialize)]
struct TestOutput<'a> {
    command: &'a str,
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl<'a> TestOutput<'a> {
    const fn new(command: &'a str, decision: Decision) -> Self {
        match decision {
            Decision::Allow => Self {
                command,
                decision: "allow",
                rule_id: None,
                reason: None,
            },
            Decision::Deny { rule_id, reason } => Self {
                command,
                decision: "deny",
                rule_id: Some(rule_id),
                reason: Some(reason),
            },
        }
    }
}
