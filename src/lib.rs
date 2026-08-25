#![forbid(unsafe_code)]
//! A deliberately small destructive-command classifier.
//!
//! `dcg` is a guardrail for well-intentioned coding agents, not a security
//! boundary. It recognizes a focused set of commands likely to destroy source
//! code, uncommitted Git work, or filesystems.

pub mod hook;

use serde::Deserialize;
use std::path::{Path, PathBuf};

const MAX_PROJECT_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PROJECT_RULES: usize = 64;

/// The result of evaluating one shell command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    /// No retained rule matched.
    Allow,
    /// A destructive operation matched.
    Deny {
        /// Stable identifier for the matching rule.
        rule_id: String,
        /// Short explanation suitable for an agent.
        reason: String,
    },
}

impl Decision {
    /// Whether execution should be blocked.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

#[derive(Debug)]
struct ProjectRules {
    deny: Vec<ProjectRule>,
}

#[derive(Debug)]
struct ProjectRule {
    id: String,
    reason: String,
    matcher: ProjectMatcher,
}

#[derive(Debug)]
enum ProjectMatcher {
    Exact(String),
    Prefix(String),
    Contains(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectFile {
    #[serde(default)]
    deny: Vec<ProjectRuleFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRuleFile {
    id: String,
    reason: String,
    exact: Option<String>,
    prefix: Option<String>,
    contains: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    Boundary,
}

/// Evaluate a shell command without executing it.
#[must_use]
pub fn evaluate(command: &str) -> Decision {
    let tokens = lex(command);
    for segment in tokens.split(|token| matches!(token, Token::Boundary)) {
        let words: Vec<&str> = segment
            .iter()
            .filter_map(|token| match token {
                Token::Word(word) if !word.is_empty() => Some(word.as_str()),
                _ => None,
            })
            .collect();
        if let Some(decision) = evaluate_words(&words) {
            return decision;
        }
    }
    Decision::Allow
}

/// Evaluate a command with the nearest repository-local `.dcg.toml` policy.
///
/// Project policy can only add denials; it cannot weaken built-in rules. An
/// invalid or unreadable policy fails closed with `project-config.invalid`.
///
/// # Examples
///
/// ```
/// use destructive_command_guard::evaluate_in;
///
/// let decision = evaluate_in("git status", std::path::Path::new("."));
/// assert!(!decision.is_denied());
/// ```
#[must_use]
pub fn evaluate_in(command: &str, cwd: &Path) -> Decision {
    let builtin = evaluate(command);
    if builtin.is_denied() {
        return builtin;
    }

    match load_project_rules(cwd) {
        Ok(Some(rules)) => evaluate_with_rules(command, &rules),
        Ok(None) => Decision::Allow,
        Err(reason) => Decision::Deny {
            rule_id: "project-config.invalid".to_owned(),
            reason,
        },
    }
}

fn load_project_rules(cwd: &Path) -> Result<Option<ProjectRules>, String> {
    let Some(path) = find_project_config(cwd) else {
        return Ok(None);
    };
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.len() > MAX_PROJECT_CONFIG_BYTES {
        return Err(format!(
            "{} exceeds the 64 KiB project-policy limit",
            path.display()
        ));
    }
    let input = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if input.len() as u64 > MAX_PROJECT_CONFIG_BYTES {
        return Err(format!(
            "{} exceeds the 64 KiB project-policy limit",
            path.display()
        ));
    }
    parse_project_rules(&input).map(Some)
}

fn find_project_config(cwd: &Path) -> Option<PathBuf> {
    for directory in cwd.ancestors() {
        let candidate = directory.join(".dcg.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if directory.join(".git").exists() {
            break;
        }
    }
    None
}

fn parse_project_rules(input: &str) -> Result<ProjectRules, String> {
    let file: ProjectFile =
        toml::from_str(input).map_err(|error| format!("invalid .dcg.toml: {error}"))?;
    if file.deny.len() > MAX_PROJECT_RULES {
        return Err(format!(
            ".dcg.toml contains more than {MAX_PROJECT_RULES} deny rules"
        ));
    }

    let mut rules = Vec::with_capacity(file.deny.len());
    for source in file.deny {
        validate_rule_id(&source.id)?;
        if source.reason.trim().is_empty() || source.reason.len() > 512 {
            return Err(format!(
                "project rule {:?} needs a reason of 1 to 512 bytes",
                source.id
            ));
        }
        if rules.iter().any(|rule: &ProjectRule| rule.id == source.id) {
            return Err(format!("duplicate project rule id {:?}", source.id));
        }

        let matchers = [
            source.exact.map(ProjectMatcher::Exact),
            source.prefix.map(ProjectMatcher::Prefix),
            source.contains.map(ProjectMatcher::Contains),
        ];
        let mut matchers = matchers.into_iter().flatten();
        let Some(matcher) = matchers.next() else {
            return Err(format!(
                "project rule {:?} needs exactly one of exact, prefix, or contains",
                source.id
            ));
        };
        if matchers.next().is_some() {
            return Err(format!(
                "project rule {:?} has more than one matcher",
                source.id
            ));
        }
        let pattern = match &matcher {
            ProjectMatcher::Exact(pattern)
            | ProjectMatcher::Prefix(pattern)
            | ProjectMatcher::Contains(pattern) => pattern,
        };
        if pattern.trim().is_empty() || pattern.len() > 1024 {
            return Err(format!(
                "project rule {:?} needs a matcher of 1 to 1024 bytes",
                source.id
            ));
        }
        rules.push(ProjectRule {
            id: source.id,
            reason: source.reason,
            matcher,
        });
    }
    Ok(ProjectRules { deny: rules })
}

fn validate_rule_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(format!(
            "invalid project rule id {id:?}; use 1 to 64 lowercase ASCII letters, digits, '.', '-', or '_'"
        ));
    }
    Ok(())
}

fn evaluate_with_rules(command: &str, rules: &ProjectRules) -> Decision {
    let command = command.trim();
    for rule in &rules.deny {
        let matched = match &rule.matcher {
            ProjectMatcher::Exact(pattern) => command == pattern,
            ProjectMatcher::Prefix(pattern) => command
                .strip_prefix(pattern)
                .is_some_and(|rest| rest.is_empty() || starts_shell_boundary(rest)),
            ProjectMatcher::Contains(pattern) => command.contains(pattern),
        };
        if matched {
            return Decision::Deny {
                rule_id: format!("project.{}", rule.id),
                reason: rule.reason.clone(),
            };
        }
    }
    Decision::Allow
}

fn starts_shell_boundary(rest: &str) -> bool {
    rest.chars().next().is_some_and(|character| {
        character.is_whitespace() || matches!(character, ';' | '|' | '&' | '<' | '>' | '(' | ')')
    })
}

fn evaluate_words(words: &[&str]) -> Option<Decision> {
    let words = strip_prefixes(words);
    let (&program, args) = words.split_first()?;
    let program = program_name(program);

    if matches!(program.as_str(), "sh" | "bash" | "zsh" | "dash" | "fish")
        && let Some(script) = shell_script(args)
    {
        let decision = evaluate(script);
        return decision.is_denied().then_some(decision);
    }
    if matches!(program.as_str(), "pwsh" | "powershell")
        && let Some(script) = argument_value(args, &["-c", "-command"])
    {
        let decision = evaluate(script);
        return decision.is_denied().then_some(decision);
    }
    if program == "cmd"
        && let Some(script) = argument_value(args, &["/c"])
    {
        let decision = evaluate(script);
        return decision.is_denied().then_some(decision);
    }

    match program.as_str() {
        "rm" => evaluate_rm(args),
        "git" => evaluate_git(args),
        "find" => has_arg(args, "-delete").then_some(deny(
            "filesystem.find-delete",
            "find -delete recursively removes matched paths",
        )),
        "shred"
            if !args
                .iter()
                .any(|arg| matches!(*arg, "--help" | "--version")) =>
        {
            Some(deny(
                "filesystem.shred",
                "shred irreversibly overwrites file contents",
            ))
        }
        "mkfs" | "mkfs.ext2" | "mkfs.ext3" | "mkfs.ext4" | "mkfs.xfs" | "mkfs.btrfs" => Some(deny(
            "filesystem.format",
            "filesystem formatting destroys existing data",
        )),
        "dd" => args
            .iter()
            .any(|arg| arg.starts_with("of="))
            .then_some(deny(
                "filesystem.dd-output",
                "dd with an output target can overwrite a device or file",
            )),
        "truncate" => evaluate_truncate(args),
        "xargs" => evaluate_words(strip_wrapper(
            words,
            &["-a", "--arg-file", "-E", "-I", "-L", "-n", "-P", "-s"],
        )),
        "remove-item" => powershell_recursive(args).then_some(deny(
            "filesystem.remove-item-recursive",
            "recursive Remove-Item can delete directory trees",
        )),
        "rd" | "rmdir" => windows_recursive(args).then_some(deny(
            "filesystem.rmdir-recursive",
            "recursive directory removal can delete directory trees",
        )),
        "del" | "erase" => windows_recursive(args).then_some(deny(
            "filesystem.del-recursive",
            "recursive deletion can remove directory trees",
        )),
        _ => None,
    }
}

fn evaluate_rm(args: &[&str]) -> Option<Decision> {
    let recursive = args.iter().any(|arg| {
        *arg == "--recursive"
            || (arg.starts_with('-')
                && !arg.starts_with("--")
                && arg[1..].chars().any(|flag| matches!(flag, 'r' | 'R')))
    });
    recursive.then_some(deny(
        "filesystem.rm-recursive",
        "recursive rm can delete an entire directory tree",
    ))
}

fn evaluate_git(args: &[&str]) -> Option<Decision> {
    let args = strip_git_globals(args);
    let (&subcommand, rest) = args.split_first()?;
    match subcommand {
        "reset" if has_arg(rest, "--hard") || has_arg(rest, "--merge") => Some(deny(
            "git.reset-destructive",
            "git reset can discard uncommitted changes",
        )),
        "clean" if clean_deletes(rest) => Some(deny(
            "git.clean",
            "git clean permanently deletes untracked files",
        )),
        "checkout" if checkout_overwrites(rest) => Some(deny(
            "git.checkout-overwrite",
            "git checkout can overwrite working-tree changes",
        )),
        "restore" if restore_overwrites(rest) => Some(deny(
            "git.restore-overwrite",
            "git restore can discard working-tree changes",
        )),
        "branch"
            if has_short_flag(rest, 'D')
                || has_short_flag(rest, 'M')
                || has_short_flag(rest, 'C')
                || (has_short_flag(rest, 'd') && has_short_flag(rest, 'f')) =>
        {
            Some(deny(
                "git.branch-force-delete",
                "forcing a branch ref update can discard existing work",
            ))
        }
        "branch" if has_arg(rest, "--delete") && has_arg(rest, "--force") => Some(deny(
            "git.branch-force-delete",
            "forcing branch deletion can discard unmerged work",
        )),
        "push"
            if rest.iter().any(|arg| {
                arg.starts_with("--force-with-lease")
                    || matches!(*arg, "--force" | "--force-if-includes")
                    || has_short_flag(&[*arg], 'f')
            }) =>
        {
            Some(deny(
                "git.push-force",
                "force-pushing can overwrite remote branch history",
            ))
        }
        "stash"
            if rest
                .first()
                .is_some_and(|arg| matches!(*arg, "drop" | "clear")) =>
        {
            Some(deny(
                "git.stash-delete",
                "this command permanently removes Git stashes",
            ))
        }
        "reflog" if rest.first() == Some(&"expire") => Some(deny(
            "git.reflog-expire",
            "expiring the reflog removes a recovery path",
        )),
        "gc" if rest.iter().any(|arg| arg.starts_with("--prune")) => Some(deny(
            "git.gc-prune",
            "pruning Git objects can remove recovery data",
        )),
        _ => None,
    }
}

fn strip_git_globals<'a>(mut args: &'a [&'a str]) -> &'a [&'a str] {
    while let Some(arg) = args.first() {
        if matches!(
            *arg,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace"
        ) {
            args = args.get(2..).unwrap_or_default();
        } else if arg.starts_with("--git-dir=")
            || arg.starts_with("--work-tree=")
            || arg.starts_with("--namespace=")
            || matches!(
                *arg,
                "-p" | "--paginate"
                    | "-P"
                    | "--no-pager"
                    | "--bare"
                    | "--no-replace-objects"
                    | "--literal-pathspecs"
                    | "--glob-pathspecs"
                    | "--noglob-pathspecs"
                    | "--icase-pathspecs"
            )
        {
            args = &args[1..];
        } else {
            break;
        }
    }
    args
}

fn clean_deletes(args: &[&str]) -> bool {
    args.iter().any(|arg| {
        *arg == "--force"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('f'))
    }) && !has_arg(args, "--dry-run")
        && !has_short_flag(args, 'n')
}

fn checkout_overwrites(args: &[&str]) -> bool {
    has_short_flag(args, 'f')
        || has_arg(args, "--force")
        || args
            .iter()
            .position(|arg| *arg == "--")
            .is_some_and(|index| args.get(index + 1).is_some())
}

fn restore_overwrites(args: &[&str]) -> bool {
    has_arg(args, "--worktree")
        || has_short_flag(args, 'W')
        || (!has_arg(args, "--staged")
            && !has_short_flag(args, 'S')
            && args
                .iter()
                .any(|arg| !arg.starts_with('-') || arg.starts_with("--source=")))
}

fn evaluate_truncate(args: &[&str]) -> Option<Decision> {
    args.iter()
        .enumerate()
        .any(|(index, arg)| {
            let size = if matches!(*arg, "-s" | "--size") {
                args.get(index + 1).copied()
            } else {
                arg.strip_prefix("--size=")
                    .or_else(|| arg.strip_prefix("-s").filter(|size| !size.is_empty()))
            };
            size.is_some_and(|size| size == "0" || size.starts_with('-'))
        })
        .then_some(deny(
            "filesystem.truncate-zero",
            "truncating a file to zero bytes destroys its contents",
        ))
}

fn strip_prefixes<'a>(mut words: &'a [&'a str]) -> &'a [&'a str] {
    while let Some(word) = words.first() {
        if is_assignment(word) {
            words = &words[1..];
            continue;
        }
        match program_name(word).as_str() {
            "sudo" | "doas" => {
                words = strip_wrapper(
                    words,
                    &[
                        "-u",
                        "--user",
                        "-g",
                        "--group",
                        "-h",
                        "--host",
                        "-p",
                        "--prompt",
                        "-C",
                        "--close-from",
                        "-R",
                        "--chroot",
                        "-t",
                    ],
                );
            }
            "env" => {
                words = strip_wrapper(words, &["-u", "--unset", "-C", "--chdir", "-S"]);
            }
            "nice" => words = strip_wrapper(words, &["-n", "--adjustment"]),
            "command" | "builtin" | "nohup" | "time" => words = strip_wrapper(words, &[]),
            "timeout" => {
                words = strip_wrapper(words, &["-s", "--signal", "-k", "--kill-after"]);
                if words.first().is_some_and(|word| looks_like_duration(word)) {
                    words = &words[1..];
                }
            }
            "watch" => words = strip_wrapper(words, &["-n", "--interval"]),
            _ => break,
        }
    }
    words
}

fn strip_wrapper<'a>(words: &'a [&'a str], value_flags: &[&str]) -> &'a [&'a str] {
    let mut index = 1;
    while let Some(word) = words.get(index) {
        if *word == "--" {
            index += 1;
            break;
        }
        if value_flags.contains(word) {
            index += 2;
        } else if word.starts_with('-') || is_assignment(word) {
            index += 1;
        } else {
            break;
        }
    }
    &words[index..]
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
            && !name.starts_with(|character: char| character.is_ascii_digit())
    })
}

fn looks_like_duration(word: &str) -> bool {
    word.chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
}

fn shell_script<'a>(args: &'a [&'a str]) -> Option<&'a str> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(script) = arg.strip_prefix("-c")
            && !script.is_empty()
        {
            return Some(script);
        }
        if (*arg == "-c"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c')))
            && let Some(script) = args.get(index + 1)
        {
            return Some(script);
        }
    }
    None
}

fn argument_value<'a>(args: &'a [&'a str], flags: &[&str]) -> Option<&'a str> {
    args.windows(2).find_map(|pair| {
        flags
            .iter()
            .any(|flag| pair[0].eq_ignore_ascii_case(flag))
            .then_some(pair[1])
    })
}

fn has_arg(args: &[&str], expected: &str) -> bool {
    args.contains(&expected)
}

fn has_short_flag(args: &[&str], expected: char) -> bool {
    args.iter()
        .any(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(expected))
}

fn powershell_recursive(args: &[&str]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.to_ascii_lowercase().as_str(), "-recurse" | "-r"))
}

fn windows_recursive(args: &[&str]) -> bool {
    args.iter().any(|arg| arg.eq_ignore_ascii_case("/s"))
}

fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

fn program_name(program: &str) -> String {
    let name = basename(program).to_ascii_lowercase();
    name.strip_suffix(".exe")
        .map_or_else(|| name.clone(), std::borrow::ToOwned::to_owned)
}

fn deny(rule_id: &str, reason: &str) -> Decision {
    Decision::Deny {
        rule_id: rule_id.to_owned(),
        reason: reason.to_owned(),
    }
}

fn lex(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut chars = input.chars().peekable();
    let mut quote = None;

    while let Some(character) = chars.next() {
        if let Some(delimiter) = quote {
            match character {
                '\\' if delimiter == '"' => {
                    if let Some(escaped) = chars.next() {
                        word.push(escaped);
                    }
                }
                value if value == delimiter => quote = None,
                value => word.push(value),
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '\\' => {
                if let Some(escaped) = chars.next() {
                    word.push(escaped);
                }
            }
            ' ' | '\t' | '\r' => push_word(&mut tokens, &mut word),
            '\n' | ';' | '|' | '&' => {
                push_word(&mut tokens, &mut word);
                tokens.push(Token::Boundary);
                if chars.peek() == Some(&character) {
                    chars.next();
                }
            }
            '#' if word.is_empty() => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        tokens.push(Token::Boundary);
                        break;
                    }
                }
            }
            value => word.push(value),
        }
    }
    push_word(&mut tokens, &mut word);
    tokens
}

fn push_word(tokens: &mut Vec<Token>, word: &mut String) {
    if !word.is_empty() {
        tokens.push(Token::Word(std::mem::take(word)));
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, evaluate, evaluate_with_rules, parse_project_rules};

    fn denied(command: &str) {
        assert!(evaluate(command).is_denied(), "expected denial: {command}");
    }

    fn allowed(command: &str) {
        assert_eq!(
            evaluate(command),
            Decision::Allow,
            "expected allow: {command}"
        );
    }

    #[test]
    fn blocks_retained_destructive_commands() {
        for command in [
            "git reset --hard HEAD~1",
            "git reset --merge HEAD~1",
            "git -C repo clean -fdx",
            "git clean --force -d",
            "git checkout -- .",
            "git checkout -f main",
            "git restore .",
            "git restore --staged --worktree file",
            "git branch -D work",
            "git branch --delete --force work",
            "git branch -df work",
            "git branch -M main",
            "git push --force origin main",
            "git push --force-with-lease=main origin main",
            "git stash clear",
            "git stash drop stash@{0}",
            "git reflog expire --expire=now --all",
            "git gc --prune=now",
            "rm -rf ./src",
            "/bin/rm --recursive src",
            "sudo rm -R important",
            "nice rm -rf /",
            "sudo -u root rm -rf /",
            "env -u DEBUG rm -rf /",
            "nice -n 10 rm -rf /",
            "timeout --signal TERM 10s rm -rf /",
            "watch -n 2 rm -rf /",
            "FOO=bar sh -c 'echo hi; rm -rf /'",
            "bash -lc 'git reset --hard'",
            "sh -c'rm -rf /'",
            "git --no-pager reset --hard",
            "git.exe reset --hard",
            "pwsh -Command 'Remove-Item -Recurse src'",
            "cmd.exe /c 'rd /s src'",
            "xargs -a paths rm -rf",
            "find . -name '*.tmp' -delete",
            "shred secrets.txt",
            "mkfs.ext4 /dev/sda1",
            "truncate -s 0 important.txt",
            "truncate -s0 important.txt",
            "truncate --size=-1 important.txt",
            "dd if=/dev/zero of=/dev/sda",
            "Remove-Item -Recurse -Force src",
            "del /s build",
            "echo ready && git reset --hard",
            "echo ready\nrm -rf src",
        ] {
            denied(command);
        }
    }

    #[test]
    fn allows_ordinary_and_quoted_mentions() {
        for command in [
            "git status",
            "git reset --soft HEAD~1",
            "git clean -ndx",
            "git clean --force --dry-run",
            "git checkout -b feature",
            "git restore --staged file",
            "git restore -S file",
            "git branch -d merged-feature",
            "git push origin main",
            "git stash list",
            "git stash pop",
            "git reflog show",
            "git gc",
            "rm file.txt",
            "rm -f build.log",
            "echo 'never run rm -rf /'",
            "printf '%s' 'git reset --hard'",
            "find . -name '*.rs' -print",
            "truncate -s 10 file",
            "shred --help",
            "dd if=image.iso status=progress",
            "echo ok # rm -rf src",
            "printf '%s' \"git push --force origin main\"",
        ] {
            allowed(command);
        }
    }

    #[test]
    fn gas_city_approval_wrapper_is_not_a_reusable_bypass() {
        allowed("gc approval exec permit-123 -- rm -rf src");
        allowed("gc approval show permit-123 --json");
        denied("DCG_APPROVAL_TOKEN=permit-123 rm -rf src");
        denied("DCG_ALLOW_DESTRUCTIVE=1 git reset --hard");
        denied("rm -rf src");
    }

    #[test]
    fn project_rules_support_one_explicit_match_shape() {
        let rules = parse_project_rules(
            r#"
                [[deny]]
                id = "no-prod-deploy"
                prefix = "deploy production"
                reason = "production deploys require the release workflow"

                [[deny]]
                id = "no-reset-script"
                exact = "./scripts/reset-state"
                reason = "state reset is intentionally manual"

                [[deny]]
                id = "protect-account"
                contains = "--account production"
                reason = "production account operations require review"
            "#,
        )
        .expect("valid project rules");

        for command in [
            "deploy production --sha abc123",
            "./scripts/reset-state",
            "tool sync --account production --dry-run",
        ] {
            let decision = evaluate_with_rules(command, &rules);
            assert!(decision.is_denied(), "expected project denial: {command}");
        }
        assert_eq!(
            evaluate_with_rules("deploy production-like", &rules),
            Decision::Allow
        );
    }

    #[test]
    fn project_rules_reject_ambiguous_or_invalid_policy() {
        for policy in [
            "[[deny]]\nid = \"x\"\nreason = \"missing matcher\"",
            "[[deny]]\nid = \"x\"\nexact = \"a\"\nprefix = \"a\"\nreason = \"two matchers\"",
            "[[deny]]\nid = \"Bad ID\"\nexact = \"a\"\nreason = \"invalid id\"",
            "[[deny]]\nid = \"x\"\nexact = \"a\"\nreason = \"first\"\n[[deny]]\nid = \"x\"\nexact = \"b\"\nreason = \"duplicate\"",
            "unknown = true",
            "[[allow]]\nexact = \"rm -rf src\"\nreason = \"not supported\"",
        ] {
            assert!(
                parse_project_rules(policy).is_err(),
                "expected invalid project policy: {policy}"
            );
        }
    }
}
