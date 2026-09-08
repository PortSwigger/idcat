use crate::config::TokenSource;
use anyhow::{Context, bail};
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

pub fn read_token(source: &TokenSource) -> anyhow::Result<String> {
    match source {
        TokenSource::Path(path) => read_token_path(path),
        TokenSource::Program { executable, args } => run_token_program(executable, args),
        TokenSource::ShellCommand(command) => run_token_shell_command(command),
    }
}

fn read_token_path(path: &Path) -> anyhow::Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read token-path: {}", path.display()))?;
    trim_token(token, "token-path produced an empty token")
}

/// Runs a fixed executable with an explicit argument array. Nothing is passed through a shell, so
/// no part of the configuration is word-split, globbed or substituted.
fn run_token_program(executable: &Path, args: &[String]) -> anyhow::Result<String> {
    let output = Command::new(executable)
        .args(args.iter().map(OsStr::new))
        .output()
        .with_context(|| {
            format!(
                "failed to execute token-executable: {}",
                executable.display()
            )
        })?;
    token_from_output(output, "token-executable")
}

fn run_token_shell_command(command: &str) -> anyhow::Result<String> {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| format!("failed to execute token-command: {command}"))?;
    token_from_output(output, "token-command")
}

fn token_from_output(output: std::process::Output, source: &str) -> anyhow::Result<String> {
    if !output.status.success() {
        // Deliberately does not include stdout: on some failures a token source still prints a
        // usable token before exiting non-zero, and that must not reach a log.
        bail!(
            "{source} exited with status {}",
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
        );
    }

    let token = String::from_utf8(output.stdout)
        .with_context(|| format!("{source} output was not UTF-8"))?;
    trim_token(token, &format!("{source} produced an empty token"))
}

fn trim_token(token: String, empty_message: &str) -> anyhow::Result<String> {
    let token = token.trim();
    if token.is_empty() {
        bail!("{empty_message}");
    }

    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn reads_a_token_from_a_program_and_its_argument_array() {
        let source = TokenSource::Program {
            executable: PathBuf::from("/bin/echo"),
            args: vec!["synthetic-token".to_owned()],
        };

        assert_eq!(read_token(&source).unwrap(), "synthetic-token");
    }

    #[test]
    fn passes_each_argument_verbatim_without_a_shell() {
        // Under `/bin/sh -c` this would be substituted; as an argv element it must arrive intact.
        let source = TokenSource::Program {
            executable: PathBuf::from("/bin/echo"),
            args: vec!["$(echo injected)".to_owned()],
        };

        assert_eq!(read_token(&source).unwrap(), "$(echo injected)");
    }

    #[test]
    fn does_not_split_an_argument_on_whitespace() {
        let source = TokenSource::Program {
            executable: PathBuf::from("/bin/echo"),
            args: vec!["-n".to_owned(), "one two".to_owned()],
        };

        assert_eq!(read_token(&source).unwrap(), "one two");
    }

    #[test]
    fn rejects_an_empty_program_token() {
        let source = TokenSource::Program {
            executable: PathBuf::from("/bin/echo"),
            args: vec!["-n".to_owned(), String::new()],
        };

        let error = read_token(&source).unwrap_err();

        assert!(error.to_string().contains("empty token"), "{error}");
    }

    #[test]
    fn reports_a_failing_program_without_echoing_its_output() {
        let source = TokenSource::Program {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_owned(), "echo ghs_leaked; exit 3".to_owned()],
        };

        let error = read_token(&source).unwrap_err();

        assert!(error.to_string().contains("status 3"), "{error}");
        assert!(
            !error.to_string().contains("ghs_leaked"),
            "a failure message must not echo what the token source printed: {error}"
        );
    }

    #[test]
    fn the_deprecated_shell_command_still_works() {
        let source = TokenSource::ShellCommand("echo synthetic-token".to_owned());

        assert_eq!(read_token(&source).unwrap(), "synthetic-token");
    }

    #[test]
    fn reads_a_token_from_a_file() {
        let path = std::env::temp_dir().join("idcat-token-source-test");
        std::fs::write(&path, "synthetic-token\n").unwrap();

        let token = read_token(&TokenSource::Path(path.clone())).unwrap();

        std::fs::remove_file(&path).ok();
        assert_eq!(token, "synthetic-token");
    }
}
