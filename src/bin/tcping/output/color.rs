use clap::{ColorChoice, builder::styling::AnsiColor};
use std::env;
use tcping::{FailureKind, Outcome};

pub(crate) fn enabled(choice: ColorChoice, is_terminal: bool) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            is_terminal
                && !env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
                && env::var_os("TERM").is_none_or(|value| value != "dumb")
        }
    }
}

pub(super) fn status(outcome: &Outcome, text: &str, enabled: bool) -> String {
    if !enabled {
        return text.to_owned();
    }
    let color = match outcome {
        Outcome::Open => AnsiColor::Green,
        Outcome::Cancelled => AnsiColor::BrightBlack,
        Outcome::TimedOut => AnsiColor::Yellow,
        Outcome::Failed(failure)
            if matches!(
                failure.kind(),
                FailureKind::HostUnreachable | FailureKind::NetworkUnreachable
            ) =>
        {
            AnsiColor::Yellow
        }
        _ => AnsiColor::Red,
    };
    let style = color.on_default();
    format!("{style}{text}{}", style.render_reset())
}
