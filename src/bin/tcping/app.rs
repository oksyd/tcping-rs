use crate::{
    cli::{Args, OutputMode},
    output::{Renderer, color},
    signals,
};
use anstream::{AutoStream, ColorChoice};
use std::{
    io::{self, IsTerminal},
    ops::ControlFlow,
};
use tcping::{ConfigError, Engine, RunError, SessionError, StopReason, Summary};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum AppError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub(crate) fn run(args: Args) -> Result<u8, AppError> {
    let config = args.config()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let stdout = io::stdout();
    let color =
        args.output_mode == OutputMode::Normal && color::enabled(args.color, stdout.is_terminal());
    let writer = AutoStream::new(
        stdout.lock(),
        if color {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        },
    );
    let mut renderer = Renderer::new(writer, args.output_mode, args.timestamp_format(), color);
    runtime.block_on(async {
        let cancel = signals::install()?;
        let result = Engine::default()
            .run_until(&config, cancel, |event| {
                renderer.write_event(event)?;
                Ok::<_, io::Error>(ControlFlow::Continue(()))
            })
            .await;
        match result {
            Ok(summary) => Ok(exit_code(&summary)),
            Err(RunError::Session(error)) => Err(error.into()),
            Err(RunError::Handler(error)) => Err(error.into()),
        }
    })
}

fn exit_code(summary: &Summary) -> u8 {
    match summary.reason() {
        StopReason::Cancelled => 130,
        StopReason::FirstSuccess => 0,
        _ if summary.counts().open() > 0
            && summary.counts().failed() == 0
            && summary.counts().timed_out() == 0 =>
        {
            0
        }
        _ => 1,
    }
}
