mod app;
mod cli;
mod output;
mod signals;

use clap::Parser;
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    match app::run(cli::Args::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(app::AppError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "error: {error}");
            ExitCode::from(2)
        }
    }
}
