use std::io::{self, Write};

use color_eyre::eyre::Result;

mod cli;

#[doc(hidden)]
fn main() -> Result<()> {
    color_eyre::config::HookBuilder::default()
        .display_env_section(false)
        .install()?;

    if let Err(e) = cli::run() {
        writeln!(io::stderr(), "Error: {:?}", e)?;

        std::process::exit(1);
    }

    Ok(())
}
