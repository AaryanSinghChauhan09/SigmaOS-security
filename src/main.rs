//! SigmaOS-security - SigmaOS Component CLI
//!
//! Command-line interface for SigmaOS-security component.

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use security::{Component, ComponentStatus, Config, security};

#[derive(Parser)]
#[command(name = "security")]
#[command(about = "SigmaOS SigmaOS-security component", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the component
    Init {
        /// Enable debug mode
        #[arg(short, long)]
        debug: bool,
    },
    /// Start the component
    Start,
    /// Stop the component
    Stop,
    /// Get component status
    Status,
    /// Run the component
    Run {
        /// Enable debug mode
        #[arg(short, long)]
        debug: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    let config = Config::default();
    let mut component = security::new(config);

    match cli.command {
        Commands::Init { debug } => {
            if debug {
                println!("Initializing SigmaOS-security in debug mode...");
            } else {
                println!("Initializing SigmaOS-security...");
            }
            component.initialize()?;
            println!("SigmaOS-security initialized successfully");
        }
        Commands::Start => {
            component.initialize()?;
            component.start()?;
            println!("SigmaOS-security started successfully");
        }
        Commands::Stop => {
            component.stop()?;
            println!("SigmaOS-security stopped successfully");
        }
        Commands::Status => {
            let status = component.status();
            println!("SigmaOS-security status: {:?}", status);
        }
        Commands::Run { debug } => {
            if debug {
                println!("Running SigmaOS-security in debug mode...");
            } else {
                println!("Running SigmaOS-security...");
            }
            component.initialize()?;
            component.start()?;
            println!("SigmaOS-security is running. Press Ctrl+C to stop.");
            
            // Keep running
            tokio::runtime::Runtime::new()?.block_on(async {
                tokio::signal::ctrl_c().await.unwrap();
                info!("Received Ctrl+C, shutting down...");
            });
            
            component.stop()?;
            println!("SigmaOS-security stopped");
        }
    }

    Ok(())
}
