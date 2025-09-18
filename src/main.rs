mod direct; // Direct execution mode using setuid binary

use std::process::ExitCode;
use clap::{Parser, Subcommand};

use crate::direct::Args;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    op: Op,
}

#[derive(Subcommand, Debug)]
enum Op {
    /// Runs a program directly with resource limits applied
    /// 
    /// Assumes the proccontrol binary itself is a setuid root binary
    /// and is executed by a non-root user.
    Direct {
        /// The command to run
        /// 
        /// Security notes:
        /// - The first argument is the command itself, followed by its arguments
        /// - The command itself must be reachable by the callers user
        command: Vec<String>,
        /// The soft memory limit in bytes
        /// If not specified, no memory limit is applied
        #[clap(short, long)]
        memory_soft: Option<i64>,
        /// The hard memory limit in bytes
        /// If not specified, no memory limit is applied
        #[clap(short, long)]
        memory_hard: Option<i64>,
        /// Whether to run verbosely
        #[clap(short, long, action)]
        verbose: bool,
    }
}


fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mode = Cli::parse();
    match mode.op {
        Op::Direct { command, memory_soft, memory_hard, verbose } => {
            let args = Args {
                command,
                memory_soft,
                memory_hard,
                verbose,
            };

            direct::main(args)
        }
    }
}