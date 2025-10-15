mod direct; // Direct execution mode using setuid binary
mod chrootprep; // Prepares a chroot environment

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
        /// Chroot to this directory before executing
        /// 
        /// Uses pivot_root always
        #[clap(short, long)]
        chroot: Option<String>,
        /// Mandate full security checks and refuse to run if any fail
        #[clap(short, long, default_value_t = false)]
        secure: bool,
    }
}


fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mode = Cli::parse();
    match mode.op {
        Op::Direct { command, memory_soft, memory_hard, verbose, chroot, secure } => {
            let args = Args {
                command,
                memory_soft,
                memory_hard,
                verbose,
                chroot,
                secure
            };

            direct::main(args)
        }
    }
}