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
        /// What percentage of the CPU can the process use (0-100)
        /// If not specified, no CPU limit is applied
        #[clap(short, long)]
        cpu_limit_percent: Option<u8>,
        /// Whether to run verbosely
        #[clap(short, long, action)]
        verbose: bool,
        /// Chroot to this directory before executing
        /// 
        /// Uses pivot_root always
        #[clap(short, long)]
        chroot: Option<String>,
        /// Whether or not to use a new user namespace
        /// *EXPERIMENTAL*
        #[clap(short, long, default_value_t = false)]
        new_userns: bool,
        /// Mandate full security checks and refuse to run if any fail
        #[clap(short, long, default_value_t = false)]
        secure: bool,
    },
    /// Sets up a chroot environment in the specified directory for the specified binary
    /// This is intended to be used prior to using the `Direct` command with the `--chroot` option
    /// ///
    /// Note that this command may take some time to complete as it needs to copy files and
    /// set up the chroot environment.
    PrepareChroot {
        /// The directory to set up the chroot environment in
        dir: String,
        /// The binary to prepare the chroot environment for
        bin: String,
        /// Whether to run verbosely
        #[clap(short, long, action)]
        verbose: bool,
    }
}


fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mode = Cli::parse();
    match mode.op {
        Op::Direct { command, memory_soft, memory_hard, cpu_limit_percent, verbose, chroot, secure, new_userns } => {
            let args = Args {
                command,
                memory_soft,
                memory_hard,
                cpu_limit_percent,
                verbose,
                chroot,
                secure,
                new_userns
            };

            direct::main(args)
        }
        Op::PrepareChroot { dir, bin, verbose } => {
            chrootprep::prepare_chroot_env(&dir, &bin, verbose)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}