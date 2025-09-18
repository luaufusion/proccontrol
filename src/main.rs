use std::{os::unix::process::CommandExt, process::{ExitCode, ExitStatus}, sync::LazyLock};

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    /// Command to run
    #[clap(required = true)]
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

pub static ARGS: LazyLock<Args> = LazyLock::new(|| Args::parse());

fn setuid_help() {
    println!("This program must be run as a setuid binary owned by root (uid=0) but executed by a non-root user (for security reasons).");
}

struct CgroupDtor {
    cg: cgroups_rs::fs::Cgroup,
}

impl Drop for CgroupDtor {
    fn drop(&mut self) {
        let cg = cgroups_rs::fs::Cgroup::load(
            Box::new(cgroups_rs::fs::hierarchies::V2::new()),
            self.cg.path(),
        );

        if let Err(e) = cg.kill() {
            eprintln!("Failed to kill cgroup processes: {}", e);
        }

        if let Err(e) = cg.delete() {
            eprintln!("Failed to delete cgroup: {}", e);
        } else {
            if ARGS.verbose {
                println!("Deleted cgroup");
            }
        }
    }
}

fn exec() -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let eid = nix::unistd::geteuid();
    if !eid.is_root() {
        setuid_help();
        return Err(format!("This program must be run as the root EUID (euid=0). Current euid={eid}").into());
    }
    let uid = nix::unistd::getuid();
    if uid.is_root() {
        setuid_help();
        return Err(format!("This program must not be run as the root user itself (uid!=0). Current uid={uid}").into());
    }

    let gid = nix::unistd::getgid();
    let egid = nix::unistd::getegid();

    if ARGS.verbose {
        println!("Current groupid: {}, effective groupid {}", gid, egid);
        println!("Current userid: {}, effective userid {}", uid, eid);
        println!("Args: {:?}", *ARGS);
    }

    // Do stuff needing root privileges here, e.g., setting up cgroups.
    if ARGS.command.is_empty() {
        return Err("No command specified to run".into());
    }

    let cgroup = {        
        let cg_name = format!("ce{}", rand::random::<u64>());
        if ARGS.verbose {
            println!("Creating cgroup: {}", cg_name);
        }

        let cg = cgroups_rs::fs::cgroup_builder::CgroupBuilder::new(&cg_name)
        .set_specified_controllers(vec!["memory".to_string()]);
        let cg = {
            let mut mem_controller = cg.memory();
            if let Some(soft) = ARGS.memory_soft {
                mem_controller = mem_controller.memory_soft_limit(soft);
            }
            if let Some(hard) = ARGS.memory_hard {
                mem_controller = mem_controller.memory_hard_limit(hard);
            }

            mem_controller.done()
        };

        let cg = match cg.build(
            Box::new(cgroups_rs::fs::hierarchies::V2::new()),
        ) {
            Ok(cg) => cg,
            Err(e) => {
                return Err(format!("Failed to create cgroup: {}", e).into());
            }
        };

        assert!(cg.exists(), "Cgroup does not exist after creation");

        cg
    };

    let _cg_dtor = CgroupDtor { cg: cgroup };

    // Now spawn the command
    let command = &ARGS.command[0];
    let command_args = &ARGS.command[1..];

    if ARGS.verbose {
        println!("Spawning command: {} {:?}", command, command_args);
    }

    let mut cmd = std::process::Command::new(command);
    cmd.args(command_args);

    let path = _cg_dtor.cg.path().to_string();
    let cgroup_procs_file_path = format!("/sys/fs/cgroup/{}/cgroup.procs", path);
    
    unsafe {
        cmd.pre_exec(move || {
            // Write the PID to the cgroup procs file
            {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&cgroup_procs_file_path)?;

                file.write_all(std::process::id().to_string().as_bytes())?;
                file.flush()?;
            }

            // Then drop privileges
            
            //println!("Dropping privileges to uid={}, gid={}", uid, gid);
            nix::unistd::setgroups(&[gid])?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?;

            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Err(format!("Failed to spawn command '{}': {}", command, e).into());
        }
    };

    if ARGS.verbose {
        println!("Spawned child process with PID: {}", child.id());
    }

    match child.wait() {
        Err(e) => {
            return Err(format!("Failed to wait for command '{command}': {e}").into());
        }
        Ok(exit_status) => {
            if !exit_status.success() {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            return Ok(exit_status);
        }
    }
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let status = exec()?;
    match status.code() {
        Some(mut code) => {
            if code < 0 {
                code = -1 * code;
            }
            if code > 255 {
                code = 255;
            }
            Ok(ExitCode::from(code as u8))
        },
        None => {
            eprintln!("Process terminated due to unknown reason (signal?)");
            Ok(ExitCode::from(1))
        }
    }
}