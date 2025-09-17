use std::{os::unix::process::CommandExt, sync::LazyLock};

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
        if let Err(e) = cg.delete() {
            eprintln!("Failed to delete cgroup: {}", e);
        } else {
            if ARGS.verbose {
                println!("Deleted cgroup");
            }

            println!("Deleted cgroup");
        }
    }
}

fn main() {
    let exit_status = {
        let eid = nix::unistd::geteuid();
        if !eid.is_root() {
            eprintln!("This program must be run as the root EUID (euid=0). Current euid={}", eid);
            setuid_help();
            std::process::exit(1);
        }
        let uid = nix::unistd::getuid();
        if uid.is_root() {
            eprintln!("This program must not be run as the root user itself (uid!=0). Current uid={}", uid);
            setuid_help();
            std::process::exit(1);
        }

        let gid = nix::unistd::getgid();
        let egid = nix::unistd::getegid();

        if ARGS.verbose {
            println!("Current groupid: {}, effective groupid {}", gid, egid);
            println!("Current userid: {}, effective userid {}", uid, eid);
            println!("Args: {:?}", *ARGS);
        }

        if ARGS.verbose {
            // Lookup the name of the effective user id
            let euser = nix::unistd::User::from_uid(eid).unwrap();
            if euser.is_none() {
                eprintln!("Failed to lookup user for euid={}", eid);
                std::process::exit(1);
            }
            let user = nix::unistd::User::from_uid(uid).unwrap();
            if user.is_none() {
                eprintln!("Failed to lookup user for uid={}", uid);
                std::process::exit(1);
            }

            println!("Running as user: {} (uid={}), effective user: {} (euid={})", user.as_ref().unwrap().name, uid, euser.as_ref().unwrap().name, eid);
        }

        // Do stuff needing root privileges here, e.g., setting up cgroups.
        if ARGS.command.is_empty() {
            eprintln!("No command specified to run");
            std::process::exit(1);
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

            let cg = cg.build(
                Box::new(cgroups_rs::fs::hierarchies::V2::new()),
            ).unwrap_or_else(|e| {
                eprintln!("Failed to create cgroup: {}", e);
                std::process::exit(1);
            });

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
        unsafe {
            cmd.pre_exec(move || {
                // Write the PID to the cgroup procs file
                {
                    use std::io::Write;
                    let cgroup_procs_file_path = format!("/sys/fs/cgroup/{}/cgroup.procs", path);
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&cgroup_procs_file_path)?;

                    file.write_all(std::process::id().to_string().as_bytes())?;
                    file.flush()?;
                }

                // Then drop privileges
                println!("Dropping privileges to uid={}, gid={}", uid, gid);
                nix::unistd::setgroups(&[gid])?;
                nix::unistd::setgid(gid)?;
                nix::unistd::setuid(uid)?;

                Ok(())
            });
        }

        let mut child = cmd.spawn().unwrap_or_else(|e| {
            eprintln!("Failed to spawn command '{}': {}", command, e);
            std::process::exit(1);
        });

        println!("Spawned child process with PID: {}", child.id());
        let exit_status = child.wait().unwrap_or_else(|e| {
            eprintln!("Failed to wait for command '{}': {}", command, e);
            std::process::exit(1);
        });

        if !exit_status.success() {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        exit_status
    };
    println!("Command exited with status: {}", exit_status);
    std::process::exit(exit_status.code().unwrap_or(1));
}