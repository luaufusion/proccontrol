use std::{cell::RefCell, os::unix::process::CommandExt, process::{ExitCode, ExitStatus}, rc::Rc, sync::LazyLock};

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    /// The command to run
    /// 
    /// Security notes:
    /// - The first argument is the command itself, followed by its arguments
    /// - The command itself must be the same user id as the caller
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
    error_rc: Rc<RefCell<Vec<String>>>,
    cg: cgroups_rs::fs::Cgroup,
}

impl Drop for CgroupDtor {
    fn drop(&mut self) {
        let cg = cgroups_rs::fs::Cgroup::load(
            Box::new(cgroups_rs::fs::hierarchies::V2::new()),
            self.cg.path(),
        );

        if let Err(e) = cg.kill() {
            self.error_rc.borrow_mut().push(format!("Failed to kill cgroup processes: {e}"));
        }

        if let Err(e) = cg.delete() {
            self.error_rc.borrow_mut().push(format!("Failed to delete cgroup: {e}"));
        }
    }
}

fn exec(cgroup_dtor_error_rc: Rc<RefCell<Vec<String>>>) -> Result<ExitStatus, Box<dyn std::error::Error>> {
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

    // SAFETY: Error if LD_PRELOAD is set
    if std::env::var_os("LD_PRELOAD").is_some() {
        return Err("LD_PRELOAD is set, refusing to run for security reasons".into());
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

    let cmd_name = &ARGS.command[0];
    let cmd_args = &ARGS.command[1..];

    let mut cmd = std::process::Command::new(cmd_name);

    cmd.args(cmd_args);

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

    let _cg_dtor = CgroupDtor { cg: cgroup, error_rc: cgroup_dtor_error_rc };

    // Now spawn the command
    if ARGS.verbose {
        println!("Spawning command: {:?}", ARGS.command);
    }

    let path = _cg_dtor.cg.path().to_string();
    let cgroup_procs_file_path = format!("/sys/fs/cgroup/{}/cgroup.procs", path);
    
    let mut id_buf= Vec::with_capacity(10); // Enough for basically all PIDs without further allocations
    unsafe {
        cmd.pre_exec(move || {
            // Write the PID to the cgroup procs file
            {
                use std::io::Write;

                // SAFETY: It is not *entirely* safe to heap allocate strings here
                // so we need to write the pid to id_buf first then write_all to file
                write!(&mut id_buf, "{}", std::process::id())?;

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&cgroup_procs_file_path)?;

                file.write_all(&id_buf)?;
                file.flush()?;
            }

            // Drop permissions before returning Ok(())
            //
            // Once Ok has been returned, exec() will be called, after which
            // we cannot control what the process does anymore
            nix::unistd::setgroups(&[gid])?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?;

            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Err(format!("Failed to spawn command: {e}").into());
        }
    };

    if ARGS.verbose {
        println!("Spawned child process with PID: {}", child.id());
    }

    match child.wait() {
        Err(e) => {
            return Err(format!("Failed to wait for command: {e}").into());
        }
        Ok(exit_status) => {
            /*if !exit_status.success() {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }*/
            return Ok(exit_status);
        }
    }
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cgroup_dtor_error_rc = Rc::new(RefCell::new(Vec::new()));
    let status = exec(cgroup_dtor_error_rc.clone())?;
    if status.success() {
        if cgroup_dtor_error_rc.borrow().len() > 0 {
            return Err(cgroup_dtor_error_rc.borrow().join(", ").into());
        }
    }
    match status.code() {
        Some(mut code) => {
            if cgroup_dtor_error_rc.borrow().len() > 0 {
                // We have to hijack the exit code to indicate an error
                // in cgroup deletion here unfortunately.
                // TODO: Use a flag for controlling this
                return Err(cgroup_dtor_error_rc.borrow().join(", ").into());
            }

            if code < 0 {
                code = -1 * code;
            }
            if code > 255 {
                code = 255;
            }
            Ok(ExitCode::from(code as u8))
        },
        None => {
            return Err("Process terminated by signal".into());
        }
    }
}