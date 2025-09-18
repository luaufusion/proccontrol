use std::{cell::RefCell, os::unix::process::CommandExt, process::{ExitCode, ExitStatus}, rc::Rc};


#[derive(Debug)]
pub struct Args {
    /// The command to run
    pub command: Vec<String>,
    /// The soft memory limit in bytes
    /// If not specified, no memory limit is applied
    pub memory_soft: Option<i64>,
    /// The hard memory limit in bytes
    /// If not specified, no memory limit is applied
    pub memory_hard: Option<i64>,
    /// Whether to run verbosely
    pub verbose: bool,
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

fn exec(args: Args, cgroup_dtor_error_rc: Rc<RefCell<Vec<String>>>) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let eid = nix::unistd::geteuid();
    if !eid.is_root() {
        println!("This program must be run as a setuid binary owned by root (uid=0) but executed by a non-root user (for security reasons).");
        return Err(format!("This program must be run as the root EUID (euid=0). Current euid={eid}").into());
    }
    let uid = nix::unistd::getuid();
    if uid.is_root() {
        println!("This program must be run as a setuid binary owned by root (uid=0) but executed by a non-root user (for security reasons).");
        return Err(format!("This program must not be run as the root user itself (uid!=0). Current uid={uid}").into());
    }

    // SAFETY: Error if LD_PRELOAD is set
    if std::env::var_os("LD_PRELOAD").is_some() {
        return Err("LD_PRELOAD is set, refusing to run for security reasons".into());
    }

    let gid = nix::unistd::getgid();
    let egid = nix::unistd::getegid();

    if args.verbose {
        println!("Current groupid: {}, effective groupid {}", gid, egid);
        println!("Current userid: {}, effective userid {}", uid, eid);
        println!("Args: {:?}", args);
    }

    // Do stuff needing root privileges here, e.g., setting up cgroups.
    if args.command.is_empty() {
        return Err("No command specified to run".into());
    }

    let cmd_name = &args.command[0];

    let cmd_args = &args.command[1..];

    let mut cmd = std::process::Command::new(cmd_name);

    cmd.args(cmd_args);

    let cgroup = {        
        let cg_name = format!("ce{}", rand::random::<u64>());
        if args.verbose {
            println!("Creating cgroup: {}", cg_name);
        }

        let cg = cgroups_rs::fs::cgroup_builder::CgroupBuilder::new(&cg_name)
        .set_specified_controllers(vec!["memory".to_string()]);
        let cg = {
            let mut mem_controller = cg.memory();
            if let Some(soft) = args.memory_soft {
                mem_controller = mem_controller.memory_soft_limit(soft);
            }
            if let Some(hard) = args.memory_hard {
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
    if args.verbose {
        println!("Spawning command: {:?}", args.command);
    }

    let path = _cg_dtor.cg.path().to_string();
    let cgroup_procs_file_path = format!("/sys/fs/cgroup/{}/cgroup.procs", path);
    
    unsafe {
        cmd.pre_exec(move || {
            // Write the PID to the cgroup procs file
            {
                // Because rust File is not guaranteed to be async signal safe, we need to use raw nix
                let fd = nix::fcntl::open(
                    cgroup_procs_file_path.as_str(),
                    nix::fcntl::OFlag::O_WRONLY,
                    nix::sys::stat::Mode::empty(),
                )?;
                nix::unistd::write(fd, format!("{}", std::process::id()).as_bytes())?;
            } // fd is dropped and hence closed after write (which takes ownership)

            // Drop permissions before returning Ok(())
            //
            // Once Ok has been returned, exec() will be called, after which
            // we cannot control what the process does anymore
            nix::unistd::setgroups(&[gid])?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?; // Technically unsound on glibc but we don't spawn any threads so this should(TM) be fine

            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Err(format!("Failed to spawn command: {e}").into());
        }
    };

    if args.verbose {
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

pub(crate) fn main(args: Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cgroup_dtor_error_rc = Rc::new(RefCell::new(Vec::new()));
    let status = exec(args, cgroup_dtor_error_rc.clone())?;
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