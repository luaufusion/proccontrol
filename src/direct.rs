use std::{cell::RefCell, os::unix::process::CommandExt, process::{ExitCode, ExitStatus}, rc::Rc};
use nix::mount;


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
    /// What percentage of the CPU can the process use (0-100)
    /// If not specified, no CPU limit is applied
    pub cpu_limit_percent: Option<u8>,
    /// Chroot to this directory before executing
    pub chroot: Option<String>,
    /// Whether or not to use a new user namespace
    /// *EXPERIMENTAL*
    pub new_userns: bool,
    /// Whether to run verbosely
    pub verbose: bool,
    /// Mandate full security checks and refuse to run if any fail
    pub secure: bool,
}

struct CgroupDtor {
    error_rc: Rc<RefCell<Vec<String>>>,
    cg: cgroups_rs::fs::Cgroup,
}

impl Drop for CgroupDtor {
    fn drop(&mut self) {      
        println!("In CgroupDtor drop, cleaning up cgroup {}", self.cg.path());  
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

fn setup_cgroup(args: &Args) -> Result<cgroups_rs::fs::Cgroup, Box<dyn std::error::Error>> {
    let cgroup = {        
        let cg_name = format!("ce{}", rand::random::<u64>());
        if args.verbose {
            println!("Creating cgroup: {}", cg_name);
        }

        let cg = cgroups_rs::fs::cgroup_builder::CgroupBuilder::new(&cg_name)
        .set_specified_controllers(vec!["memory".to_string(), "cpu".to_string()]);

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

        let cg = {
            let mut cpu_controller = cg.cpu();

            cpu_controller = if let Some(percent) = args.cpu_limit_percent {
                let quota = percent as i64 * 1000;
                cpu_controller = cpu_controller.quota(quota);
                cpu_controller = cpu_controller.period(100_000);
                cpu_controller
            } else {
                cpu_controller
            };

            cpu_controller.done()
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

    Ok(cgroup)
}

fn exec(args: Args, cgroup_dtor_error_rc: Rc<RefCell<Vec<String>>>) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    // SAFETY: Error if LD_PRELOAD is set
    if std::env::var_os("LD_PRELOAD").is_some() {
        return Err("LD_PRELOAD is set, refusing to run for security reasons".into());
    }

    if args.secure {
        if args.chroot.is_none() {
            return Err("Secure mode requires a chroot to be specified".into());
        }

        if args.memory_soft.is_none() && args.memory_hard.is_none() {
            return Err("Secure mode requires at least one memory limit to be specified".into());
        }
    }

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

    let mut cmd_name = args.command[0].clone();

    // Limit net
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
    
    // If chroot is specified, we need to prepare the target directory's chroot environment
    if args.chroot.is_some() {
        let chroot_dir = args.chroot.as_ref().unwrap();
        // Ensure chroot dir exists and is a directory
        let md = std::fs::metadata(chroot_dir)?;
        if !md.is_dir() {
            return Err(format!("Chroot directory {} does not exist or is not a directory", chroot_dir).into());
        }
        if args.verbose {
            println!("Setting up chroot environment in {}", chroot_dir);
        }

        chroot_post_op(chroot_dir, args.verbose)?;

        let old_root_dir = format!("{}/tmp/old_root", chroot_dir);
        std::fs::create_dir_all(&old_root_dir)?;

        nix::unistd::pivot_root(
            std::path::Path::new(chroot_dir),
            std::path::Path::new(&old_root_dir),
        )
        .map_err(|e| format!("Failed to pivot_root to {}: {}", chroot_dir, e))?;

        // Change working directory to /
        std::env::set_current_dir("/")?;

        // List files in new root
        if args.verbose {
            println!("New root directory contents:");
            for entry in std::fs::read_dir("/sys/fs/cgroup")? {
                let entry = entry?;
                println!(" - {}", entry.file_name().to_string_lossy());
            }
        }

        cmd_name = "/bin/".to_owned() + &cmd_name;
    }

    let cgroup = setup_cgroup(&args)?;
    let _cg_dtor = CgroupDtor { cg: cgroup, error_rc: cgroup_dtor_error_rc };
    let path = _cg_dtor.cg.path().to_string();
    let cgroup_procs_file_path = format!("/sys/fs/cgroup/{}/cgroup.procs", path);

    // Now spawn the command
    if args.verbose {
        println!("Spawning command: {:?}", cmd_name);
    }

    let cmd_args = &args.command[1..];

    let mut cmd = std::process::Command::new(cmd_name);

    cmd.args(cmd_args);

    let new_userns = args.new_userns;
    unsafe {
        cmd.pre_exec(move || {
            {
                // Because rust File is not guaranteed to be async signal safe, we need to use raw nix
                let fd = nix::fcntl::open(
                    cgroup_procs_file_path.as_str(),
                    nix::fcntl::OFlag::O_WRONLY,
                    nix::sys::stat::Mode::empty(),
                )?;
                nix::unistd::write(fd, b"0")?;
            } // fd is dropped and hence closed after write (which takes ownership)

            // Drop permissions before returning Ok(())
            //
            // Once Ok has been returned, exec() will be called, after which
            // we cannot control what the process does anymore
            nix::unistd::setgroups(&[gid])?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?; // Technically unsound on glibc but we don't spawn any threads so this should(TM) be fine

            // Enter new user namespace
            if new_userns {
                // Technically unsafe/unsound, but its not a very big deal
                // as we've not yet called exec() and we don't spawn any threads
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER)
                .map_err(|e| format!("Failed to unshare USER namespace: {}", e))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            }

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

    println!("cgroup tasks: {:?}", _cg_dtor.cg.tasks());

    match child.wait() {
        Err(e) => {
            return Err(format!("Failed to wait for command: {e}").into());
        }
        Ok(exit_status) => {
            return Ok(exit_status);
        }
    }
}

pub(crate) fn main(args: Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cgroup_dtor_error_rc = Rc::new(RefCell::new(Vec::new()));
    let status = exec(args, cgroup_dtor_error_rc.clone())
        .map_err(|e| format!("Failed to execute command: {}", e))?;
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

fn chroot_post_op(dir: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Enter new PID/CGROUP namespace
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
    .map_err(|e| format!("Failed to enter new mount namespace: {}", e))?;

    // TODO: Support NEWCGROUP as well soon
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID)
        .map_err(|e| format!("Failed to unshare PID namespace: {}", e))?;
    
    mount::mount(None::<&str>, "/", None::<&str>, mount::MsFlags::MS_REC | mount::MsFlags::MS_PRIVATE, None::<&str>)?;
    mount::mount(Some(dir), dir, None::<&str>, mount::MsFlags::MS_BIND, None::<&str>)?;

    let proc_target = format!("{}/proc", dir);

    // Check if proc is already mounted
    if nix::sys::statfs::statfs(std::path::Path::new(&proc_target))?.filesystem_type() == nix::sys::statfs::PROC_SUPER_MAGIC {
        panic!("Proc already mounted in chroot, cannot continue for security reasons");
    }

    if verbose {
        println!("Mounting proc filesystem to {}", proc_target);
    }

    nix::mount::mount(
        Some("proc"),
        std::path::Path::new(&proc_target),
        Some("proc"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NOEXEC | nix::mount::MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    // Check if sys is mounted
    let sys_target = format!("{}/sys", dir);
    if nix::sys::statfs::statfs(std::path::Path::new(&sys_target))?.filesystem_type() == nix::sys::statfs::SYSFS_MAGIC {
        panic!("Sysfs already mounted in chroot, cannot continue for security reasons");
    }

    if verbose {
        println!("Mounting sys filesystem to {}", sys_target);
    }

    nix::mount::mount(
        Some("sys"),
        std::path::Path::new(&sys_target),
        Some("sysfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NOEXEC | nix::mount::MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    // Mount cgroup2 to /sys/fs/cgroup
    let cgroup_mount_point = format!("{}/sys/fs/cgroup", dir);
    if verbose {
        println!("Mounting cgroup2 filesystem to {}", cgroup_mount_point);
    }

    nix::mount::mount(
        Some("cgroup2"),
        std::path::Path::new(&cgroup_mount_point),
        Some("cgroup2"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NOEXEC | nix::mount::MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    // Mount a tmpfs to /tmp
    let tmp_target = format!("{}/tmp", dir);
    if verbose {
        println!("Mounting tmpfs to {}", tmp_target);
    }

    if nix::sys::statfs::statfs(std::path::Path::new(&tmp_target))?.filesystem_type() == nix::sys::statfs::TMPFS_MAGIC {
        panic!("Tmpfs already mounted in chroot, cannot continue for security reasons");
    }

    nix::mount::mount(
        Some("tmpfs"),
        std::path::Path::new(&tmp_target),
        Some("tmpfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NOEXEC | nix::mount::MsFlags::MS_NODEV,
        None::<&str>,
    )?; 

    if verbose {
        println!("Chroot environment setup complete.");
    }

    Ok(())
}