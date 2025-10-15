use nix::mount;

/// Prepares a chroot environment in dir if needed
pub fn prepare_chroot_env(dir: &str, bin: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("Preparing chroot environment in {}", dir);
    // if $dir/.prepared exists, return
    let prep_marker = format!("{}/.prepared", dir);
    if std::path::Path::new(&prep_marker).exists() {
        return Ok(());
    }

    // Resolve the command to an absolute path
    let cmd_path = if bin.contains("/") {
        std::path::PathBuf::from(bin)
    } else {
        which::which(bin)?
    };
    
    println!("Preparing chroot environment in {} for command {}", dir, cmd_path.display());

    // Assert no dots in dir
    if dir.contains(".") {
        return Err("Chroot directory cannot contain '.' for security reasons".into());
    }

    // Create necessary directories
    let dirs = [
        "bin",
        "proc",
        "sys",
        "tmp",
        "lib64",
        "lib",
        "bin"
    ];

    for d in dirs.iter() {
        let path = format!("{}/{}", dir, d);
        if verbose {
            println!("Creating directory: {}", path);
        }
        std::fs::create_dir_all(&path)?;
    }

    // Get needed libraries for bin
    let output = std::process::Command::new("ldd")
        .arg(&cmd_path)
        .output()?;

    let mut is_dynamic = true;
    if !output.status.success() {
        // if not dynamic executable, ldd returns error
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not a dynamic executable") {
            is_dynamic = false;
        } else {
            return Err(format!("Failed to run ldd on {}: {}", bin, String::from_utf8_lossy(&output.stderr)).into());
        }
    }

    if is_dynamic {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut libs = Vec::new();
        for line in stdout.lines() {
            if let Some(start) = line.find("=>") {
                let rest = &line[start + 2..].trim();
                if let Some(end) = rest.find(' ') {
                    let lib = &rest[..end];
                    libs.push(lib.to_string());
                } else {
                    libs.push(rest.to_string());
                }
            } else if let Some(start) = line.find('/') {
                let lib = &line[start..].trim();
                libs.push(lib.to_string());
            }
        }

        for lib in libs.iter_mut() {
            // Remove any trailing characters like (0x00007ff...)
            if let Some(pos) = lib.find(' ') {
                *lib = lib[..pos].to_string();
            }
        }

        println!("Needed libraries: {:?}", libs);
        for lib in libs.iter() {
            let dest = format!("{}/{}", dir, lib);
            let dest_dir = std::path::Path::new(&dest).parent().unwrap();
            if verbose {
                println!("Copying library {} to {}", lib, dest);
            }
            std::fs::create_dir_all(dest_dir)?;
            std::fs::copy(lib, &dest)?;
        }
    }

    // Copy the binary itself to bin in the chroot env
    let dest = format!("{}/bin/{}", dir, cmd_path.file_name().unwrap().to_string_lossy());
    if verbose {
        println!("Copying binary {} to {}", cmd_path.display(), dest);
    }
    std::fs::copy(&cmd_path, &dest)?;

    // Copy /bin/bash
    let bash_path = which::which("bash")?;
    let dest = format!("{}/bin/{}", dir, bash_path.file_name().unwrap().to_string_lossy());
    if verbose {
        println!("Copying bash {} to {}", bash_path.display(), dest);
    }
    std::fs::copy(&bash_path, &dest)?;

    // Create the .prepared marker file
    std::fs::write(prep_marker, bin)?;

    nix::unistd::sync();
    std::thread::sleep(std::time::Duration::from_millis(100));
    Ok(())
}

pub fn post_op(dir: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
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