/// Apply app specific patch operations after chroot is set up
pub fn app_specific_post_op(dir: &str, bin: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Check if running on Ubuntu
    let os_release = std::fs::read_to_string("/etc/os-release")?;
    let is_ubuntu = os_release.lines().any(|line| line.starts_with("ID=ubuntu"));

    fn copy_dir(dir: &str, dest: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
        if verbose {
            println!("Copying directory {} to {}", dir, dest);
        }
        std::fs::create_dir_all(dest)?;

        // Spawn a shell process and use cp -r to copy the directory
        let status = std::process::Command::new("cp")
            .arg("-r")
            .arg(dir)
            .arg(dest)
            .status()?;

        if !status.success() {
            return Err(format!("Failed to copy directory {} to {}", dir, dest).into());
        }

        // Make sure to chown the copied files to uid:uid if needed
        let uid = nix::unistd::getuid();
        let euid = nix::unistd::geteuid();
        if uid != euid {
            if verbose {
                println!("Changing ownership of copied files in {} to uid: {}", dest, uid);
            }
            let status = std::process::Command::new("chown")
                .arg("-R")
                .arg(format!("{}:{}", uid, uid))
                .arg(dest)
                .status()?;

            if !status.success() {
                return Err(format!("Failed to chown copied files in {}", dest).into());
            }
        }

        Ok(())
    }

    fn ubuntu_app_specific(dir: &str, bin: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
        if verbose {
            println!("Applying Ubuntu specific post operations for binary {}", bin);
            println!("Current binary: {}", bin);
        }
        match bin {
            "node" | "nodejs" => {
                if verbose { 
                    println!("Applying Ubuntu specific patches for Node.js");
                }
                // Nodejs needs /usr/share/nodejs copied over
                copy_dir("/usr/share/nodejs", &format!("{}/usr/share", dir), verbose)?;
            }
            _ => {
                println!("No Ubuntu specific post operations for binary `{}`", bin);
            }
        }        

        Ok(())
    }

    if is_ubuntu {
        ubuntu_app_specific(dir, bin, verbose)?;
    }

    Ok(())
}

/// Prepares a chroot environment in dir if needed
pub fn prepare_chroot_env(dir: &str, bin: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let uid = nix::unistd::getuid();
    if uid.is_root() {
        println!("Chroot creation must be executed by a non-root user although may be run within suid euid (for security reasons).");
        return Err(format!("This program must not be run as the root user itself (uid!=0). Current uid={uid}").into());
    }

    // Check if dir already exists
    if std::path::Path::new(dir).exists() {
        return Err(format!("Chroot directory {} already exists, refusing to continue for safety reasons", dir).into());
    }

    println!("Preparing chroot environment in {}", dir);
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

    // Apply app specific post operations
    if verbose {
        println!("Applying app specific post operations");
    }
    app_specific_post_op(dir, bin, verbose)?;

    nix::unistd::sync();
    std::thread::sleep(std::time::Duration::from_millis(100));
    Ok(())
}

