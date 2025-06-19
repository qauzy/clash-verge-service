#[cfg(not(target_os = "windows"))]
use std::process::Output;
use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

static TARGET_MAT: &str = "verge-mat";
static TARGET_MAT_ALPHA: &str = "verge-mat-alpha";

pub mod safety_path {
    use super::{TARGET_MAT, TARGET_MAT_ALPHA};

    #[cfg(not(target_os = "windows"))]
    pub fn is_symlink(path: &str) -> bool {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            metadata.file_type().is_symlink()
        } else {
            false
        }
    }
    #[cfg(target_os = "windows")]
    pub fn is_symlink(path: &str) -> bool {
        false
    }

    pub fn is_verge_mat_path(path: &str) -> bool {
        let binary_name = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path);
        let is_mat_binary = binary_name == TARGET_MAT;
        let is_mat_alpha_binary = binary_name == TARGET_MAT_ALPHA;
        is_mat_binary || is_mat_alpha_binary
    }

    pub fn is_path_safe(path: &str) -> bool {
        let is_safe = !is_symlink(path) && is_verge_mat_path(path);
        println!("[Path Check] Path is safe: {}", is_safe);
        is_safe
    }
}

pub mod safety_args {
    use super::{TARGET_MAT, TARGET_MAT_ALPHA};

    pub fn is_verge_mat_process_name(process_name: &str) -> bool {
        let is_verge_mat = process_name == TARGET_MAT;
        let is_verge_mat_alpha = process_name == TARGET_MAT_ALPHA;
        is_verge_mat || is_verge_mat_alpha
    }
}

pub fn spawn_process(command: &str, args: &[&str], mut log: std::fs::File) -> io::Result<u32> {
    if !safety_path::is_path_safe(command) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Unsafe command path: {}", command),
        ));
    }

    // Log the command being executed
    let _ = writeln!(log, "Spawning process: {} {}", command, args.join(" "));
    log.flush()?;

    #[cfg(target_os = "macos")]
    {
        // On macOS, use posix_spawn via Command
        let child = Command::new(command)
            .args(args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::null())
            .spawn()?;

        // Get the process ID
        let pid = child.id();

        // Detach the child process
        std::thread::spawn(move || {
            let _ = child.wait_with_output();
        });

        Ok(pid)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let child = Command::new(command)
            .args(args)
            .stdout(log)
            .stderr(Stdio::null())
            .spawn()?;
        Ok(child.id())
    }
}

pub fn spawn_process_debug(command: &str, args: &[&str]) -> io::Result<(u32, String, i32)> {
    if !safety_path::is_path_safe(command) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Unsafe command path: {}", command),
        ));
    }

    let child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id();
    let output = child.wait_with_output()?;

    // Combine stdout and stderr
    let mut combined_output = String::new();
    if !output.stdout.is_empty() {
        combined_output.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        if !combined_output.is_empty() {
            combined_output.push('\n');
        }
        combined_output.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    // Get the exit code
    let exit_code = output.status.code().unwrap_or(-1);

    Ok((pid, combined_output, exit_code))
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32) -> io::Result<()> {
    let taskkill_args = &["/F", "/PID", &pid.to_string()];
    Command::new("taskkill").args(taskkill_args).output()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn kill_process(pid: u32) -> io::Result<()> {
    let kill_args = &["-9", &pid.to_string()];
    let output: Output = Command::new("kill").args(kill_args).output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Kill command failed: {:?}", output),
        ))
    }
}

#[cfg(target_os = "windows")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    if !safety_args::is_verge_mat_process_name(process_name) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Unsafe process name: {}", process_name),
        ));
    }

    let output = Command::new("tasklist")
        .args(&["/FO", "CSV", "/NH"])
        .output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in output_str.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let name = parts[0].trim_matches('"');
            if name.to_lowercase().contains(&process_name.to_lowercase()) {
                if let Some(pid_str) = parts[1].trim_matches('"').split_whitespace().next() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    Ok(pids)
}

#[cfg(target_os = "linux")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    if !safety_args::is_verge_mat_process_name(process_name) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Unsafe process name: {}", process_name),
        ));
    }

    let output = Command::new("pgrep").arg("-f").arg(process_name).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }

    Ok(pids)
}

#[cfg(target_os = "macos")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    if !safety_args::is_verge_mat_process_name(process_name) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Unsafe process name: {}", process_name),
        ));
    }

    let output = Command::new("pgrep").arg("-f").arg(process_name).output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();

    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }

    Ok(pids)
}
