use super::{
    data::{ClashStatus, CoreManager, MatStatus, StartBody, StatusInner},
    process,
};
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, Mutex},
};

impl CoreManager {
    pub fn new() -> Self {
        CoreManager {
            clash_status: StatusInner::new(ClashStatus::default()),
            mat_status: StatusInner::new(MatStatus::default()),
        }
    }

    pub fn test_config_file(&self) -> Result<(), String> {
        let config = match self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone()
        {
            Some(config) => config,
            None => return Err("Runtime config is not set".to_string()),
        };

        let bin_path = config.bin_path.as_str();
        let config_dir = config.config_dir.as_str();
        let config_file = config.config_file.as_str();
        let args = vec!["-d", config_dir, "-f", config_file, "-t"];

        println!(
            "Testing config file with bin_path: {}, config_dir: {}, config_file: {}",
            bin_path, config_dir, config_file
        );

        let result = process::spawn_process_debug(bin_path, &args)
            .map_err(|e| format!("Failed to execute config test: {}", e))?;

        let (_pid, output, _exit_code) = result;

        let mut errors: Vec<String> = Vec::new();
        for line in output.lines() {
            if line.contains("fata") || line.contains("error") {
                if let Some(pos) = line.find("msg=") {
                    if pos + 1 < line.len() {
                        let message = line[(pos + 4)..].trim().replace("'", "").replace('"', "");
                        let prefix = "[broken]";
                        errors.push(format!("{} {}", prefix, message));
                    }
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("\n"));
        }

        println!("Config test passed successfully");
        Ok(())
    }
}

impl CoreManager {
    pub fn get_version(&self) -> Result<HashMap<String, String>> {
        let current_pid = std::process::id() as i32;
        println!("Current PID: {}", current_pid);
        Ok(HashMap::from([
            ("service".into(), "Clash Verge Service".into()),
            ("version".into(), env!("CARGO_PKG_VERSION").into()),
        ]))
    }

    pub fn get_clash_status(&self) -> Result<StartBody> {
        let runtime_config = self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone();
        if runtime_config.is_none() {
            return Ok(StartBody::default());
        }
        Ok(runtime_config.as_ref().unwrap().clone())
    }

    pub fn start_mat(&self) -> Result<()> {
        println!("Starting mat with config");

        {
            let is_running_mat = self
                .mat_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .load(Ordering::Relaxed);
            let mat_running_pid = self
                .mat_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .load(Ordering::Relaxed);

            if is_running_mat && mat_running_pid > 0 {
                println!("Mat is already running, stopping it first");
                let _ = self.stop_mat();
                println!("Mat stopped successfully");
            }
        }

        // 检测并停止系统中其他可能运行的verge-mat进程
        self.stop_other_mat_processes()?;

        {
            // Get runtime config
            let config = self
                .clash_status
                .inner
                .lock()
                .unwrap()
                .runtime_config
                .lock()
                .unwrap()
                .clone();
            let config = config.ok_or(anyhow!("Runtime config is not set"))?;

            let bin_path = config.bin_path.as_str();
            let config_dir = config.config_dir.as_str();
            let config_file = config.config_file.as_str();
            let log_file = config.log_file.as_str();
            let args = vec!["-d", config_dir, "-f", config_file];

            println!(
                "Starting mat with bin_path: {}, config_dir: {}, config_file: {}, log_file: {}",
                bin_path, config_dir, config_file, log_file
            );

            // Open log file
            let log = std::fs::File::create(log_file)
                .with_context(|| format!("Failed to open log file: {}", log_file))?;

            // Spawn process
            let pid = process::spawn_process(bin_path, &args, log)?;
            println!("Mat started with PID: {}", pid);

            // Update mat status
            self.mat_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .store(pid as i32, Ordering::Relaxed);
            self.mat_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .store(true, Ordering::Relaxed);
            println!("Mat started successfully with PID: {}", pid);
        }

        Ok(())
    }

    pub fn stop_mat(&self) -> Result<()> {
        let mat_pid = self
            .mat_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed);
        if mat_pid <= 0 {
            println!("No running mat process found");
            return Ok(());
        }
        println!("Stopping mat process {}", mat_pid);

        let result = super::process::kill_process(mat_pid as u32)
            .with_context(|| format!("Failed to kill mat process with PID: {}", mat_pid));

        match result {
            Ok(_) => {
                println!("Mat process {} stopped successfully", mat_pid);
            }
            Err(e) => {
                eprintln!("Error killing mat process: {}", e);
            }
        }

        self.mat_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .store(-1, Ordering::Relaxed);
        self.mat_status
            .inner
            .lock()
            .unwrap()
            .is_running
            .store(false, Ordering::Relaxed);
        Ok(())
    }

    // 检测并停止其他verge-mat进程
    pub fn stop_other_mat_processes(&self) -> Result<()> {
        // 获取当前进程的PID
        let current_pid = std::process::id();
        let tracked_mat_pid = self
            .mat_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed) as u32;
        
        match process::find_processes("verge-mat") {
            Ok(pids) => {
                // 直接在迭代过程中过滤和终止
                let kill_count = pids.into_iter()
                    .filter(|&pid| pid != current_pid && (tracked_mat_pid <= 0 || pid != tracked_mat_pid))
                    .map(|pid| {
                        println!("Found other verge-mat process with PID: {}, stopping it", pid);
                        match process::kill_process(pid) {
                            Ok(_) => {
                                println!("Successfully stopped verge-mat process {}", pid);
                                true
                            }
                            Err(e) => {
                                eprintln!("Failed to kill verge-mat process {}: {}", pid, e);
                                false
                            }
                        }
                    })
                    .filter(|&success| success)
                    .count();
                    
                println!("Successfully stopped {} verge-mat processes", kill_count);
            }
            Err(e) => {
                eprintln!("Error finding verge-mat processes: {}", e);
            }
        }
        
        Ok(())
    }

    pub fn start_clash(&self, body: StartBody) -> Result<(), String> {
        {
            // Check clash & stop if needed
            let is_running_clash = self
                .clash_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .load(Ordering::Relaxed);
            let clash_running_pid = self
                .clash_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .load(Ordering::Relaxed);
            let current_pid = std::process::id() as i32;

            if is_running_clash && clash_running_pid == current_pid {
                println!("Clash is already running with pid: {}", current_pid);
            }
            if !is_running_clash && clash_running_pid <= 0 {
                let current_pid = std::process::id() as i32;
                println!("Clash is start running with pid: {}", current_pid);
                self.clash_status
                    .inner
                    .lock()
                    .unwrap()
                    .running_pid
                    .store(current_pid, Ordering::Relaxed);
                self.clash_status
                    .inner
                    .lock()
                    .unwrap()
                    .is_running
                    .store(true, Ordering::Relaxed);
                println!("done");
            }
        }

        {
            println!("Setting clash runtime config with config: {:?}", body);
            self.clash_status.inner.lock().unwrap().runtime_config =
                Arc::new(Mutex::new(Some(body.clone())));
            println!("Testing config file");
            self.test_config_file()?;
        }

        {
            // Check mat & stop if needed
            println!("Checking if mat is running before start clash");
            let is_mat_running = self
                .mat_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .load(Ordering::Relaxed);
            let mat_running_pid = self
                .mat_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .load(Ordering::Relaxed);

            if is_mat_running && mat_running_pid > 0 {
                println!("Mat is running, stopping it first");
                let _ = self.stop_mat();
                let _ = self.start_mat();
            } else {
                println!("Mat is not running, starting it");
                let _ = self.start_mat();
            }
        }

        println!("Clash started successfully");
        Ok(())
    }

    pub fn stop_clash(&self) -> Result<()> {
        let clash_pid = self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed);
        if clash_pid <= 0 {
            println!("No running clash process found");
            return Ok(());
        }
        println!("Stopping clash process {}", clash_pid);

        if let Err(e) = super::process::kill_process(clash_pid as u32)
            .with_context(|| format!("Failed to kill clash process with PID: {}", clash_pid))
        {
            eprintln!("Error killing clash process: {}", e);
        }

        // 同时停止mat进程和其他verge-mat进程
        let _ = self.stop_mat();
        let _ = self.stop_other_mat_processes();

        println!("Clash process {} stopped successfully", clash_pid);
        Ok(())
    }
}

// 全局静态的 CoreManager 实例
pub static COREMANAGER: Lazy<Arc<Mutex<CoreManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(CoreManager::new())));
