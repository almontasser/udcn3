use std::io::Write;
use std::process::{Command, Stdio};
use std::path::PathBuf;
use std::fs;
use std::time::Duration;
use log::{info, warn, error};
use tokio::time::sleep;

/// Daemon client for managing the UDCN daemon process
pub struct DaemonClient {
    config_path: PathBuf,
    pid_file: PathBuf,
}

impl DaemonClient {
    pub fn new(config_path: Option<&str>) -> Self {
        let config_path = config_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/udcn/udcnd.conf"));
        
        let pid_file = PathBuf::from("/var/run/udcnd.pid");
        
        Self {
            config_path,
            pid_file,
        }
    }

    /// Start the daemon process
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Check if daemon is already running
        if self.is_running().await? {
            return Err("Daemon is already running".into());
        }

        info!("Starting UDCN daemon");

        // Find the udcnd binary
        let udcnd_path = self.find_udcnd_binary()?;
        
        // Start the daemon process
        let mut child = Command::new(udcnd_path)
            .arg("--config")
            .arg(&self.config_path)
            .arg("--daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for a short time to see if the process starts successfully
        sleep(Duration::from_millis(500)).await;

        // Check if the child process is still running
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("Daemon failed to start, exited with status: {}", status).into());
            }
            Ok(None) => {
                // Process is still running, good
                info!("Daemon started successfully with PID: {}", child.id());
                
                // Write PID file
                if let Err(e) = fs::write(&self.pid_file, format!("{}", child.id())) {
                    warn!("Failed to write PID file: {}", e);
                }
                
                // Detach from the child process
                std::mem::forget(child);
                
                Ok(())
            }
            Err(e) => {
                return Err(format!("Failed to check daemon status: {}", e).into());
            }
        }
    }

    /// Stop the daemon process
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let pid = self.get_daemon_pid().await?;
        
        if pid.is_none() {
            return Err("Daemon is not running".into());
        }

        let pid = pid.unwrap();
        info!("Stopping UDCN daemon (PID: {})", pid);

        // Send SIGTERM to the process
        let result = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();

        match result {
            Ok(status) if status.success() => {
                // Wait for the process to terminate
                let mut attempts = 0;
                while attempts < 30 {
                    if !self.is_running().await? {
                        info!("Daemon stopped successfully");
                        
                        // Remove PID file
                        if let Err(e) = fs::remove_file(&self.pid_file) {
                            warn!("Failed to remove PID file: {}", e);
                        }
                        
                        return Ok(());
                    }
                    
                    sleep(Duration::from_millis(100)).await;
                    attempts += 1;
                }

                // If still running, try SIGKILL
                warn!("Daemon did not stop gracefully, sending SIGKILL");
                let kill_result = Command::new("kill")
                    .arg("-KILL")
                    .arg(pid.to_string())
                    .status();

                match kill_result {
                    Ok(status) if status.success() => {
                        info!("Daemon forcefully stopped");
                        
                        // Remove PID file
                        if let Err(e) = fs::remove_file(&self.pid_file) {
                            warn!("Failed to remove PID file: {}", e);
                        }
                        
                        Ok(())
                    }
                    Ok(status) => Err(format!("Failed to kill daemon: exit code {}", status.code().unwrap_or(-1)).into()),
                    Err(e) => Err(format!("Failed to kill daemon: {}", e).into()),
                }
            }
            Ok(status) => Err(format!("Failed to stop daemon: exit code {}", status.code().unwrap_or(-1)).into()),
            Err(e) => Err(format!("Failed to stop daemon: {}", e).into()),
        }
    }

    /// Restart the daemon process
    pub async fn restart(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Restarting UDCN daemon");
        
        // Stop the daemon if running
        if self.is_running().await? {
            self.stop().await?;
        }
        
        // Start the daemon again
        self.start().await?;
        
        Ok(())
    }

    /// Get the status of the daemon
    pub async fn status(&self) -> Result<DaemonStatus, Box<dyn std::error::Error>> {
        let pid = self.get_daemon_pid().await?;
        
        if let Some(pid) = pid {
            if self.is_process_running(pid).await? {
                Ok(DaemonStatus {
                    running: true,
                    pid: Some(pid),
                    uptime: self.get_process_uptime(pid).await.ok(),
                })
            } else {
                // PID file exists but process is not running
                warn!("PID file exists but process is not running, cleaning up");
                if let Err(e) = fs::remove_file(&self.pid_file) {
                    warn!("Failed to remove stale PID file: {}", e);
                }
                
                Ok(DaemonStatus {
                    running: false,
                    pid: None,
                    uptime: None,
                })
            }
        } else {
            Ok(DaemonStatus {
                running: false,
                pid: None,
                uptime: None,
            })
        }
    }

    /// Check if the daemon is running
    pub async fn is_running(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let status = self.status().await?;
        Ok(status.running)
    }

    /// Get the daemon PID from the PID file
    async fn get_daemon_pid(&self) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        if !self.pid_file.exists() {
            return Ok(None);
        }

        let pid_str = fs::read_to_string(&self.pid_file)?;
        let pid = pid_str.trim().parse::<u32>()?;
        Ok(Some(pid))
    }

    /// Check if a process with the given PID is running
    async fn is_process_running(&self, pid: u32) -> Result<bool, Box<dyn std::error::Error>> {
        let result = Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .output();

        match result {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    /// Get the uptime of a process
    async fn get_process_uptime(&self, pid: u32) -> Result<Duration, Box<dyn std::error::Error>> {
        let output = Command::new("ps")
            .arg("-o")
            .arg("etime=")
            .arg("-p")
            .arg(pid.to_string())
            .output()?;

        if !output.status.success() {
            return Err("Failed to get process uptime".into());
        }

        let etime_str = String::from_utf8(output.stdout)?;
        let etime = etime_str.trim();
        
        // Parse the elapsed time format (e.g., "1-02:34:56" or "02:34:56" or "34:56")
        let duration = self.parse_elapsed_time(etime)?;
        Ok(duration)
    }

    /// Parse ps elapsed time format
    fn parse_elapsed_time(&self, etime: &str) -> Result<Duration, Box<dyn std::error::Error>> {
        // Handle different formats:
        // "1-02:34:56" (days-hours:minutes:seconds)
        // "02:34:56" (hours:minutes:seconds)
        // "34:56" (minutes:seconds)
        // "56" (seconds)
        
        let parts: Vec<&str> = etime.split('-').collect();
        let (days, time_part) = if parts.len() == 2 {
            (parts[0].parse::<u64>().unwrap_or(0), parts[1])
        } else {
            (0, etime)
        };

        let time_parts: Vec<&str> = time_part.split(':').collect();
        let (hours, minutes, seconds) = match time_parts.len() {
            3 => (
                time_parts[0].parse::<u64>().unwrap_or(0),
                time_parts[1].parse::<u64>().unwrap_or(0),
                time_parts[2].parse::<u64>().unwrap_or(0),
            ),
            2 => (
                0,
                time_parts[0].parse::<u64>().unwrap_or(0),
                time_parts[1].parse::<u64>().unwrap_or(0),
            ),
            1 => (0, 0, time_parts[0].parse::<u64>().unwrap_or(0)),
            _ => return Err("Invalid time format".into()),
        };

        let total_seconds = days * 24 * 3600 + hours * 3600 + minutes * 60 + seconds;
        Ok(Duration::from_secs(total_seconds))
    }

    /// Find the udcnd binary in the PATH or in common locations
    fn find_udcnd_binary(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        // First, try to find udcnd in PATH
        if let Ok(output) = Command::new("which").arg("udcnd").output() {
            if output.status.success() {
                let path_str = String::from_utf8(output.stdout)?;
                return Ok(PathBuf::from(path_str.trim()));
            }
        }

        // Try common locations
        let common_paths = [
            "/usr/local/bin/udcnd",
            "/usr/bin/udcnd",
            "/opt/udcn/bin/udcnd",
            "./target/release/udcnd",
            "./target/debug/udcnd",
        ];

        for path in &common_paths {
            let path_buf = PathBuf::from(path);
            if path_buf.exists() {
                return Ok(path_buf);
            }
        }

        Err("udcnd binary not found".into())
    }
}

/// Status information for the daemon
#[derive(Debug)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime: Option<Duration>,
}

impl DaemonStatus {
    pub fn format(&self) -> String {
        if self.running {
            let uptime_str = if let Some(uptime) = self.uptime {
                format_duration(uptime)
            } else {
                "unknown".to_string()
            };
            
            format!(
                "Daemon is running (PID: {}, Uptime: {})",
                self.pid.unwrap_or(0),
                uptime_str
            )
        } else {
            "Daemon is not running".to_string()
        }
    }
}

/// Format a duration in human-readable format
fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let days = total_seconds / (24 * 3600);
    let hours = (total_seconds % (24 * 3600)) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}