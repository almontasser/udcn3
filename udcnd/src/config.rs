use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub pid_file: String,
    pub user: Option<String>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub bind_address: String,
    pub port: u16,
    pub max_connections: usize,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig {
                pid_file: "/var/run/udcnd.pid".to_string(),
                user: None,
                group: None,
            },
            network: NetworkConfig {
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
                max_connections: 1000,
                interface: "eth0".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
        }
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}
