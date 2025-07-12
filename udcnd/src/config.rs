use std::{fs, path::Path, sync::{Arc, Mutex}};
use notify::{Watcher, RecursiveMode, Event};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub network: NetworkConfig,
    pub routing: RoutingConfigSection,
    pub logging: LoggingConfig,
    #[serde(skip)]
    pub runtime: RuntimeConfig,
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
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,
}

fn default_transport_protocol() -> String {
    "udp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfigSection {
    pub fib_entries: Vec<FibEntry>,
    pub default_strategy: String,
    pub enable_interest_aggregation: bool,
    pub enable_content_store: bool,
    pub max_next_hops: usize,
    pub pit_lifetime_ms: u64,
    pub content_store_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FibEntry {
    pub prefix: String,
    pub next_hop: String,
    pub cost: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub config_path: String,
    pub last_reload: std::time::SystemTime,
    pub reload_count: u64,
    pub validation_enabled: bool,
    pub rollback_enabled: bool,
    pub backup_configs: std::collections::VecDeque<Config>,
    pub max_backups: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            config_path: "/etc/udcn/udcnd.conf".to_string(),
            last_reload: std::time::SystemTime::now(),
            reload_count: 0,
            validation_enabled: true,
            rollback_enabled: true,
            backup_configs: std::collections::VecDeque::new(),
            max_backups: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigPolicy {
    pub section: ConfigSection,
    pub hot_reload_allowed: bool,
    pub validation_required: bool,
    pub admin_only: bool,
    pub restart_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfigSection {
    Daemon,
    Network,
    Routing,
    Logging,
    All,
}

#[derive(Debug)]
pub enum ConfigError {
    ValidationFailed(String),
    PolicyViolation(String),
    ReloadFailed(String),
    BackupFailed(String),
    InvalidSection(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::ValidationFailed(msg) => write!(f, "Configuration validation failed: {}", msg),
            ConfigError::PolicyViolation(msg) => write!(f, "Configuration policy violation: {}", msg),
            ConfigError::ReloadFailed(msg) => write!(f, "Configuration reload failed: {}", msg),
            ConfigError::BackupFailed(msg) => write!(f, "Configuration backup failed: {}", msg),
            ConfigError::InvalidSection(msg) => write!(f, "Invalid configuration section: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

pub struct ConfigManager {
    policies: std::collections::HashMap<ConfigSection, ConfigPolicy>,
    file_watcher: Option<notify::RecommendedWatcher>,
}

impl Default for ConfigManager {
    fn default() -> Self {
        let mut policies = std::collections::HashMap::new();
        
        // Define default policies for each section
        policies.insert(ConfigSection::Daemon, ConfigPolicy {
            section: ConfigSection::Daemon,
            hot_reload_allowed: false,
            validation_required: true,
            admin_only: true,
            restart_required: true,
        });
        
        policies.insert(ConfigSection::Network, ConfigPolicy {
            section: ConfigSection::Network,
            hot_reload_allowed: true,
            validation_required: true,
            admin_only: false,
            restart_required: false,
        });
        
        policies.insert(ConfigSection::Logging, ConfigPolicy {
            section: ConfigSection::Logging,
            hot_reload_allowed: true,
            validation_required: false,
            admin_only: false,
            restart_required: false,
        });
        
        policies.insert(ConfigSection::Routing, ConfigPolicy {
            section: ConfigSection::Routing,
            hot_reload_allowed: true,
            validation_required: true,
            admin_only: false,
            restart_required: false,
        });
        
        Self {
            policies,
            file_watcher: None,
        }
    }
}
impl ConfigManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set up file system watcher for configuration file
    pub fn setup_file_watcher(&mut self, config_path: &str, callback: Arc<Mutex<dyn Fn() + Send>>) -> Result<(), ConfigError> {
        let (tx, rx) = std::sync::mpsc::channel();
        
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        let _ = tx.send(());
                    }
                },
                Err(e) => eprintln!("File watcher error: {:?}", e),
            }
        }).map_err(|e| ConfigError::ReloadFailed(format!("Failed to create file watcher: {}", e)))?;

        watcher.watch(std::path::Path::new(config_path), RecursiveMode::NonRecursive)
            .map_err(|e| ConfigError::ReloadFailed(format!("Failed to watch config file: {}", e)))?;

        // Spawn background thread to handle file change events
        std::thread::spawn(move || {
            while rx.recv().is_ok() {
                if let Ok(callback) = callback.lock() {
                    callback();
                }
            }
        });

        self.file_watcher = Some(watcher);
        Ok(())
    }

    /// Get policy for a configuration section
    pub fn get_policy(&self, section: &ConfigSection) -> Option<&ConfigPolicy> {
        self.policies.get(section)
    }

    /// Update policy for a configuration section
    pub fn set_policy(&mut self, section: ConfigSection, policy: ConfigPolicy) {
        self.policies.insert(section, policy);
    }

    /// Check if hot reload is allowed for a section
    pub fn can_hot_reload(&self, section: &ConfigSection) -> bool {
        self.policies.get(section)
            .map(|p| p.hot_reload_allowed)
            .unwrap_or(false)
    }

    /// Check if validation is required for a section
    pub fn requires_validation(&self, section: &ConfigSection) -> bool {
        self.policies.get(section)
            .map(|p| p.validation_required)
            .unwrap_or(true)
    }

    /// Check if admin privileges are required for a section
    pub fn requires_admin(&self, section: &ConfigSection) -> bool {
        self.policies.get(section)
            .map(|p| p.admin_only)
            .unwrap_or(true)
    }

    /// Check if restart is required after updating a section
    pub fn requires_restart(&self, section: &ConfigSection) -> bool {
        self.policies.get(section)
            .map(|p| p.restart_required)
            .unwrap_or(true)
    }

    /// Get all policies
    pub fn get_all_policies(&self) -> &std::collections::HashMap<ConfigSection, ConfigPolicy> {
        &self.policies
    }
}

/// Administrative interface for configuration management
pub struct ConfigAdmin {
    pub config: Arc<Mutex<Config>>,
    manager: Arc<Mutex<ConfigManager>>,
}

impl ConfigAdmin {
    pub fn new(config: Arc<Mutex<Config>>, manager: Arc<Mutex<ConfigManager>>) -> Self {
        Self { config, manager }
    }

    /// Get current configuration as TOML string
    pub fn get_config(&self) -> Result<String, ConfigError> {
        let config = self.config.lock().unwrap();
        config.to_toml()
    }

    /// Update configuration from TOML string
    pub fn update_config(&self, toml_str: &str) -> Result<(), ConfigError> {
        let manager = self.manager.lock().unwrap();
        let mut config = self.config.lock().unwrap();
        config.from_toml(toml_str, &manager)
    }

    /// Get configuration section as TOML
    pub fn get_section(&self, section: ConfigSection) -> Result<String, ConfigError> {
        let config = self.config.lock().unwrap();
        
        match section {
            ConfigSection::Daemon => {
                toml::to_string_pretty(&config.daemon)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to serialize daemon config: {}", e)))
            },
            ConfigSection::Network => {
                toml::to_string_pretty(&config.network)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to serialize network config: {}", e)))
            },
            ConfigSection::Logging => {
                toml::to_string_pretty(&config.logging)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to serialize logging config: {}", e)))
            },
            ConfigSection::Routing => {
                toml::to_string_pretty(&config.routing)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to serialize routing config: {}", e)))
            },
            ConfigSection::All => config.to_toml(),
        }
    }

    /// Update specific configuration section
    pub fn update_section(&self, section: ConfigSection, toml_str: &str) -> Result<bool, ConfigError> {
        let manager = self.manager.lock().unwrap();
        let mut config = self.config.lock().unwrap();
        
        // Check policy for this section
        let policy = manager.get_policy(&section)
            .ok_or_else(|| ConfigError::InvalidSection(format!("No policy for section: {:?}", section)))?;

        if !policy.hot_reload_allowed {
            return Err(ConfigError::PolicyViolation(
                format!("Hot reload not allowed for section: {:?}", section)
            ));
        }

        // Create backup
        if config.runtime.rollback_enabled {
            config.create_backup();
        }

        // Parse and apply section-specific configuration
        match section {
            ConfigSection::Daemon => {
                let daemon_config: DaemonConfig = toml::from_str(toml_str)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to parse daemon config: {}", e)))?;
                config.daemon = daemon_config;
            },
            ConfigSection::Network => {
                let network_config: NetworkConfig = toml::from_str(toml_str)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to parse network config: {}", e)))?;
                config.network = network_config;
            },
            ConfigSection::Logging => {
                let logging_config: LoggingConfig = toml::from_str(toml_str)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to parse logging config: {}", e)))?;
                config.logging = logging_config;
            },
            ConfigSection::Routing => {
                let routing_config: RoutingConfigSection = toml::from_str(toml_str)
                    .map_err(|e| ConfigError::ValidationFailed(format!("Failed to parse routing config: {}", e)))?;
                config.routing = routing_config;
            },
            ConfigSection::All => {
                return self.update_config(toml_str).map(|_| true);
            },
        }

        // Validate if required
        if policy.validation_required {
            config.validate(&manager)?;
        }

        config.runtime.last_reload = std::time::SystemTime::now();
        
        // Return whether restart is required
        Ok(policy.restart_required)
    }

    /// Reload configuration from file
    pub fn reload_from_file(&self) -> Result<(), ConfigError> {
        let manager = self.manager.lock().unwrap();
        let mut config = self.config.lock().unwrap();
        config.reload(&manager)
    }

    /// Rollback to previous configuration
    pub fn rollback(&self) -> Result<(), ConfigError> {
        let mut config = self.config.lock().unwrap();
        config.rollback()
    }

    /// Get runtime information
    pub fn get_runtime_info(&self) -> (std::time::SystemTime, u64, usize) {
        let config = self.config.lock().unwrap();
        (
            config.runtime.last_reload,
            config.runtime.reload_count,
            config.runtime.backup_configs.len()
        )
    }

    /// Validate current configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        let manager = self.manager.lock().unwrap();
        let config = self.config.lock().unwrap();
        config.validate(&manager)
    }

    /// Save current configuration to file
    pub fn save_to_file(&self) -> Result<(), ConfigError> {
        let config = self.config.lock().unwrap();
        config.save(&config.runtime.config_path)
            .map_err(|e| ConfigError::ReloadFailed(format!("Failed to save config: {}", e)))
    }
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
                interface: "ens160".to_string(),
                transport_protocol: "udp".to_string(),
            },
            routing: RoutingConfigSection {
                fib_entries: vec![
                    FibEntry {
                        prefix: "/".to_string(),
                        next_hop: "127.0.0.1:6363".to_string(),
                        cost: 1,
                        enabled: true,
                    },
                ],
                default_strategy: "BestRoute".to_string(),
                enable_interest_aggregation: true,
                enable_content_store: true,
                max_next_hops: 10,
                pit_lifetime_ms: 4000,
                content_store_size: 1000,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
            runtime: RuntimeConfig::default(),
        }
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.as_ref().exists() {
            let mut config = Self::default();
            config.runtime.config_path = path.as_ref().to_string_lossy().to_string();
            return Ok(config);
        }

        let contents = fs::read_to_string(&path)?;
        let mut config: Config = toml::from_str(&contents)?;
        config.runtime.config_path = path.as_ref().to_string_lossy().to_string();
        config.runtime.last_reload = std::time::SystemTime::now();
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    /// Reload configuration from file with validation and backup
    pub fn reload(&mut self, manager: &ConfigManager) -> Result<(), ConfigError> {
        let backup = self.clone();
        
        // Create backup if enabled
        if self.runtime.rollback_enabled {
            self.create_backup();
        }

        // Load new configuration
        let new_config = match Self::load(&self.runtime.config_path) {
            Ok(config) => config,
            Err(e) => {
                return Err(ConfigError::ReloadFailed(format!("Failed to load config: {}", e)));
            }
        };

        // Validate configuration if required
        if self.runtime.validation_enabled {
            if let Err(e) = new_config.validate(manager) {
                return Err(e);
            }
        }

        // Apply new configuration
        self.daemon = new_config.daemon;
        self.network = new_config.network;
        self.routing = new_config.routing;
        self.logging = new_config.logging;
        self.runtime.last_reload = std::time::SystemTime::now();
        self.runtime.reload_count += 1;

        Ok(())
    }

    /// Validate configuration against policies
    pub fn validate(&self, manager: &ConfigManager) -> Result<(), ConfigError> {
        // Validate daemon configuration
        if let Some(policy) = manager.policies.get(&ConfigSection::Daemon) {
            if policy.validation_required {
                self.validate_daemon_config()?;
            }
        }

        // Validate network configuration
        if let Some(policy) = manager.policies.get(&ConfigSection::Network) {
            if policy.validation_required {
                self.validate_network_config()?;
            }
        }

        // Validate routing configuration
        if let Some(policy) = manager.policies.get(&ConfigSection::Routing) {
            if policy.validation_required {
                self.validate_routing_config()?;
            }
        }

        // Validate logging configuration
        if let Some(policy) = manager.policies.get(&ConfigSection::Logging) {
            if policy.validation_required {
                self.validate_logging_config()?;
            }
        }

        Ok(())
    }

    /// Create a backup of current configuration
    fn create_backup(&mut self) {
        let mut backup = self.clone();
        backup.runtime.backup_configs.clear(); // Don't backup the backups
        
        self.runtime.backup_configs.push_back(backup);
        
        // Maintain max backup limit
        while self.runtime.backup_configs.len() > self.runtime.max_backups {
            self.runtime.backup_configs.pop_front();
        }
    }

    /// Rollback to previous configuration
    pub fn rollback(&mut self) -> Result<(), ConfigError> {
        if !self.runtime.rollback_enabled {
            return Err(ConfigError::BackupFailed("Rollback is disabled".to_string()));
        }

        match self.runtime.backup_configs.pop_back() {
            Some(backup) => {
                self.daemon = backup.daemon;
                self.network = backup.network;
                self.routing = backup.routing;
                self.logging = backup.logging;
                self.runtime.last_reload = std::time::SystemTime::now();
                Ok(())
            }
            None => Err(ConfigError::BackupFailed("No backup available for rollback".to_string())),
        }
    }

    /// Update specific configuration section
    pub fn update_section(&mut self, section: ConfigSection, manager: &ConfigManager) -> Result<bool, ConfigError> {
        let policy = manager.policies.get(&section)
            .ok_or_else(|| ConfigError::InvalidSection(format!("No policy for section: {:?}", section)))?;

        if !policy.hot_reload_allowed {
            return Err(ConfigError::PolicyViolation(
                format!("Hot reload not allowed for section: {:?}", section)
            ));
        }

        // Return whether restart is required
        Ok(policy.restart_required)
    }

    /// Get configuration as TOML string for administrative interface
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self)
            .map_err(|e| ConfigError::ValidationFailed(format!("Failed to serialize config: {}", e)))
    }

    /// Update configuration from TOML string
    pub fn from_toml(&mut self, toml_str: &str, manager: &ConfigManager) -> Result<(), ConfigError> {
        let new_config: Config = toml::from_str(toml_str)
            .map_err(|e| ConfigError::ValidationFailed(format!("Failed to parse TOML: {}", e)))?;

        // Validate new configuration
        new_config.validate(manager)?;

        // Create backup
        if self.runtime.rollback_enabled {
            self.create_backup();
        }

        // Apply changes
        self.daemon = new_config.daemon;
        self.network = new_config.network;
        self.routing = new_config.routing;
        self.logging = new_config.logging;
        self.runtime.last_reload = std::time::SystemTime::now();

        Ok(())
    }

    /// Validate daemon configuration
    fn validate_daemon_config(&self) -> Result<(), ConfigError> {
        if self.daemon.pid_file.is_empty() {
            return Err(ConfigError::ValidationFailed("PID file path cannot be empty".to_string()));
        }

        // Validate PID file directory exists or can be created
        if let Some(parent) = std::path::Path::new(&self.daemon.pid_file).parent() {
            if !parent.exists() {
                return Err(ConfigError::ValidationFailed(
                    format!("PID file directory does not exist: {}", parent.display())
                ));
            }
        }

        Ok(())
    }

    /// Validate network configuration
    fn validate_network_config(&self) -> Result<(), ConfigError> {
        if self.network.bind_address.is_empty() {
            return Err(ConfigError::ValidationFailed("Bind address cannot be empty".to_string()));
        }

        // Validate bind address format
        if self.network.bind_address.parse::<std::net::IpAddr>().is_err() {
            return Err(ConfigError::ValidationFailed(
                format!("Invalid bind address: {}", self.network.bind_address)
            ));
        }

        // Validate port range
        if self.network.port == 0 {
            return Err(ConfigError::ValidationFailed("Port cannot be 0".to_string()));
        }

        // Validate max connections
        if self.network.max_connections == 0 {
            return Err(ConfigError::ValidationFailed("Max connections cannot be 0".to_string()));
        }

        // Validate interface name
        if self.network.interface.is_empty() {
            return Err(ConfigError::ValidationFailed("Interface name cannot be empty".to_string()));
        }

        // Validate transport protocol
        let valid_protocols = ["udp", "quic", "tcp", "unix"];
        if !valid_protocols.contains(&self.network.transport_protocol.as_str()) {
            return Err(ConfigError::ValidationFailed(
                format!("Invalid transport protocol: {}. Valid protocols: {:?}", 
                       self.network.transport_protocol, valid_protocols)
            ));
        }

        Ok(())
    }

    /// Validate routing configuration
    fn validate_routing_config(&self) -> Result<(), ConfigError> {
        // Validate default strategy
        let valid_strategies = ["BestRoute", "Multicast", "Broadcast", "LoadBalancing"];
        if !valid_strategies.contains(&self.routing.default_strategy.as_str()) {
            return Err(ConfigError::ValidationFailed(
                format!("Invalid default strategy: {}. Valid strategies: {:?}", 
                       self.routing.default_strategy, valid_strategies)
            ));
        }

        // Validate max_next_hops
        if self.routing.max_next_hops == 0 {
            return Err(ConfigError::ValidationFailed("Max next hops cannot be 0".to_string()));
        }

        // Validate pit_lifetime_ms
        if self.routing.pit_lifetime_ms == 0 {
            return Err(ConfigError::ValidationFailed("PIT lifetime cannot be 0".to_string()));
        }

        // Validate content_store_size
        if self.routing.content_store_size == 0 {
            return Err(ConfigError::ValidationFailed("Content store size cannot be 0".to_string()));
        }

        // Validate FIB entries
        for (index, entry) in self.routing.fib_entries.iter().enumerate() {
            if entry.prefix.is_empty() {
                return Err(ConfigError::ValidationFailed(
                    format!("FIB entry {} has empty prefix", index)
                ));
            }

            // Validate next_hop format (should be IP:port)
            if entry.next_hop.parse::<std::net::SocketAddr>().is_err() {
                return Err(ConfigError::ValidationFailed(
                    format!("FIB entry {} has invalid next hop format: {}", index, entry.next_hop)
                ));
            }

            // Validate cost
            if entry.cost == 0 {
                return Err(ConfigError::ValidationFailed(
                    format!("FIB entry {} has invalid cost: 0", index)
                ));
            }
        }

        Ok(())
    }

    /// Validate logging configuration
    fn validate_logging_config(&self) -> Result<(), ConfigError> {
        // Validate log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            return Err(ConfigError::ValidationFailed(
                format!("Invalid log level: {}. Valid levels: {:?}", self.logging.level, valid_levels)
            ));
        }

        // Validate log file path if specified
        if let Some(ref log_file) = self.logging.file {
            if let Some(parent) = std::path::Path::new(log_file).parent() {
                if !parent.exists() {
                    return Err(ConfigError::ValidationFailed(
                        format!("Log file directory does not exist: {}", parent.display())
                    ));
                }
            }
        }

        Ok(())
    }
}
