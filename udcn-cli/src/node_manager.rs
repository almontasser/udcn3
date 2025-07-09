use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use log::{info, warn, error};

/// Node information stored in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub address: SocketAddr,
    pub status: NodeStatus,
    pub last_seen: Option<u64>, // Unix timestamp
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Status of a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Online,
    Offline,
    Unknown,
}

/// Registry for managing known nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistry {
    pub nodes: HashMap<String, NodeInfo>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Add a node to the registry
    pub fn add_node(&mut self, id: String, address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        if self.nodes.contains_key(&id) {
            return Err(format!("Node with ID '{}' already exists", id).into());
        }

        let node_info = NodeInfo {
            id: id.clone(),
            address,
            status: NodeStatus::Unknown,
            last_seen: None,
            capabilities: Vec::new(),
            metadata: HashMap::new(),
        };

        self.nodes.insert(id.clone(), node_info);
        info!("Added node '{}' at {}", id, address);
        Ok(())
    }

    /// Remove a node from the registry
    pub fn remove_node(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(_) = self.nodes.remove(id) {
            info!("Removed node '{}'", id);
            Ok(())
        } else {
            Err(format!("Node with ID '{}' not found", id).into())
        }
    }

    /// Get node information
    pub fn get_node(&self, id: &str) -> Option<&NodeInfo> {
        self.nodes.get(id)
    }

    /// List all nodes
    pub fn list_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes.values().collect()
    }

    /// Update node status
    pub fn update_node_status(&mut self, id: &str, status: NodeStatus) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.status = status;
            node.last_seen = Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());
        }
    }

    /// Update node capabilities
    pub fn update_node_capabilities(&mut self, id: &str, capabilities: Vec<String>) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.capabilities = capabilities;
        }
    }

    /// Add metadata to a node
    pub fn add_node_metadata(&mut self, id: &str, key: String, value: String) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.metadata.insert(key, value);
        }
    }
}

/// Node manager for CLI operations
pub struct NodeManager {
    registry_path: PathBuf,
    registry: NodeRegistry,
}

impl NodeManager {
    pub fn new(registry_path: Option<PathBuf>) -> Self {
        let registry_path = registry_path
            .unwrap_or_else(|| PathBuf::from("/etc/udcn/nodes.json"));

        let registry = Self::load_registry(&registry_path)
            .unwrap_or_else(|e| {
                warn!("Failed to load node registry: {}, using empty registry", e);
                NodeRegistry::new()
            });

        Self {
            registry_path,
            registry,
        }
    }

    /// Load node registry from file
    fn load_registry(path: &PathBuf) -> Result<NodeRegistry, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(NodeRegistry::new());
        }

        let content = fs::read_to_string(path)?;
        let registry: NodeRegistry = serde_json::from_str(&content)?;
        Ok(registry)
    }

    /// Save node registry to file
    fn save_registry(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.registry_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&self.registry)?;
        fs::write(&self.registry_path, content)?;
        Ok(())
    }

    /// Add a node
    pub fn add_node(&mut self, id: String, address_str: String) -> Result<(), Box<dyn std::error::Error>> {
        let address: SocketAddr = address_str.parse()?;
        self.registry.add_node(id, address)?;
        self.save_registry()?;
        Ok(())
    }

    /// Remove a node
    pub fn remove_node(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.registry.remove_node(id)?;
        self.save_registry()?;
        Ok(())
    }

    /// List all nodes
    pub fn list_nodes(&self) -> Vec<&NodeInfo> {
        self.registry.list_nodes()
    }

    /// Get node details
    pub fn get_node(&self, id: &str) -> Option<&NodeInfo> {
        self.registry.get_node(id)
    }

    /// Ping a node to check connectivity
    pub async fn ping_node(&mut self, id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let node = self.registry.get_node(id)
            .ok_or_else(|| format!("Node '{}' not found", id))?;

        // Try to connect to the node
        let address = node.address;
        info!("Pinging node '{}' at {}", id, address);

        // Simple TCP connection test
        let result = tokio::net::TcpStream::connect(address).await;
        let is_online = result.is_ok();

        // Update node status
        let status = if is_online {
            NodeStatus::Online
        } else {
            NodeStatus::Offline
        };

        self.registry.update_node_status(id, status);
        self.save_registry()?;

        Ok(is_online)
    }

    /// Discover nodes on the network
    pub async fn discover_nodes(&mut self) -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        info!("Starting network discovery for nodes");
        
        // TODO: Implement actual network discovery
        // For now, return empty list and explain the limitation
        warn!("Network discovery not yet implemented");
        
        // Mock discovery - in a real implementation, this would:
        // 1. Scan common UDP/TCP ports for UDCN nodes
        // 2. Use multicast discovery
        // 3. Check known neighbor lists
        // 4. Use NDN name discovery
        
        Ok(Vec::new())
    }

    /// Get network status summary
    pub fn get_network_status(&self) -> NetworkStatus {
        let nodes = self.registry.list_nodes();
        let total_nodes = nodes.len();
        
        let online_nodes = nodes.iter()
            .filter(|n| matches!(n.status, NodeStatus::Online))
            .count();
        
        let offline_nodes = nodes.iter()
            .filter(|n| matches!(n.status, NodeStatus::Offline))
            .count();
        
        let unknown_nodes = total_nodes - online_nodes - offline_nodes;

        NetworkStatus {
            total_nodes,
            online_nodes,
            offline_nodes,
            unknown_nodes,
        }
    }
}

/// Network status summary
#[derive(Debug)]
pub struct NetworkStatus {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub offline_nodes: usize,
    pub unknown_nodes: usize,
}

impl NetworkStatus {
    pub fn format(&self) -> String {
        format!(
            "Network Status:\n  Total nodes: {}\n  Online: {}\n  Offline: {}\n  Unknown: {}",
            self.total_nodes,
            self.online_nodes,
            self.offline_nodes,
            self.unknown_nodes
        )
    }
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Online => write!(f, "Online"),
            NodeStatus::Offline => write!(f, "Offline"),
            NodeStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for NodeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last_seen = if let Some(timestamp) = self.last_seen {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let diff = now - timestamp;
            if diff < 60 {
                format!("{}s ago", diff)
            } else if diff < 3600 {
                format!("{}m ago", diff / 60)
            } else if diff < 86400 {
                format!("{}h ago", diff / 3600)
            } else {
                format!("{}d ago", diff / 86400)
            }
        } else {
            "Never".to_string()
        };

        write!(
            f,
            "Node ID: {}\n  Address: {}\n  Status: {}\n  Last seen: {}\n  Capabilities: {:?}",
            self.id,
            self.address,
            self.status,
            last_seen,
            self.capabilities
        )
    }
}