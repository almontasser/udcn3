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

    /// Discover nodes on the network using multicast and broadcast
    pub async fn discover_nodes(&mut self) -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        info!("Starting real network discovery for UDCN nodes");
        
        let mut discovered_nodes = Vec::new();
        
        // Multicast discovery
        if let Ok(multicast_nodes) = self.discover_multicast_nodes().await {
            discovered_nodes.extend(multicast_nodes);
        }
        
        // Broadcast discovery
        if let Ok(broadcast_nodes) = self.discover_broadcast_nodes().await {
            discovered_nodes.extend(broadcast_nodes);
        }
        
        // Port scanning discovery
        if let Ok(scanned_nodes) = self.discover_port_scan().await {
            discovered_nodes.extend(scanned_nodes);
        }
        
        // Update registry with discovered nodes
        for node in &discovered_nodes {
            if !self.registry.nodes.contains_key(&node.id) {
                self.registry.nodes.insert(node.id.clone(), node.clone());
            }
        }
        
        // Save updated registry
        self.save_registry()?;
        
        info!("Network discovery completed. Found {} nodes", discovered_nodes.len());
        Ok(discovered_nodes)
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

impl NodeManager {
    /// Discover nodes using multicast
    async fn discover_multicast_nodes(&self) -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        info!("Starting multicast discovery for UDCN nodes");
        
        let mut discovered_nodes = Vec::new();
        
        // Use IPv6 multicast for NDN discovery
        let multicast_addr = "ff02::1:2"; // NDN multicast address
        let multicast_port = 6363; // NDN default port
        
        // Create multicast socket
        let socket = match tokio::net::UdpSocket::bind("[::]:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to create multicast socket: {}", e);
                return Ok(discovered_nodes);
            }
        };
        
        // Send multicast discovery message
        let discovery_msg = b"UDCN-DISCOVERY-REQUEST";
        let multicast_target = format!("{}:{}", multicast_addr, multicast_port);
        
        match socket.send_to(discovery_msg, &multicast_target).await {
            Ok(_) => {
                info!("Sent multicast discovery message to {}", multicast_target);
                
                // Listen for responses with timeout
                let mut buffer = [0u8; 1024];
                let timeout = tokio::time::Duration::from_secs(5);
                
                let deadline = tokio::time::Instant::now() + timeout;
                
                while tokio::time::Instant::now() < deadline {
                    match tokio::time::timeout(
                        deadline - tokio::time::Instant::now(),
                        socket.recv_from(&mut buffer)
                    ).await {
                        Ok(Ok((len, src_addr))) => {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.starts_with("UDCN-DISCOVERY-RESPONSE") {
                                let node_id = format!("node-{}", src_addr);
                                let node_info = NodeInfo {
                                    id: node_id,
                                    address: src_addr,
                                    status: NodeStatus::Online,
                                    last_seen: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                                    capabilities: vec!["ndn".to_string(), "multicast".to_string()],
                                    metadata: HashMap::new(),
                                };
                                discovered_nodes.push(node_info);
                                info!("Discovered node via multicast: {}", src_addr);
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break, // Timeout
                    }
                }
            }
            Err(e) => {
                warn!("Failed to send multicast discovery message: {}", e);
            }
        }
        
        Ok(discovered_nodes)
    }
    
    /// Discover nodes using broadcast
    async fn discover_broadcast_nodes(&self) -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        info!("Starting broadcast discovery for UDCN nodes");
        
        let mut discovered_nodes = Vec::new();
        
        // Use IPv4 broadcast
        let broadcast_addr = "255.255.255.255";
        let broadcast_port = 6363;
        
        // Create broadcast socket
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to create broadcast socket: {}", e);
                return Ok(discovered_nodes);
            }
        };
        
        // Enable broadcast
        if let Err(e) = socket.set_broadcast(true) {
            warn!("Failed to enable broadcast: {}", e);
            return Ok(discovered_nodes);
        }
        
        // Send broadcast discovery message
        let discovery_msg = b"UDCN-DISCOVERY-REQUEST";
        let broadcast_target = format!("{}:{}", broadcast_addr, broadcast_port);
        
        match socket.send_to(discovery_msg, &broadcast_target).await {
            Ok(_) => {
                info!("Sent broadcast discovery message to {}", broadcast_target);
                
                // Listen for responses with timeout
                let mut buffer = [0u8; 1024];
                let timeout = tokio::time::Duration::from_secs(5);
                
                let deadline = tokio::time::Instant::now() + timeout;
                
                while tokio::time::Instant::now() < deadline {
                    match tokio::time::timeout(
                        deadline - tokio::time::Instant::now(),
                        socket.recv_from(&mut buffer)
                    ).await {
                        Ok(Ok((len, src_addr))) => {
                            let response = String::from_utf8_lossy(&buffer[..len]);
                            if response.starts_with("UDCN-DISCOVERY-RESPONSE") {
                                let node_id = format!("node-{}", src_addr);
                                let node_info = NodeInfo {
                                    id: node_id,
                                    address: src_addr,
                                    status: NodeStatus::Online,
                                    last_seen: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                                    capabilities: vec!["ndn".to_string(), "broadcast".to_string()],
                                    metadata: HashMap::new(),
                                };
                                discovered_nodes.push(node_info);
                                info!("Discovered node via broadcast: {}", src_addr);
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break, // Timeout
                    }
                }
            }
            Err(e) => {
                warn!("Failed to send broadcast discovery message: {}", e);
            }
        }
        
        Ok(discovered_nodes)
    }
    
    /// Discover nodes using port scanning
    async fn discover_port_scan(&self) -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        info!("Starting port scan discovery for UDCN nodes");
        
        let mut discovered_nodes = Vec::new();
        
        // Get local network ranges to scan
        let network_ranges = self.get_local_network_ranges().await?;
        
        for network_range in network_ranges {
            info!("Scanning network range: {}", network_range);
            
            // Scan common UDCN ports
            let ports = vec![6363, 6364, 9695]; // NDN default ports
            
            for port in ports {
                // Parse network range and scan hosts
                if let Ok(discovered_in_range) = self.scan_network_range(&network_range, port).await {
                    discovered_nodes.extend(discovered_in_range);
                }
            }
        }
        
        Ok(discovered_nodes)
    }
    
    /// Get local network ranges for scanning
    async fn get_local_network_ranges(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut ranges = Vec::new();
        
        // Common local network ranges
        ranges.push("192.168.1.0/24".to_string());
        ranges.push("192.168.0.0/24".to_string());
        ranges.push("10.0.0.0/24".to_string());
        ranges.push("172.16.0.0/24".to_string());
        
        // TODO: In a real implementation, this would:
        // 1. Get actual network interfaces
        // 2. Parse their IP addresses and subnets
        // 3. Generate appropriate scan ranges
        
        Ok(ranges)
    }
    
    /// Scan a network range for UDCN nodes
    async fn scan_network_range(&self, network_range: &str, port: u16) -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        let mut discovered_nodes = Vec::new();
        
        // Parse network range (simplified - just scan .1 to .254)
        let base_ip = network_range.split('/').next().unwrap();
        let ip_parts: Vec<&str> = base_ip.split('.').collect();
        
        if ip_parts.len() == 4 {
            let base = format!("{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2]);
            
            // Scan host range (limited to avoid flooding)
            let scan_range = std::cmp::min(50, 254); // Limit scan range
            
            for host in 1..=scan_range {
                let target_ip = format!("{}.{}", base, host);
                let target_addr = format!("{}:{}", target_ip, port);
                
                // Try to connect to check if UDCN service is running
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    tokio::net::TcpStream::connect(&target_addr)
                ).await {
                    Ok(Ok(_)) => {
                        // Connection successful, likely a UDCN node
                        let node_id = format!("node-{}", target_addr);
                        let node_info = NodeInfo {
                            id: node_id,
                            address: target_addr.parse().unwrap(),
                            status: NodeStatus::Online,
                            last_seen: Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                            capabilities: vec!["ndn".to_string(), "tcp".to_string()],
                            metadata: HashMap::new(),
                        };
                        discovered_nodes.push(node_info);
                        info!("Discovered node via port scan: {}", target_addr);
                    }
                    _ => {
                        // Connection failed or timeout, skip
                    }
                }
            }
        }
        
        Ok(discovered_nodes)
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