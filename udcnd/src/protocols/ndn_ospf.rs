use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use async_trait::async_trait;

use crate::control_plane::{
    ControlMessage, FaceStatus, NeighborInfo,
    RoutingProtocol, RoutingProtocolHandler, RoutingOperation
};

/// NDN OSPF protocol handler - implements OSPF-like routing for NDN networks
pub struct NdnOspfHandler {
    /// Local node identifier
    local_node_id: String,
    /// OSPF configuration
    config: OspfConfig,
    /// Link state database
    lsdb: Arc<RwLock<HashMap<String, LinkStateAdvertisement>>>,
    /// Neighbor table
    neighbors: Arc<RwLock<HashMap<String, OspfNeighbor>>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

/// OSPF configuration parameters
#[derive(Debug, Clone)]
pub struct OspfConfig {
    /// Hello interval in seconds
    pub hello_interval: Duration,
    /// Dead interval in seconds
    pub dead_interval: Duration,
    /// LSA refresh interval in seconds
    pub lsa_refresh_interval: Duration,
    /// Router priority
    pub router_priority: u8,
    /// Area ID
    pub area_id: u32,
}

impl Default for OspfConfig {
    fn default() -> Self {
        Self {
            hello_interval: Duration::from_secs(10),
            dead_interval: Duration::from_secs(40),
            lsa_refresh_interval: Duration::from_secs(1800), // 30 minutes
            router_priority: 1,
            area_id: 0,
        }
    }
}

/// OSPF neighbor state
#[derive(Debug, Clone, PartialEq)]
pub enum OspfNeighborState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

/// OSPF neighbor information
#[derive(Debug, Clone)]
pub struct OspfNeighbor {
    /// Neighbor router ID
    pub router_id: String,
    /// Neighbor address
    pub address: SocketAddr,
    /// Face ID for communication
    pub face_id: u32,
    /// Neighbor state
    pub state: OspfNeighborState,
    /// Last hello time
    pub last_hello: SystemTime,
    /// Router priority
    pub priority: u8,
    /// Link cost
    pub cost: u32,
}

/// Link State Advertisement types
#[derive(Debug, Clone, PartialEq)]
pub enum LsaType {
    Router,
    Network,
    Summary,
    External,
}

/// Link State Advertisement
#[derive(Debug, Clone)]
pub struct LinkStateAdvertisement {
    /// LSA type
    pub lsa_type: LsaType,
    /// Advertising router
    pub advertising_router: String,
    /// Sequence number
    pub sequence_number: u32,
    /// Age in seconds
    pub age: u32,
    /// Checksum
    pub checksum: u16,
    /// LSA data
    pub data: Vec<u8>,
    /// Creation timestamp
    pub timestamp: SystemTime,
}

/// OSPF Hello packet
#[derive(Debug, Clone)]
pub struct OspfHelloPacket {
    /// Router ID
    pub router_id: String,
    /// Area ID
    pub area_id: u32,
    /// Hello interval
    pub hello_interval: u32,
    /// Dead interval
    pub dead_interval: u32,
    /// Router priority
    pub priority: u8,
    /// Designated router
    pub designated_router: String,
    /// Backup designated router
    pub backup_designated_router: String,
    /// Neighbor list
    pub neighbors: Vec<String>,
}

impl NdnOspfHandler {
    /// Create new NDN OSPF handler
    pub fn new(local_node_id: String, config: OspfConfig) -> Self {
        Self {
            local_node_id,
            config,
            lsdb: Arc::new(RwLock::new(HashMap::new())),
            neighbors: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }



    /// Process incoming hello packet
    async fn process_hello_packet(&self, hello: OspfHelloPacket, face_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Processing hello packet from {}", hello.router_id);
        
        // Basic validation
        if hello.area_id != self.config.area_id {
            warn!("Hello packet from {} has mismatched area ID", hello.router_id);
            return Ok(());
        }
        
        let mut neighbors = self.neighbors.write().await;
        let now = SystemTime::now();
        
        // Update or create neighbor entry
        let neighbor = neighbors.entry(hello.router_id.clone()).or_insert_with(|| {
            OspfNeighbor {
                router_id: hello.router_id.clone(),
                address: SocketAddr::from(([127, 0, 0, 1], 0)), // Placeholder
                face_id,
                state: OspfNeighborState::Init,
                last_hello: now,
                priority: hello.priority,
                cost: 1, // Default cost
            }
        });
        
        neighbor.last_hello = now;
        neighbor.priority = hello.priority;
        
        // State machine transition
        match neighbor.state {
            OspfNeighborState::Down => {
                neighbor.state = OspfNeighborState::Init;
                info!("Neighbor {} transitioned to Init state", hello.router_id);
            }
            OspfNeighborState::Init => {
                // Check if we're in the neighbor's hello packet
                if hello.neighbors.contains(&self.local_node_id) {
                    neighbor.state = OspfNeighborState::TwoWay;
                    info!("Neighbor {} transitioned to TwoWay state", hello.router_id);
                }
            }
            OspfNeighborState::TwoWay => {
                // In a full implementation, we'd proceed to database exchange
                neighbor.state = OspfNeighborState::Full;
                info!("Neighbor {} transitioned to Full state", hello.router_id);
            }
            _ => {
                // Update last hello time for active neighbors
                debug!("Updated hello time for neighbor {}", hello.router_id);
            }
        }
        
        Ok(())
    }

    /// Generate Router LSA
    async fn generate_router_lsa(&self) -> Result<LinkStateAdvertisement, Box<dyn std::error::Error>> {
        let neighbors = self.neighbors.read().await;
        let mut lsa_data = Vec::new();
        
        // LSA header
        lsa_data.extend_from_slice(&(neighbors.len() as u16).to_be_bytes());
        
        // Add neighbor information
        for neighbor in neighbors.values() {
            if neighbor.state == OspfNeighborState::Full {
                lsa_data.extend_from_slice(neighbor.router_id.as_bytes());
                lsa_data.extend_from_slice(&neighbor.cost.to_be_bytes());
            }
        }
        
        let lsa = LinkStateAdvertisement {
            lsa_type: LsaType::Router,
            advertising_router: self.local_node_id.clone(),
            sequence_number: 1, // Simplified
            age: 0,
            checksum: 0, // Simplified
            data: lsa_data,
            timestamp: SystemTime::now(),
        };
        
        Ok(lsa)
    }

    /// Install LSA in database
    async fn install_lsa(&self, lsa: LinkStateAdvertisement) -> Result<(), Box<dyn std::error::Error>> {
        let mut lsdb = self.lsdb.write().await;
        let key = format!("{}:{:?}", lsa.advertising_router, lsa.lsa_type);
        
        debug!("Installing LSA: {}", key);
        lsdb.insert(key, lsa);
        
        Ok(())
    }

    /// Calculate shortest path tree using Dijkstra's algorithm
    async fn calculate_spt(&self) -> Result<HashMap<String, (u32, String)>, Box<dyn std::error::Error>> {
        let lsdb = self.lsdb.read().await;
        let mut distances: HashMap<String, u32> = HashMap::new();
        let mut previous: HashMap<String, String> = HashMap::new();
        let mut unvisited: Vec<String> = Vec::new();
        
        // Initialize distances
        distances.insert(self.local_node_id.clone(), 0);
        unvisited.push(self.local_node_id.clone());
        
        // Extract network topology from LSAs
        for lsa in lsdb.values() {
            if lsa.lsa_type == LsaType::Router {
                unvisited.push(lsa.advertising_router.clone());
                distances.entry(lsa.advertising_router.clone()).or_insert(u32::MAX);
            }
        }
        
        // Dijkstra's algorithm
        while !unvisited.is_empty() {
            // Find node with minimum distance
            let current = unvisited.iter()
                .min_by_key(|node| distances.get(*node).unwrap_or(&u32::MAX))
                .cloned()
                .unwrap();
            
            unvisited.retain(|node| node != &current);
            
            let current_distance = *distances.get(&current).unwrap_or(&u32::MAX);
            if current_distance == u32::MAX {
                break;
            }
            
            // Process neighbors from LSA
            if let Some(lsa) = lsdb.get(&format!("{}:{:?}", current, LsaType::Router)) {
                // Parse LSA data to get neighbors and costs
                // Simplified parsing
                let mut offset = 2; // Skip neighbor count
                while offset < lsa.data.len() {
                    if offset + 8 > lsa.data.len() {
                        break;
                    }
                    
                    let neighbor_id = String::from_utf8_lossy(&lsa.data[offset..offset+4]).to_string();
                    let cost = u32::from_be_bytes([
                        lsa.data[offset+4], lsa.data[offset+5], 
                        lsa.data[offset+6], lsa.data[offset+7]
                    ]);
                    
                    let alt_distance = current_distance.saturating_add(cost);
                    let neighbor_distance = distances.get(&neighbor_id).unwrap_or(&u32::MAX);
                    
                    if alt_distance < *neighbor_distance {
                        distances.insert(neighbor_id.clone(), alt_distance);
                        previous.insert(neighbor_id.clone(), current.clone());
                    }
                    
                    offset += 8;
                }
            }
        }
        
        // Build routing table
        let mut routing_table = HashMap::new();
        for (dest, cost) in distances {
            if dest != self.local_node_id {
                if let Some(next_hop) = previous.get(&dest) {
                    routing_table.insert(dest, (cost, next_hop.clone()));
                }
            }
        }
        
        Ok(routing_table)
    }

}

#[async_trait]
impl RoutingProtocolHandler for NdnOspfHandler {
    fn protocol_type(&self) -> RoutingProtocol {
        RoutingProtocol::NdnOspf
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting NDN OSPF protocol handler");
        
        *self.running.write().await = true;
        
        // Start hello protocol
        let hello_handler = NdnOspfHelloHandler {
            local_node_id: self.local_node_id.clone(),
            config: self.config.clone(),
            neighbors: self.neighbors.clone(),
            running: self.running.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = hello_handler.run().await {
                error!("OSPF hello task failed: {}", e);
            }
        });
        
        // Generate and install initial Router LSA
        let router_lsa = self.generate_router_lsa().await?;
        self.install_lsa(router_lsa).await?;
        
        info!("NDN OSPF protocol handler started");
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Stopping NDN OSPF protocol handler");
        
        *self.running.write().await = false;
        
        // Clear neighbor table
        self.neighbors.write().await.clear();
        
        info!("NDN OSPF protocol handler stopped");
        Ok(())
    }

    async fn process_message(&self, message: ControlMessage) -> Result<(), Box<dyn std::error::Error>> {
        match message {
            ControlMessage::FaceStatusUpdate { face_id, status, .. } => {
                // Update neighbor states based on face status
                let mut neighbors = self.neighbors.write().await;
                for neighbor in neighbors.values_mut() {
                    if neighbor.face_id == face_id {
                        match status {
                            FaceStatus::Up => {
                                if neighbor.state == OspfNeighborState::Down {
                                    neighbor.state = OspfNeighborState::Init;
                                }
                            }
                            FaceStatus::Down => {
                                neighbor.state = OspfNeighborState::Down;
                            }
                            _ => {}
                        }
                    }
                }
            }
            ControlMessage::ProtocolMessage { protocol, .. } => {
                if protocol == RoutingProtocol::NdnOspf {
                    // Process OSPF-specific messages
                    debug!("Processing OSPF protocol message");
                    // Deserialize and process hello packets, LSAs, etc.
                }
            }
            _ => {
                // Handle other message types as needed
                debug!("Received control message: {:?}", message);
            }
        }
        
        Ok(())
    }

    async fn handle_neighbor_discovery(&self, neighbors: Vec<NeighborInfo>) -> Result<(), Box<dyn std::error::Error>> {
        let mut ospf_neighbors = self.neighbors.write().await;
        let now = SystemTime::now();
        
        for neighbor in neighbors {
            ospf_neighbors.entry(neighbor.node_id.clone()).or_insert_with(|| {
                OspfNeighbor {
                    router_id: neighbor.node_id.clone(),
                    address: neighbor.address,
                    face_id: neighbor.face_id,
                    state: OspfNeighborState::Init,
                    last_hello: now,
                    priority: 1,
                    cost: neighbor.cost,
                }
            });
        }
        
        Ok(())
    }

    async fn generate_routing_updates(&self) -> Result<Vec<ControlMessage>, Box<dyn std::error::Error>> {
        let mut updates = Vec::new();
        
        // Calculate shortest path tree
        let routing_table = self.calculate_spt().await?;
        
        // Generate routing updates
        for (dest, (cost, next_hop)) in routing_table {
            // Find next hop address
            let neighbors = self.neighbors.read().await;
            if let Some(neighbor) = neighbors.get(&next_hop) {
                updates.push(ControlMessage::RoutingUpdate {
                    prefix: format!("/{}", dest),
                    next_hop: neighbor.address,
                    cost,
                    operation: RoutingOperation::Add,
                });
            }
        }
        
        Ok(updates)
    }
}

/// Helper struct for OSPF hello protocol task
struct NdnOspfHelloHandler {
    local_node_id: String,
    config: OspfConfig,
    neighbors: Arc<RwLock<HashMap<String, OspfNeighbor>>>,
    running: Arc<RwLock<bool>>,
}

impl NdnOspfHelloHandler {
    async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut interval = interval(self.config.hello_interval);
        
        loop {
            interval.tick().await;
            
            if !*self.running.read().await {
                break;
            }

            // Send hello packets to all neighbors
            if let Err(e) = self.send_hello_packets().await {
                error!("Failed to send hello packets: {}", e);
            }
            
            // Check for dead neighbors
            if let Err(e) = self.check_dead_neighbors().await {
                error!("Failed to check dead neighbors: {}", e);
            }
        }
        
        Ok(())
    }

    async fn send_hello_packets(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let neighbors = self.neighbors.read().await;
        let neighbor_ids: Vec<String> = neighbors.keys().cloned().collect();
        
        let hello_packet = OspfHelloPacket {
            router_id: self.local_node_id.clone(),
            area_id: self.config.area_id,
            hello_interval: self.config.hello_interval.as_secs() as u32,
            dead_interval: self.config.dead_interval.as_secs() as u32,
            priority: self.config.router_priority,
            designated_router: "0.0.0.0".to_string(), // Simplified
            backup_designated_router: "0.0.0.0".to_string(), // Simplified
            neighbors: neighbor_ids,
        };
        
        // Serialize and send hello packet
        let _hello_data = self.serialize_hello_packet(&hello_packet)?;
        
        for neighbor in neighbors.values() {
            if neighbor.state != OspfNeighborState::Down {
                debug!("Sending hello to neighbor {} on face {}", neighbor.router_id, neighbor.face_id);
                // In a real implementation, this would send through the face manager
            }
        }
        
        Ok(())
    }

    async fn check_dead_neighbors(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut neighbors = self.neighbors.write().await;
        let now = SystemTime::now();
        let mut dead_neighbors = Vec::new();
        
        for (router_id, neighbor) in neighbors.iter() {
            if let Ok(duration) = now.duration_since(neighbor.last_hello) {
                if duration > self.config.dead_interval {
                    dead_neighbors.push(router_id.clone());
                }
            }
        }
        
        for router_id in dead_neighbors {
            warn!("Neighbor {} is dead, removing from neighbor table", router_id);
            neighbors.remove(&router_id);
            
            // Update routing table
            // This would trigger LSA generation and flooding
        }
        
        Ok(())
    }

    fn serialize_hello_packet(&self, hello: &OspfHelloPacket) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut data = Vec::new();
        
        // Simplified serialization
        data.extend_from_slice(hello.router_id.as_bytes());
        data.extend_from_slice(&hello.area_id.to_be_bytes());
        data.extend_from_slice(&hello.hello_interval.to_be_bytes());
        data.extend_from_slice(&hello.dead_interval.to_be_bytes());
        data.push(hello.priority);
        
        // Add neighbor count and IDs
        data.extend_from_slice(&(hello.neighbors.len() as u16).to_be_bytes());
        for neighbor in &hello.neighbors {
            data.extend_from_slice(neighbor.as_bytes());
        }
        
        Ok(data)
    }
}