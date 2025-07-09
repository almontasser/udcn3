use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use async_trait::async_trait;
use udcn_core::packets::{Interest, Name};
use udcn_common::FaceInfo;

use crate::service::Service;
use crate::face_manager::FaceManager;
use crate::routing::RoutingManager;

/// Control message types for inter-component communication
#[derive(Debug, Clone)]
pub enum ControlMessage {
    /// Face status update notification
    FaceStatusUpdate {
        face_id: u32,
        status: FaceStatus,
        timestamp: SystemTime,
    },
    /// Routing table update notification
    RoutingUpdate {
        prefix: String,
        next_hop: SocketAddr,
        cost: u32,
        operation: RoutingOperation,
    },
    /// Network topology change notification
    TopologyChange {
        node_id: String,
        neighbors: Vec<NeighborInfo>,
        timestamp: SystemTime,
    },
    /// Protocol-specific control message
    ProtocolMessage {
        protocol: RoutingProtocol,
        sender: String,
        message_type: String,
        payload: Vec<u8>,
    },
}

/// Face status enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum FaceStatus {
    Up,
    Down,
    Degraded,
    Unknown,
}

/// Routing operation type
#[derive(Debug, Clone)]
pub enum RoutingOperation {
    Add,
    Remove,
    Update,
}

/// Neighbor information for topology discovery
#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub node_id: String,
    pub face_id: u32,
    pub address: SocketAddr,
    pub cost: u32,
    pub last_seen: SystemTime,
}

/// Routing protocol types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RoutingProtocol {
    /// OSPF-like protocol for NDN
    NdnOspf,
    /// BGP-like protocol for NDN
    NdnBgp,
    /// Static routing
    Static,
}

impl std::fmt::Display for RoutingProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingProtocol::NdnOspf => write!(f, "NDN-OSPF"),
            RoutingProtocol::NdnBgp => write!(f, "NDN-BGP"),
            RoutingProtocol::Static => write!(f, "Static"),
        }
    }
}

/// Routing protocol handler trait
#[async_trait]
pub trait RoutingProtocolHandler: Send + Sync {
    /// Get protocol type
    fn protocol_type(&self) -> RoutingProtocol;
    
    /// Start the protocol handler
    async fn start(&self) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Stop the protocol handler
    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Process incoming control message
    async fn process_message(&self, message: ControlMessage) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Handle neighbor discovery
    async fn handle_neighbor_discovery(&self, neighbors: Vec<NeighborInfo>) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Generate routing updates
    async fn generate_routing_updates(&self) -> Result<Vec<ControlMessage>, Box<dyn std::error::Error>>;
}

/// Network topology information
#[derive(Debug, Clone)]
pub struct NetworkTopology {
    /// Local node identifier
    pub local_node_id: String,
    /// Known neighbors
    pub neighbors: Arc<RwLock<HashMap<String, NeighborInfo>>>,
    /// Network graph (simplified)
    pub topology_graph: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Last topology update
    pub last_update: SystemTime,
}

/// Control plane manager configuration
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// Local node identifier
    pub local_node_id: String,
    /// Topology discovery interval
    pub topology_discovery_interval: Duration,
    /// Face monitoring interval
    pub face_monitoring_interval: Duration,
    /// Protocol heartbeat interval
    pub protocol_heartbeat_interval: Duration,
    /// Enabled routing protocols
    pub enabled_protocols: Vec<RoutingProtocol>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            local_node_id: "local-node".to_string(),
            topology_discovery_interval: Duration::from_secs(30),
            face_monitoring_interval: Duration::from_secs(5),
            protocol_heartbeat_interval: Duration::from_secs(10),
            enabled_protocols: vec![RoutingProtocol::NdnOspf],
        }
    }
}

/// Control plane manager - orchestrates routing protocols and network state
pub struct ControlPlaneManager {
    /// Configuration
    config: ControlPlaneConfig,
    /// Face manager reference
    face_manager: Arc<FaceManager>,
    /// Routing manager reference
    routing_manager: Arc<RoutingManager>,
    /// Protocol handlers
    protocol_handlers: HashMap<RoutingProtocol, Box<dyn RoutingProtocolHandler>>,
    /// Network topology
    topology: Arc<RwLock<NetworkTopology>>,
    /// Control message channel
    control_tx: mpsc::UnboundedSender<ControlMessage>,
    control_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<ControlMessage>>>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl ControlPlaneManager {
    /// Create new control plane manager
    pub fn new(
        config: ControlPlaneConfig,
        face_manager: Arc<FaceManager>,
        routing_manager: Arc<RoutingManager>,
    ) -> Self {
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        
        let topology = Arc::new(RwLock::new(NetworkTopology {
            local_node_id: config.local_node_id.clone(),
            neighbors: Arc::new(RwLock::new(HashMap::new())),
            topology_graph: Arc::new(RwLock::new(HashMap::new())),
            last_update: SystemTime::now(),
        }));

        Self {
            config,
            face_manager,
            routing_manager,
            protocol_handlers: HashMap::new(),
            topology,
            control_tx,
            control_rx: Arc::new(RwLock::new(Some(control_rx))),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Add a routing protocol handler
    pub fn add_protocol_handler(&mut self, handler: Box<dyn RoutingProtocolHandler>) {
        let protocol_type = handler.protocol_type();
        self.protocol_handlers.insert(protocol_type, handler);
    }

    /// Send control message
    pub async fn send_control_message(&self, message: ControlMessage) -> Result<(), Box<dyn std::error::Error>> {
        self.control_tx.send(message).map_err(|e| e.into())
    }

    /// Get network topology
    pub async fn get_topology(&self) -> NetworkTopology {
        self.topology.read().await.clone()
    }

    /// Update neighbor information
    pub async fn update_neighbor(&self, neighbor: NeighborInfo) {
        {
            let topology = self.topology.read().await;
            let mut neighbors = topology.neighbors.write().await;
            neighbors.insert(neighbor.node_id.clone(), neighbor);
        }
        let mut topology = self.topology.write().await;
        topology.last_update = SystemTime::now();
    }


    /// Static control message processing task
    async fn process_control_messages(
        mut rx: mpsc::UnboundedReceiver<ControlMessage>,
        routing_manager: Arc<RoutingManager>,
        running: Arc<RwLock<bool>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        while let Some(message) = rx.recv().await {
            if !*running.read().await {
                break;
            }

            debug!("Processing control message: {:?}", message);
            
            // Process message based on type
            match &message {
                ControlMessage::FaceStatusUpdate { face_id, status, .. } => {
                    info!("Face {} status changed to {:?}", face_id, status);
                    // Protocol handlers would be notified here in a full implementation
                }
                ControlMessage::RoutingUpdate { prefix, next_hop, cost, operation } => {
                    info!("Routing update: {:?} {} -> {} (cost: {})", operation, prefix, next_hop, cost);
                    
                    // Apply routing update
                    match operation {
                        RoutingOperation::Add => {
                            if let Err(e) = routing_manager.add_fib_entry(prefix, *next_hop, *cost).await {
                                error!("Failed to add FIB entry: {}", e);
                            }
                        }
                        RoutingOperation::Remove => {
                            if let Err(e) = routing_manager.remove_fib_entry(prefix).await {
                                error!("Failed to remove FIB entry: {}", e);
                            }
                        }
                        RoutingOperation::Update => {
                            // Remove and re-add for update
                            let _ = routing_manager.remove_fib_entry(prefix).await;
                            if let Err(e) = routing_manager.add_fib_entry(prefix, *next_hop, *cost).await {
                                error!("Failed to update FIB entry: {}", e);
                            }
                        }
                    }
                }
                ControlMessage::TopologyChange { node_id, neighbors, .. } => {
                    info!("Topology change from node {}: {} neighbors", node_id, neighbors.len());
                    // Topology updates would be handled here
                }
                ControlMessage::ProtocolMessage { protocol, sender, message_type, .. } => {
                    debug!("Protocol message from {}: {} ({})", sender, message_type, protocol);
                    // Protocol handlers would be called here
                }
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl Service for ControlPlaneManager {
    async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Control Plane Manager");
        
        *self.running.write().await = true;
        
        // Start protocol handlers
        for (protocol, handler) in &self.protocol_handlers {
            info!("Starting protocol handler: {:?}", protocol);
            if let Err(e) = handler.start().await {
                error!("Failed to start protocol handler {:?}: {}", protocol, e);
                return Err(e);
            }
        }
        
        // Start background tasks
        let running = self.running.clone();
        
        // Start control message processing
        if let Some(rx) = self.control_rx.write().await.take() {
            let routing_manager = self.routing_manager.clone();
            let protocol_handlers_len = self.protocol_handlers.len();
            let running = self.running.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::process_control_messages(rx, routing_manager, running).await {
                    error!("Control message task failed: {}", e);
                }
            });
        }
        
        // Clone self references for tasks
        let topology_manager = ControlPlaneTopologyManager {
            config: self.config.clone(),
            face_manager: self.face_manager.clone(),
            running: self.running.clone(),
        };
        
        let monitoring_manager = ControlPlaneFaceMonitor {
            config: self.config.clone(),
            face_manager: self.face_manager.clone(),
            running: self.running.clone(),
            control_tx: self.control_tx.clone(),
        };
        
        tokio::spawn(async move {
            if let Err(e) = topology_manager.run().await {
                error!("Topology discovery task failed: {}", e);
            }
        });
        
        tokio::spawn(async move {
            if let Err(e) = monitoring_manager.run().await {
                error!("Face monitoring task failed: {}", e);
            }
        });
        
        info!("Control Plane Manager started successfully");
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Stopping Control Plane Manager");
        
        *self.running.write().await = false;
        
        // Stop protocol handlers
        for (protocol, handler) in &self.protocol_handlers {
            info!("Stopping protocol handler: {:?}", protocol);
            if let Err(e) = handler.stop().await {
                error!("Failed to stop protocol handler {:?}: {}", protocol, e);
            }
        }
        
        info!("Control Plane Manager stopped");
        Ok(())
    }

    fn name(&self) -> &str {
        "ControlPlaneManager"
    }

    fn is_running(&self) -> bool {
        // We use try_read to avoid blocking in a sync function
        self.running.try_read().map(|r| *r).unwrap_or(false)
    }
}

// Helper function to create Name from string path
fn create_name_from_path(path: &str) -> Result<Name, Box<dyn std::error::Error>> {
    let mut name = Name::new();
    
    if !path.starts_with('/') {
        return Err("Name must start with '/'".into());
    }
    
    let components: Vec<&str> = path.split('/').skip(1).collect();
    for component in components {
        if !component.is_empty() {
            name.components.push(component.as_bytes().to_vec());
        }
    }
    
    Ok(name)
}

/// Helper struct for topology discovery task
struct ControlPlaneTopologyManager {
    config: ControlPlaneConfig,
    face_manager: Arc<FaceManager>,
    running: Arc<RwLock<bool>>,
}

impl ControlPlaneTopologyManager {
    async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut interval = interval(self.config.topology_discovery_interval);
        
        loop {
            interval.tick().await;
            
            if !*self.running.read().await {
                break;
            }

            // Discover neighbors through active faces
            match self.face_manager.list_faces().await {
                Ok(faces) => {
                    for face in faces {
                        if face.state == udcn_common::FACE_STATE_UP {
                            debug!("Topology discovery through face {}", face.face_id);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to list faces for topology discovery: {}", e);
                }
            }
        }
        
        Ok(())
    }
}

/// Helper struct for face monitoring task
struct ControlPlaneFaceMonitor {
    config: ControlPlaneConfig,
    face_manager: Arc<FaceManager>,
    running: Arc<RwLock<bool>>,
    control_tx: mpsc::UnboundedSender<ControlMessage>,
}

impl ControlPlaneFaceMonitor {
    async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut interval = interval(self.config.face_monitoring_interval);
        
        loop {
            interval.tick().await;
            
            if !*self.running.read().await {
                break;
            }

            // Monitor face health
            match self.face_manager.monitor_faces().await {
                Ok(_) => {
                    // Check for face status changes
                    if let Ok(faces) = self.face_manager.list_faces().await {
                        for face in faces {
                            let status = match face.state {
                                udcn_common::FACE_STATE_UP => FaceStatus::Up,
                                udcn_common::FACE_STATE_DOWN => FaceStatus::Down,
                                _ => FaceStatus::Unknown,
                            };
                            
                            // Send face status update
                            let message = ControlMessage::FaceStatusUpdate {
                                face_id: face.face_id,
                                status,
                                timestamp: SystemTime::now(),
                            };
                            
                            if let Err(e) = self.control_tx.send(message) {
                                warn!("Failed to send face status update: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Face monitoring failed: {}", e);
                }
            }
        }
        
        Ok(())
    }
}