use std::net::SocketAddr;
use std::sync::Arc;

use log::{error, info};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::ebpf::EbpfManager;
use crate::face_manager::{FaceManager, FaceConfig};
use crate::routing::{RoutingManager, RoutingConfig, RoutingStrategy};
use crate::service::Service;
use crate::control_plane::{ControlPlaneManager, ControlPlaneConfig};
use crate::protocols::NdnOspfHandler;

pub struct Daemon {
    config: Config,
    ebpf_manager: Option<EbpfManager>,
    face_manager: Option<Arc<FaceManager>>,
    routing_manager: Option<Arc<RoutingManager>>,
    control_plane_manager: Option<Arc<ControlPlaneManager>>,
    // For now, we'll manage services differently until we need them
    _services: Arc<RwLock<Vec<String>>>,
}

impl Daemon {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ebpf_manager: None,
            face_manager: None,
            routing_manager: None,
            control_plane_manager: None,
            _services: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting UDCN Daemon services");

        // Initialize core services
        udcn_core::init();
        udcn_transport::init();

        // Initialize eBPF manager
        let interface = self.config.network.interface.clone();
        let mut ebpf_manager = EbpfManager::new(interface);
        
        // Load eBPF program
        info!("Loading eBPF program for interface: {}", self.config.network.interface);
        if let Err(e) = ebpf_manager.load_program().await {
            error!("Failed to load eBPF program: {}", e);
            return Err(e);
        }

        self.ebpf_manager = Some(ebpf_manager);

        // Initialize Face Manager with eBPF integration
        let face_manager = Arc::new(FaceManager::new());
        
        // Start the face manager service
        if let Err(e) = face_manager.start().await {
            error!("Failed to start Face Manager: {}", e);
            return Err(e);
        }
        
        self.face_manager = Some(face_manager.clone());

        // Initialize Routing Manager
        let local_address = SocketAddr::from(([127, 0, 0, 1], 6363)); // Default NDN port
        let routing_manager = Arc::new(RoutingManager::new(local_address));
        
        // Start the routing manager service
        if let Err(e) = routing_manager.start().await {
            error!("Failed to start Routing Manager: {}", e);
            return Err(e);
        }
        
        self.routing_manager = Some(routing_manager.clone());

        // Initialize Control Plane Manager
        let control_plane_config = ControlPlaneConfig {
            local_node_id: format!("udcnd-{}", self.config.network.interface),
            ..Default::default()
        };
        
        let mut control_plane_manager = ControlPlaneManager::new(
            control_plane_config,
            face_manager.clone(),
            routing_manager.clone(),
        );
        
        // Add NDN OSPF protocol handler
        let ospf_config = crate::protocols::ndn_ospf::OspfConfig::default();
        let ospf_handler = NdnOspfHandler::new(
            format!("udcnd-{}", self.config.network.interface),
            ospf_config,
        );
        control_plane_manager.add_protocol_handler(Box::new(ospf_handler));
        
        let control_plane_manager = Arc::new(control_plane_manager);
        
        // Start the control plane manager service
        if let Err(e) = control_plane_manager.start().await {
            error!("Failed to start Control Plane Manager: {}", e);
            return Err(e);
        }
        
        self.control_plane_manager = Some(control_plane_manager);

        info!("All services started successfully");

        Ok(())
    }

    pub async fn stop(&mut self) {
        info!("Stopping UDCN Daemon services");

        // Stop Control Plane Manager first
        if let Some(ref control_plane_manager) = self.control_plane_manager {
            if let Err(e) = control_plane_manager.stop().await {
                error!("Failed to stop Control Plane Manager: {}", e);
            }
        }
        self.control_plane_manager = None;

        // Stop Routing Manager
        if let Some(ref routing_manager) = self.routing_manager {
            if let Err(e) = routing_manager.stop().await {
                error!("Failed to stop Routing Manager: {}", e);
            }
        }
        self.routing_manager = None;

        // Stop Face Manager
        if let Some(ref face_manager) = self.face_manager {
            if let Err(e) = face_manager.stop().await {
                error!("Failed to stop Face Manager: {}", e);
            }
        }
        self.face_manager = None;

        // Unload eBPF program
        if let Some(ref mut ebpf_manager) = self.ebpf_manager {
            if let Err(e) = ebpf_manager.unload_program().await {
                error!("Failed to unload eBPF program: {}", e);
            }
        }
        self.ebpf_manager = None;

        info!("All services stopped");
    }

    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Reloading configuration");
        // TODO: Implement configuration reload
        Ok(())
    }

    /// Get packet statistics from the eBPF program
    pub async fn get_packet_stats(&self) -> Result<udcn_common::PacketStats, Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.get_packet_stats().await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Get PIT statistics from the eBPF program
    pub async fn get_pit_stats(&self) -> Result<udcn_common::PitStats, Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.get_pit_stats().await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Get Content Store statistics from the eBPF program
    pub async fn get_cs_stats(&self) -> Result<udcn_common::ContentStoreStats, Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.get_cs_stats().await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Update eBPF configuration
    pub async fn update_ebpf_config(&self, config: &udcn_common::UdcnConfig) -> Result<(), Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.update_config(config).await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Add a face to the eBPF face table
    pub async fn add_face(&self, face_id: u32, face_info: &udcn_common::FaceInfo) -> Result<(), Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.add_face(face_id, face_info).await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Remove a face from the eBPF face table
    pub async fn remove_face(&self, face_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.remove_face(face_id).await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Get face information
    pub async fn get_face(&self, face_id: u32) -> Result<udcn_common::FaceInfo, Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.get_face(face_id).await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    /// Get health status of the daemon and eBPF components
    pub async fn get_health_status(&self) -> Result<crate::ebpf::EbpfHealthStatus, Box<dyn std::error::Error>> {
        match &self.ebpf_manager {
            Some(manager) => manager.get_health_status().await,
            None => Err("eBPF manager not initialized".into()),
        }
    }

    // === ENHANCED FACE MANAGEMENT API ===

    /// Create a new face with automatic ID generation
    pub async fn create_face(&self, config: FaceConfig) -> Result<u32, Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.create_face_auto_id(config).await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Create a face with specific ID
    pub async fn create_face_with_id(&self, config: FaceConfig) -> Result<u32, Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.create_face(config).await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Delete a face
    pub async fn delete_face(&self, face_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.delete_face(face_id).await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Get face configuration
    pub async fn get_face_config(&self, face_id: u32) -> Result<FaceConfig, Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.get_face_config(face_id).await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// List all faces
    pub async fn list_faces(&self) -> Result<Vec<udcn_common::FaceInfo>, Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.list_faces().await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Update face state
    pub async fn update_face_state(&self, face_id: u32, state: u8) -> Result<(), Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.update_face_state(face_id, state).await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Get faces by type
    pub async fn get_faces_by_type(&self, face_type: u8) -> Result<Vec<udcn_common::FaceInfo>, Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.get_faces_by_type(face_type).await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Get active faces
    pub async fn get_active_faces(&self) -> Result<Vec<udcn_common::FaceInfo>, Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.get_active_faces().await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Monitor face health
    pub async fn monitor_faces(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.face_manager {
            Some(manager) => manager.monitor_faces().await.map_err(|e| e.into()),
            None => Err("Face manager not initialized".into()),
        }
    }

    /// Create an Ethernet face
    pub async fn create_ethernet_face(&self, interface_name: String, mac_address: [u8; 6]) -> Result<u32, Box<dyn std::error::Error>> {
        let config = FaceConfig::new_ethernet(0, interface_name, mac_address);
        self.create_face(config).await
    }

    /// Create a UDP face
    pub async fn create_udp_face(&self, ip_address: std::net::IpAddr, port: u16) -> Result<u32, Box<dyn std::error::Error>> {
        let config = FaceConfig::new_udp(0, ip_address, port);
        self.create_face(config).await
    }

    /// Create a TCP face
    pub async fn create_tcp_face(&self, ip_address: std::net::IpAddr, port: u16) -> Result<u32, Box<dyn std::error::Error>> {
        let config = FaceConfig::new_tcp(0, ip_address, port);
        self.create_face(config).await
    }

    /// Create an IP face
    pub async fn create_ip_face(&self, ip_address: std::net::IpAddr) -> Result<u32, Box<dyn std::error::Error>> {
        let config = FaceConfig::new_ip(0, ip_address);
        self.create_face(config).await
    }

    /// Check if the eBPF program is loaded
    pub fn is_ebpf_loaded(&self) -> bool {
        self.ebpf_manager.as_ref().map(|m| m.is_loaded()).unwrap_or(false)
    }

    // === ROUTING OPERATIONS API ===

    /// Process incoming Interest packet
    pub async fn process_interest(&self, interest: udcn_core::packets::Interest, incoming_face: u32) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => manager.process_interest(interest, incoming_face).await,
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Process incoming Data packet
    pub async fn process_data(&self, data: udcn_core::packets::Data, incoming_face: u32) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => manager.process_data(data, incoming_face).await,
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Add a FIB entry
    pub async fn add_fib_entry(&self, prefix: &str, next_hop: std::net::SocketAddr, cost: u32) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => manager.add_fib_entry(prefix, next_hop, cost).await,
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Remove a FIB entry
    pub async fn remove_fib_entry(&self, prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => manager.remove_fib_entry(prefix).await,
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Set routing strategy for a name prefix
    pub async fn set_routing_strategy(&self, prefix: String, strategy: RoutingStrategy) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => manager.set_strategy(prefix, strategy).await,
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Get routing strategy for a name prefix
    pub async fn get_routing_strategy(&self, prefix: &str) -> Result<RoutingStrategy, Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => Ok(manager.get_strategy(prefix).await),
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Get routing statistics
    pub async fn get_routing_stats(&self) -> Result<crate::routing::RoutingStats, Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => Ok(manager.get_stats().await),
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Reset routing statistics
    pub async fn reset_routing_stats(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => { manager.reset_stats().await; Ok(()) },
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Update routing configuration
    pub async fn update_routing_config(&self, config: RoutingConfig) -> Result<(), Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => manager.update_config(config).await,
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Get current routing configuration
    pub async fn get_routing_config(&self) -> Result<RoutingConfig, Box<dyn std::error::Error>> {
        match &self.routing_manager {
            Some(manager) => Ok(manager.get_config().await),
            None => Err("Routing manager not initialized".into()),
        }
    }

    /// Check if routing manager is running
    pub async fn is_routing_active(&self) -> bool {
        match &self.routing_manager {
            Some(manager) => manager.is_running().await,
            None => false,
        }
    }

    // === CONTROL PLANE OPERATIONS API ===

    /// Get network topology information
    pub async fn get_network_topology(&self) -> Result<crate::control_plane::NetworkTopology, Box<dyn std::error::Error>> {
        match &self.control_plane_manager {
            Some(manager) => Ok(manager.get_topology().await),
            None => Err("Control plane manager not initialized".into()),
        }
    }

    /// Send control message to control plane
    pub async fn send_control_message(&self, message: crate::control_plane::ControlMessage) -> Result<(), Box<dyn std::error::Error>> {
        match &self.control_plane_manager {
            Some(manager) => manager.send_control_message(message).await,
            None => Err("Control plane manager not initialized".into()),
        }
    }

    /// Update neighbor information
    pub async fn update_neighbor(&self, neighbor: crate::control_plane::NeighborInfo) -> Result<(), Box<dyn std::error::Error>> {
        match &self.control_plane_manager {
            Some(manager) => {
                manager.update_neighbor(neighbor).await;
                Ok(())
            },
            None => Err("Control plane manager not initialized".into()),
        }
    }

    /// Check if control plane is running
    pub async fn is_control_plane_active(&self) -> bool {
        match &self.control_plane_manager {
            Some(manager) => manager.is_running(),
            None => false,
        }
    }
}
