use std::sync::Arc;

use log::{error, info};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::ebpf::EbpfManager;
use crate::face_manager::{FaceManager, FaceConfig};
use crate::service::Service;

pub struct Daemon {
    config: Config,
    ebpf_manager: Option<EbpfManager>,
    face_manager: Option<FaceManager>,
    // For now, we'll manage services differently until we need them
    _services: Arc<RwLock<Vec<String>>>,
}

impl Daemon {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ebpf_manager: None,
            face_manager: None,
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
        let face_manager = FaceManager::new();
        
        // Start the face manager service
        if let Err(e) = face_manager.start().await {
            error!("Failed to start Face Manager: {}", e);
            return Err(e);
        }
        
        self.face_manager = Some(face_manager);

        info!("All services started successfully");

        Ok(())
    }

    pub async fn stop(&mut self) {
        info!("Stopping UDCN Daemon services");

        // Stop Face Manager first
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
}
