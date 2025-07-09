use std::sync::Arc;

use log::{error, info, warn};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::ebpf::EbpfManager;

pub struct Daemon {
    config: Config,
    ebpf_manager: Option<EbpfManager>,
    // For now, we'll manage services differently until we need them
    _services: Arc<RwLock<Vec<String>>>,
}

impl Daemon {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ebpf_manager: None,
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

        info!("All services started successfully");

        Ok(())
    }

    pub async fn stop(&mut self) {
        info!("Stopping UDCN Daemon services");

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

    /// Check if the eBPF program is loaded
    pub fn is_ebpf_loaded(&self) -> bool {
        self.ebpf_manager.as_ref().map(|m| m.is_loaded()).unwrap_or(false)
    }
}
