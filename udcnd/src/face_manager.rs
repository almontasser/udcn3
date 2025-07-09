use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use async_trait::async_trait;
use udcn_common::{FaceInfo, FACE_TYPE_ETHERNET, FACE_TYPE_IP, FACE_TYPE_UDP, FACE_TYPE_TCP, FACE_STATE_UP, FACE_STATE_DOWN};

use crate::service::Service;

/// Face configuration for different face types
#[derive(Debug, Clone)]
pub struct FaceConfig {
    pub face_id: u32,
    pub face_type: u8,
    pub interface_name: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub port: Option<u16>,
    pub mac_address: Option<[u8; 6]>,
    pub mtu: Option<u32>,
    pub enable_stats: bool,
}

impl FaceConfig {
    pub fn new_ethernet(face_id: u32, interface_name: String, mac_address: [u8; 6]) -> Self {
        Self {
            face_id,
            face_type: FACE_TYPE_ETHERNET,
            interface_name: Some(interface_name),
            ip_address: None,
            port: None,
            mac_address: Some(mac_address),
            mtu: Some(1500),
            enable_stats: true,
        }
    }

    pub fn new_udp(face_id: u32, ip_address: IpAddr, port: u16) -> Self {
        Self {
            face_id,
            face_type: FACE_TYPE_UDP,
            interface_name: None,
            ip_address: Some(ip_address),
            port: Some(port),
            mac_address: None,
            mtu: Some(1500),
            enable_stats: true,
        }
    }

    pub fn new_tcp(face_id: u32, ip_address: IpAddr, port: u16) -> Self {
        Self {
            face_id,
            face_type: FACE_TYPE_TCP,
            interface_name: None,
            ip_address: Some(ip_address),
            port: Some(port),
            mac_address: None,
            mtu: Some(1500),
            enable_stats: true,
        }
    }

    pub fn new_ip(face_id: u32, ip_address: IpAddr) -> Self {
        Self {
            face_id,
            face_type: FACE_TYPE_IP,
            interface_name: None,
            ip_address: Some(ip_address),
            port: None,
            mac_address: None,
            mtu: Some(1500),
            enable_stats: true,
        }
    }

    pub fn validate(&self) -> Result<(), FaceManagerError> {
        if self.face_id == 0 {
            return Err(FaceManagerError::InvalidConfiguration("Face ID cannot be zero".to_string()));
        }

        match self.face_type {
            FACE_TYPE_ETHERNET => {
                if self.interface_name.is_none() {
                    return Err(FaceManagerError::InvalidConfiguration("Ethernet face requires interface name".to_string()));
                }
                if self.mac_address.is_none() {
                    return Err(FaceManagerError::InvalidConfiguration("Ethernet face requires MAC address".to_string()));
                }
            }
            FACE_TYPE_UDP | FACE_TYPE_TCP => {
                if self.ip_address.is_none() {
                    return Err(FaceManagerError::InvalidConfiguration("UDP/TCP face requires IP address".to_string()));
                }
                if self.port.is_none() {
                    return Err(FaceManagerError::InvalidConfiguration("UDP/TCP face requires port".to_string()));
                }
            }
            FACE_TYPE_IP => {
                if self.ip_address.is_none() {
                    return Err(FaceManagerError::InvalidConfiguration("IP face requires IP address".to_string()));
                }
            }
            _ => {
                return Err(FaceManagerError::InvalidConfiguration(format!("Unsupported face type: {}", self.face_type)));
            }
        }

        Ok(())
    }
}

/// Error types for face management operations
#[derive(Debug, thiserror::Error)]
pub enum FaceManagerError {
    #[error("Face not found: {0}")]
    FaceNotFound(u32),
    #[error("Face already exists: {0}")]
    FaceAlreadyExists(u32),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("eBPF error: {0}")]
    EbpfError(String),
    #[error("Service not running")]
    ServiceNotRunning,
}

/// Face management service
pub struct FaceManager {
    faces: Arc<RwLock<HashMap<u32, FaceInfo>>>,
    configs: Arc<RwLock<HashMap<u32, FaceConfig>>>,
    running: Arc<RwLock<bool>>,
    next_face_id: Arc<RwLock<u32>>,
    // TODO: Add eBPF manager integration when ready
    // ebpf_manager: Option<Arc<crate::ebpf::EbpfManager>>,
}

impl FaceManager {
    pub fn new() -> Self {
        Self {
            faces: Arc::new(RwLock::new(HashMap::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
            next_face_id: Arc::new(RwLock::new(1)),
            // ebpf_manager: None,
        }
    }

    // TODO: Uncomment when eBPF integration is ready
    // pub fn with_ebpf_manager(mut self, ebpf_manager: Arc<crate::ebpf::EbpfManager>) -> Self {
    //     self.ebpf_manager = Some(ebpf_manager);
    //     self
    // }

    /// Create a new face with the given configuration
    pub async fn create_face(&self, config: FaceConfig) -> Result<u32, FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        config.validate()?;

        let mut faces = self.faces.write().await;
        if faces.contains_key(&config.face_id) {
            return Err(FaceManagerError::FaceAlreadyExists(config.face_id));
        }

        let face_info = self.config_to_face_info(&config)?;
        
        // TODO: Add to eBPF if available
        // if let Some(ref ebpf_manager) = self.ebpf_manager {
        //     if let Err(e) = ebpf_manager.add_face(config.face_id, &face_info).await {
        //         return Err(FaceManagerError::EbpfError(e.to_string()));
        //     }
        // }

        faces.insert(config.face_id, face_info);
        self.configs.write().await.insert(config.face_id, config.clone());

        info!("Created face {} (type: {})", config.face_id, config.face_type);
        Ok(config.face_id)
    }

    /// Create a face with auto-generated ID
    pub async fn create_face_auto_id(&self, mut config: FaceConfig) -> Result<u32, FaceManagerError> {
        let face_id = self.allocate_face_id().await;
        config.face_id = face_id;
        self.create_face(config).await
    }

    /// Delete a face
    pub async fn delete_face(&self, face_id: u32) -> Result<(), FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let mut faces = self.faces.write().await;
        if !faces.contains_key(&face_id) {
            return Err(FaceManagerError::FaceNotFound(face_id));
        }

        // TODO: Remove from eBPF if available
        // if let Some(ref ebpf_manager) = self.ebpf_manager {
        //     if let Err(e) = ebpf_manager.remove_face(face_id).await {
        //         warn!("Failed to remove face {} from eBPF: {}", face_id, e);
        //     }
        // }

        faces.remove(&face_id);
        self.configs.write().await.remove(&face_id);

        info!("Deleted face {}", face_id);
        Ok(())
    }

    /// Get face information
    pub async fn get_face(&self, face_id: u32) -> Result<FaceInfo, FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let faces = self.faces.read().await;
        faces.get(&face_id)
            .copied()
            .ok_or(FaceManagerError::FaceNotFound(face_id))
    }

    /// Get face configuration
    pub async fn get_face_config(&self, face_id: u32) -> Result<FaceConfig, FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let configs = self.configs.read().await;
        configs.get(&face_id)
            .cloned()
            .ok_or(FaceManagerError::FaceNotFound(face_id))
    }

    /// List all faces
    pub async fn list_faces(&self) -> Result<Vec<FaceInfo>, FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let faces = self.faces.read().await;
        Ok(faces.values().copied().collect())
    }

    /// Update face state
    pub async fn update_face_state(&self, face_id: u32, state: u8) -> Result<(), FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let mut faces = self.faces.write().await;
        if let Some(face_info) = faces.get_mut(&face_id) {
            face_info.state = state;
            face_info.last_activity = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;

            // TODO: Update eBPF if available
            // if let Some(ref ebpf_manager) = self.ebpf_manager {
            //     if let Err(e) = ebpf_manager.add_face(face_id, face_info).await {
            //         warn!("Failed to update face {} in eBPF: {}", face_id, e);
            //     }
            // }

            debug!("Updated face {} state to {}", face_id, state);
            Ok(())
        } else {
            Err(FaceManagerError::FaceNotFound(face_id))
        }
    }

    /// Get faces by type
    pub async fn get_faces_by_type(&self, face_type: u8) -> Result<Vec<FaceInfo>, FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let faces = self.faces.read().await;
        Ok(faces.values()
            .filter(|face| face.face_type == face_type)
            .copied()
            .collect())
    }

    /// Get active faces (state = UP)
    pub async fn get_active_faces(&self) -> Result<Vec<FaceInfo>, FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let faces = self.faces.read().await;
        Ok(faces.values()
            .filter(|face| face.state & FACE_STATE_UP != 0)
            .copied()
            .collect())
    }

    /// Monitor face health and update states
    pub async fn monitor_faces(&self) -> Result<(), FaceManagerError> {
        if !*self.running.read().await {
            return Err(FaceManagerError::ServiceNotRunning);
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut faces = self.faces.write().await;
        let mut updated_faces = Vec::new();

        for (face_id, face_info) in faces.iter_mut() {
            let age = current_time.saturating_sub(face_info.last_activity);
            
            // Consider face down if no activity for 30 seconds
            if age > 30_000_000_000 && face_info.state & FACE_STATE_UP != 0 {
                face_info.state = FACE_STATE_DOWN;
                updated_faces.push(*face_id);
            }
        }

        drop(faces);

        // TODO: Update eBPF for changed faces
        // if let Some(ref ebpf_manager) = self.ebpf_manager {
        //     for face_id in updated_faces {
        //         if let Ok(face_info) = self.get_face(face_id).await {
        //             if let Err(e) = ebpf_manager.add_face(face_id, &face_info).await {
        //                 warn!("Failed to update face {} in eBPF during monitoring: {}", face_id, e);
        //             }
        //         }
        //     }
        // }

        Ok(())
    }

    /// Allocate a new face ID
    async fn allocate_face_id(&self) -> u32 {
        let mut next_id = self.next_face_id.write().await;
        let id = *next_id;
        *next_id += 1;
        id
    }

    /// Convert FaceConfig to FaceInfo
    fn config_to_face_info(&self, config: &FaceConfig) -> Result<FaceInfo, FaceManagerError> {
        let mut face_info = FaceInfo {
            face_id: config.face_id,
            face_type: config.face_type,
            state: FACE_STATE_UP,
            ifindex: 0,
            mac_addr: [0; 6],
            ip_addr: [0; 16],
            port: 0,
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            _padding: [0; 6],
        };

        if let Some(mac_addr) = config.mac_address {
            face_info.mac_addr = mac_addr;
        }

        if let Some(ip_addr) = config.ip_address {
            match ip_addr {
                IpAddr::V4(addr) => {
                    let octets = addr.octets();
                    face_info.ip_addr[0..4].copy_from_slice(&octets);
                }
                IpAddr::V6(addr) => {
                    face_info.ip_addr.copy_from_slice(&addr.octets());
                }
            }
        }

        if let Some(port) = config.port {
            face_info.port = port;
        }

        Ok(face_info)
    }
}

#[async_trait]
impl Service for FaceManager {
    async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Face Manager service");
        *self.running.write().await = true;
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Stopping Face Manager service");
        *self.running.write().await = false;
        
        // Clean up all faces
        let face_ids: Vec<u32> = self.faces.read().await.keys().copied().collect();
        for face_id in face_ids {
            if let Err(e) = self.delete_face(face_id).await {
                warn!("Failed to delete face {} during shutdown: {}", face_id, e);
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "face-manager"
    }

    fn is_running(&self) -> bool {
        // We need to handle the async nature differently
        false // This is a limitation of the trait, we'll need to use a different approach
    }
}

impl Default for FaceManager {
    fn default() -> Self {
        Self::new()
    }
}