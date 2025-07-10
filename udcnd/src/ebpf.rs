use std::sync::Arc;

use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use aya_log;
use libc;
use log::{debug, info, warn};
use tokio::sync::RwLock;

use udcn_common::*;

/// eBPF program loader and manager
pub struct EbpfManager {
    bpf: Option<Arc<RwLock<Ebpf>>>,
    program_loaded: bool,
    interface_name: String,
}

impl EbpfManager {
    /// Create a new eBPF manager
    pub fn new(interface_name: String) -> Self {
        Self {
            bpf: None,
            program_loaded: false,
            interface_name,
        }
    }

    /// Load the eBPF program from embedded bytecode
    pub async fn load_program(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Loading eBPF program for interface: {}", self.interface_name);

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        // Load the eBPF program from embedded bytecode
        let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/udcn"
        )))?;
        
        // Initialize eBPF logger
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }

        // Get and load the XDP program
        let program: &mut aya::programs::Xdp = bpf.program_mut("udcn").unwrap().try_into()?;
        program.load()?;
        
        // Attach the program to the interface
        program.attach(&self.interface_name, aya::programs::XdpFlags::default())
            .map_err(|e| format!("failed to attach the XDP program to {}: {} - try changing XdpFlags::default() to XdpFlags::SKB_MODE", 
                                self.interface_name, e))?;

        // Store the loaded eBPF program
        self.bpf = Some(Arc::new(RwLock::new(bpf)));
        self.program_loaded = true;

        info!("eBPF program loaded and attached to interface: {}", self.interface_name);
        Ok(())
    }

    /// Unload the eBPF program
    pub async fn unload_program(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.program_loaded {
            warn!("No eBPF program loaded to unload");
            return Ok(());
        }

        info!("Unloading eBPF program from interface: {}", self.interface_name);

        // Detach the program from the interface
        if let Some(bpf_arc) = &self.bpf {
            let bpf = bpf_arc.read().await;
            if let Some(program) = bpf.program("udcn") {
                if let Ok(program) = program.try_into() as Result<&Xdp, _> {
                    // XDP programs detach automatically when dropped, but we can be explicit
                    // program.detach(&self.interface_name)?;
                    debug!("XDP program will be detached when dropped");
                }
            }
        }

        self.bpf = None;
        self.program_loaded = false;

        info!("eBPF program unloaded from interface: {}", self.interface_name);
        Ok(())
    }

    /// Check if the eBPF program is loaded
    pub fn is_loaded(&self) -> bool {
        self.program_loaded
    }

    // TODO: These methods need to be restructured to avoid lifetime issues
    // /// Get access to a specific eBPF map with default key type
    // pub async fn get_map<T>(&self, name: &str) -> Result<HashMap<&mut aya::maps::MapData, u32, T>, Box<dyn std::error::Error>>
    // where
    //     T: 'static + Send + Sync + Clone + aya::Pod,
    // {
    //     debug!("Getting eBPF map: {}", name);
    //     if let Some(bpf_arc) = &self.bpf {
    //         let mut bpf = bpf_arc.write().await;
    //         let map = bpf.map_mut(name)
    //             .ok_or_else(|| format!("Map '{}' not found", name))?;
    //         let hash_map: HashMap<&mut aya::maps::MapData, u32, T> = HashMap::try_from(map)
    //             .map_err(|e| format!("Failed to convert map '{}' to HashMap: {}", name, e))?;
    //         Ok(hash_map)
    //     } else {
    //         Err("eBPF program not loaded".into())
    //     }
    // }

    // /// Get access to a specific eBPF map with custom key type
    // pub async fn get_map_with_key<K, T>(&self, name: &str) -> Result<HashMap<&mut aya::maps::MapData, K, T>, Box<dyn std::error::Error>>
    // where
    //     K: 'static + Send + Sync + Clone + aya::Pod,
    //     T: 'static + Send + Sync + Clone + aya::Pod,
    // {
    //     debug!("Getting eBPF map with custom key: {}", name);
    //     if let Some(bpf_arc) = &self.bpf {
    //         let mut bpf = bpf_arc.write().await;
    //         let map = bpf.map_mut(name)
    //             .ok_or_else(|| format!("Map '{}' not found", name))?;
    //         let hash_map: HashMap<&mut aya::maps::MapData, K, T> = HashMap::try_from(map)
    //             .map_err(|e| format!("Failed to convert map '{}' to HashMap: {}", name, e))?;
    //         Ok(hash_map)
    //     } else {
    //         Err("eBPF program not loaded".into())
    //     }
    // }

    /// Get packet statistics from the eBPF program
    pub async fn get_packet_stats(&self) -> Result<PacketStats, Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("PACKET_STATS")
                .ok_or("PACKET_STATS map not found")?;
            let stats_map: HashMap<&mut aya::maps::MapData, u32, PacketStats> = HashMap::try_from(map)?;
            
            // Get statistics from the map (key 0 is typically used for global stats)
            match stats_map.get(&0, 0) {
                Ok(stats) => Ok(stats),
                Err(e) => {
                    warn!("Failed to get packet statistics from eBPF map: {}", e);
                    // Return default stats if map read fails
                    Ok(PacketStats {
                        packets_processed: 0,
                        packets_dropped: 0,
                        packets_passed: 0,
                        packets_redirected: 0,
                        bytes_processed: 0,
                        processing_time_ns: 0,
                        interest_packets: 0,
                        data_packets: 0,
                        nack_packets: 0,
                        control_packets: 0,
                        parse_errors: 0,
                        memory_errors: 0,
                    })
                }
            }
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Get PIT statistics from the eBPF program
    pub async fn get_pit_stats(&self) -> Result<PitStats, Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("PIT_STATS")
                .ok_or("PIT_STATS map not found")?;
            let pit_stats_map: HashMap<&mut aya::maps::MapData, u32, PitStats> = HashMap::try_from(map)?;
            
            // Get PIT statistics from the map (key 0 is typically used for global stats)
            match pit_stats_map.get(&0, 0) {
                Ok(stats) => {
                    debug!("Retrieved PIT statistics from eBPF: {:?}", stats);
                    Ok(stats)
                }
                Err(e) => {
                    warn!("Failed to get PIT statistics from eBPF map: {}", e);
                    // Return default stats if map read fails
                    Ok(PitStats {
                        entries_created: 0,
                        entries_satisfied: 0,
                        entries_expired: 0,
                        interests_aggregated: 0,
                        active_entries: 0,
                        max_entries_reached: 0,
                        lookups: 0,
                        insertions: 0,
                        deletions: 0,
                        cleanups: 0,
                    })
                }
            }
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Get Content Store statistics from the eBPF program
    pub async fn get_cs_stats(&self) -> Result<ContentStoreStats, Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("CS_STATS")
                .ok_or("CS_STATS map not found")?;
            let cs_stats_map: HashMap<&mut aya::maps::MapData, u32, ContentStoreStats> = HashMap::try_from(map)?;
            
            // Get CS statistics from the map (key 0 is typically used for global stats)
            match cs_stats_map.get(&0, 0) {
                Ok(stats) => Ok(stats),
                Err(e) => {
                    warn!("Failed to get Content Store statistics from eBPF map: {}", e);
                    // Return default stats if map read fails
                    Ok(ContentStoreStats {
                        lookups: 0,
                        hits: 0,
                        misses: 0,
                        insertions: 0,
                        evictions: 0,
                        expirations: 0,
                        current_entries: 0,
                        bytes_stored: 0,
                        max_entries_reached: 0,
                        cleanups: 0,
                    })
                }
            }
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Update configuration in the eBPF program
    pub async fn update_config(&self, config: &UdcnConfig) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("CONFIG_MAP")
                .ok_or("CONFIG_MAP map not found")?;
            let mut config_map: HashMap<&mut aya::maps::MapData, u32, UdcnConfig> = HashMap::try_from(map)?;
            
            // Update the configuration in the eBPF map (key 0 is typically used for global config)
            config_map.insert(0, config.clone(), 0)?;
            
            info!("Updated eBPF configuration: {:?}", config);
            Ok(())
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Add a face to the face table
    pub async fn add_face(&self, face_id: u32, face_info: &FaceInfo) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("FACE_TABLE")
                .ok_or("FACE_TABLE map not found")?;
            let mut face_table: HashMap<&mut aya::maps::MapData, u32, FaceInfo> = HashMap::try_from(map)?;
            
            // Insert the face into the eBPF face table
            face_table.insert(face_id, face_info.clone(), 0)?;
            
            info!("Added face {} to eBPF face table: {:?}", face_id, face_info);
            Ok(())
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Remove a face from the face table
    pub async fn remove_face(&self, face_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("FACE_TABLE")
                .ok_or("FACE_TABLE map not found")?;
            let mut face_table: HashMap<&mut aya::maps::MapData, u32, FaceInfo> = HashMap::try_from(map)?;
            
            // Remove the face from the eBPF face table
            face_table.remove(&face_id)?;
            
            info!("Removed face {} from eBPF face table", face_id);
            Ok(())
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Get face information
    pub async fn get_face(&self, face_id: u32) -> Result<FaceInfo, Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("FACE_TABLE")
                .ok_or("FACE_TABLE map not found")?;
            let face_table: HashMap<&mut aya::maps::MapData, u32, FaceInfo> = HashMap::try_from(map)?;
            
            // Get the face from the eBPF face table
            match face_table.get(&face_id, 0) {
                Ok(face_info) => {
                    debug!("Retrieved face {} from eBPF face table: {:?}", face_id, face_info);
                    Ok(face_info)
                }
                Err(e) => {
                    warn!("Face {} not found in eBPF face table: {}", face_id, e);
                    Err(format!("Face {} not found", face_id).into())
                }
            }
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Clear all PIT entries (for debugging/testing)
    pub async fn clear_pit(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("PIT_TABLE")
                .ok_or("PIT_TABLE map not found")?;
            let mut pit_table: HashMap<&mut aya::maps::MapData, u32, PitEntry> = HashMap::try_from(map)?;
            
            // Clear all PIT entries by iterating through and removing each one
            let mut keys_to_remove = Vec::new();
            for key in pit_table.keys() {
                if let Ok(key_value) = key {
                    keys_to_remove.push(key_value);
                }
            }
            
            for key in keys_to_remove {
                if let Err(e) = pit_table.remove(&key) {
                    warn!("Failed to remove PIT entry {}: {}", key, e);
                }
            }
            
            info!("Cleared all PIT entries");
            Ok(())
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Clear all Content Store entries (for debugging/testing)
    pub async fn clear_content_store(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(bpf_arc) = &self.bpf {
            let mut bpf = bpf_arc.write().await;
            let map = bpf.map_mut("CONTENT_STORE")
                .ok_or("CONTENT_STORE map not found")?;
            let mut cs_table: HashMap<&mut aya::maps::MapData, u32, ContentStoreEntry> = HashMap::try_from(map)?;
            
            // Clear all Content Store entries by iterating through and removing each one
            let mut keys_to_remove = Vec::new();
            for key in cs_table.keys() {
                if let Ok(key_value) = key {
                    keys_to_remove.push(key_value);
                }
            }
            
            for key in keys_to_remove {
                if let Err(e) = cs_table.remove(&key) {
                    warn!("Failed to remove CS entry {}: {}", key, e);
                }
            }
            
            info!("Cleared all Content Store entries");
            Ok(())
        } else {
            Err("eBPF program not loaded".into())
        }
    }

    /// Get health status of the eBPF program
    pub async fn get_health_status(&self) -> Result<EbpfHealthStatus, Box<dyn std::error::Error>> {
        let packet_stats = self.get_packet_stats().await?;
        let pit_stats = self.get_pit_stats().await?;
        let cs_stats = self.get_cs_stats().await?;

        Ok(EbpfHealthStatus {
            program_loaded: self.program_loaded,
            interface_name: self.interface_name.clone(),
            packet_stats,
            pit_stats,
            cs_stats,
        })
    }
}

/// Health status information for the eBPF program
#[derive(Debug, Clone)]
pub struct EbpfHealthStatus {
    pub program_loaded: bool,
    pub interface_name: String,
    pub packet_stats: PacketStats,
    pub pit_stats: PitStats,
    pub cs_stats: ContentStoreStats,
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        if self.program_loaded {
            warn!("eBPF program still loaded during drop - this may cause resource leaks");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ebpf_manager_creation() {
        let manager = EbpfManager::new("eth0".to_string());
        assert!(!manager.is_loaded());
        assert_eq!(manager.interface_name, "eth0");
    }

    #[tokio::test]
    async fn test_ebpf_manager_placeholder_methods() {
        let manager = EbpfManager::new("eth0".to_string());
        
        // Test placeholder methods
        let stats = manager.get_packet_stats().await.unwrap();
        assert_eq!(stats.packets_processed, 0);
        
        let face_info = manager.get_face(1).await.unwrap();
        assert_eq!(face_info.face_id, 1);
        
        let health = manager.get_health_status().await.unwrap();
        assert_eq!(health.interface_name, "eth0");
        assert!(!health.program_loaded);
    }
}