use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{timeout, Duration};
use log::{debug, error, info, warn};

use udcn_core::packets::{Interest, Data};
use crate::transport_manager::{TransportManager, IncomingPacket};

/// Content store entry
#[derive(Debug, Clone)]
struct ContentEntry {
    data: Data,
    stored_at: std::time::Instant,
    freshness_period: Option<Duration>,
    access_count: u64,
}

impl ContentEntry {
    fn new(data: Data) -> Self {
        Self {
            data,
            stored_at: std::time::Instant::now(),
            freshness_period: Some(Duration::from_secs(300)), // 5 minutes default
            access_count: 0,
        }
    }

    fn is_fresh(&self) -> bool {
        if let Some(freshness_period) = self.freshness_period {
            self.stored_at.elapsed() < freshness_period
        } else {
            true // No freshness period means always fresh
        }
    }
}

/// NDN Packet Handler for processing Interest and Data packets
pub struct PacketHandler {
    content_store: Arc<RwLock<HashMap<String, ContentEntry>>>,
    transport_manager: Arc<RwLock<TransportManager>>,
    running: Arc<RwLock<bool>>,
    stats: Arc<RwLock<PacketHandlerStats>>,
    packet_receiver: Option<mpsc::Receiver<IncomingPacket>>,
}

#[derive(Debug, Default)]
pub struct PacketHandlerStats {
    pub interests_received: u64,
    pub interests_satisfied: u64,
    pub interests_timeout: u64,
    pub data_received: u64,
    pub data_stored: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl PacketHandler {
    /// Create a new packet handler
    pub fn new(
        transport_manager: Arc<RwLock<TransportManager>>,
    ) -> Self {
        Self {
            content_store: Arc::new(RwLock::new(HashMap::new())),
            transport_manager,
            running: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(PacketHandlerStats::default())),
            packet_receiver: None,
        }
    }

    /// Set the packet receiver
    pub fn set_packet_receiver(&mut self, receiver: mpsc::Receiver<IncomingPacket>) {
        self.packet_receiver = Some(receiver);
    }

    /// Start the packet handler
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting NDN Packet Handler");
        
        if self.packet_receiver.is_none() {
            return Err("Packet receiver not set. Call set_packet_receiver first.".into());
        }
        
        *self.running.write().await = true;
        
        // Take the receiver
        let receiver = self.packet_receiver.take().unwrap();
        
        // Start the packet processing loop
        let content_store = self.content_store.clone();
        let transport_manager = self.transport_manager.clone();
        let running = self.running.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            Self::packet_processing_loop(
                receiver,
                content_store,
                transport_manager,
                running,
                stats,
            ).await;
        });
        
        info!("NDN Packet Handler started with packet receiver");
        Ok(())
    }

    /// Stop the packet handler
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Stopping NDN Packet Handler");
        *self.running.write().await = false;
        Ok(())
    }

    /// Main packet processing loop
    async fn packet_processing_loop(
        mut receiver: mpsc::Receiver<IncomingPacket>,
        content_store: Arc<RwLock<HashMap<String, ContentEntry>>>,
        transport_manager: Arc<RwLock<TransportManager>>,
        running: Arc<RwLock<bool>>,
        stats: Arc<RwLock<PacketHandlerStats>>,
    ) {
        info!("Packet processing loop started");
        while *running.read().await {
            // Wait for incoming packet
            match timeout(Duration::from_millis(1000), receiver.recv()).await {
                Ok(Some(packet)) => {
                    info!("Received packet in PacketHandler");
                    match packet {
                        IncomingPacket::Interest(interest, src_addr) => {
                            info!("Processing Interest for {} from {}", interest.name, src_addr);
                            stats.write().await.interests_received += 1;
                            
                            // Look up content in store
                            let name_str = interest.name.to_string();
                            let mut store = content_store.write().await;
                            
                            if let Some(entry) = store.get_mut(&name_str) {
                                if entry.is_fresh() {
                                    // Cache hit - respond with data
                                    info!("Cache hit for {}", name_str);
                                    entry.access_count += 1;
                                    
                                    let data = entry.data.clone();
                                    drop(store); // Release lock before sending
                                    
                                    if let Err(e) = transport_manager.read().await.send_data(&data, src_addr).await {
                                        error!("Failed to send data response: {}", e);
                                    } else {
                                        info!("Sent data response for {} to {}", name_str, src_addr);
                                        stats.write().await.interests_satisfied += 1;
                                        stats.write().await.cache_hits += 1;
                                    }
                                } else {
                                    // Entry expired - remove it
                                    info!("Cache entry expired for {}", name_str);
                                    store.remove(&name_str);
                                    stats.write().await.cache_misses += 1;
                                }
                            } else {
                                // Cache miss
                                info!("Cache miss for {}", name_str);
                                stats.write().await.cache_misses += 1;
                            }
                        }
                        IncomingPacket::Data(data, src_addr) => {
                            info!("Processing Data for {} from {}", data.name, src_addr);
                            stats.write().await.data_received += 1;
                            
                            // Store in content store
                            let name_str = data.name.to_string();
                            let entry = ContentEntry::new(data);
                            
                            content_store.write().await.insert(name_str.clone(), entry);
                            info!("Stored data for {} in content store", name_str);
                            stats.write().await.data_stored += 1;
                        }
                        IncomingPacket::Unknown(_, src_addr) => {
                            warn!("Received unknown packet from {}", src_addr);
                        }
                    }
                }
                Ok(None) => {
                    // Channel closed
                    break;
                }
                Err(_) => {
                    // Timeout - this is normal, just continue
                }
            }
        }
        
        info!("Packet processing loop stopped");
    }


    /// Store data in the content store
    pub async fn store_data(&self, data: Data) {
        let name_str = data.name.to_string();
        let entry = ContentEntry::new(data);
        
        self.content_store.write().await.insert(name_str.clone(), entry);
        debug!("Manually stored data for {} in content store", name_str);
        self.stats.write().await.data_stored += 1;
    }

    /// Get content from the store
    pub async fn get_data(&self, name: &str) -> Option<Data> {
        let mut store = self.content_store.write().await;
        if let Some(entry) = store.get_mut(name) {
            if entry.is_fresh() {
                entry.access_count += 1;
                Some(entry.data.clone())
            } else {
                store.remove(name);
                None
            }
        } else {
            None
        }
    }

    /// Get packet handler statistics
    pub async fn get_stats(&self) -> PacketHandlerStats {
        let stats = self.stats.read().await;
        PacketHandlerStats {
            interests_received: stats.interests_received,
            interests_satisfied: stats.interests_satisfied,
            interests_timeout: stats.interests_timeout,
            data_received: stats.data_received,
            data_stored: stats.data_stored,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
        }
    }

    /// Clear the content store
    pub async fn clear_content_store(&self) {
        self.content_store.write().await.clear();
        info!("Content store cleared");
    }

    /// Get content store size
    pub async fn get_content_store_size(&self) -> usize {
        self.content_store.read().await.len()
    }

    /// Clean up expired entries
    pub async fn cleanup_expired_entries(&self) {
        let mut store = self.content_store.write().await;
        let initial_size = store.len();
        
        store.retain(|_, entry| entry.is_fresh());
        
        let removed = initial_size - store.len();
        if removed > 0 {
            debug!("Cleaned up {} expired entries from content store", removed);
        }
    }
}

/// Content store statistics
#[derive(Debug, Clone)]
pub struct ContentStoreStats {
    pub total_entries: usize,
    pub total_size_bytes: usize,
    pub cache_hit_rate: f64,
    pub oldest_entry_age_secs: Option<u64>,
}

impl PacketHandler {
    /// Get detailed content store statistics
    pub async fn get_content_store_stats(&self) -> ContentStoreStats {
        let store = self.content_store.read().await;
        let stats = self.stats.read().await;
        
        let total_entries = store.len();
        let mut total_size_bytes = 0;
        let mut oldest_entry_age_secs = None;
        
        for entry in store.values() {
            total_size_bytes += entry.data.content.len();
            
            let age_secs = entry.stored_at.elapsed().as_secs();
            oldest_entry_age_secs = Some(
                oldest_entry_age_secs.map_or(age_secs, |oldest: u64| oldest.max(age_secs))
            );
        }
        
        let cache_hit_rate = if stats.cache_hits + stats.cache_misses > 0 {
            stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64
        } else {
            0.0
        };
        
        ContentStoreStats {
            total_entries,
            total_size_bytes,
            cache_hit_rate,
            oldest_entry_age_secs,
        }
    }
}