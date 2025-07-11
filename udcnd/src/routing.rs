use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

use async_trait::async_trait;
use udcn_core::packets::{Interest, Data};
use udcn_transport::{NdnForwardingEngine, ForwardingConfig, ForwardingDecision};

use crate::service::Service;
use crate::transport_manager::{TransportManager, TransportConfig};

/// Routing strategy type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RoutingStrategy {
    /// Best route strategy - forward to the lowest cost next hop
    BestRoute,
    /// Multicast strategy - forward to all available next hops
    Multicast,
    /// Broadcast strategy - forward to all faces
    Broadcast,
    /// Load balancing strategy - distribute load across multiple next hops
    LoadBalancing,
}

/// Routing configuration
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Default routing strategy
    pub default_strategy: RoutingStrategy,
    /// Enable Interest aggregation
    pub enable_interest_aggregation: bool,
    /// Enable Data packet caching
    pub enable_content_store: bool,
    /// Maximum number of next hops per FIB entry
    pub max_next_hops: usize,
    /// PIT entry lifetime in milliseconds
    pub pit_lifetime_ms: u64,
    /// Content store size limit
    pub content_store_size: usize,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_strategy: RoutingStrategy::BestRoute,
            enable_interest_aggregation: true,
            enable_content_store: true,
            max_next_hops: 10,
            pit_lifetime_ms: 4000,
            content_store_size: 1000,
        }
    }
}

/// Routing statistics
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    /// Total number of forwarded Interests
    pub interests_forwarded: u64,
    /// Total number of forwarded Data packets
    pub data_forwarded: u64,
    /// Number of dropped Interest packets
    pub interests_dropped: u64,
    /// Number of dropped Data packets
    pub data_dropped: u64,
    /// Number of PIT hits
    pub pit_hits: u64,
    /// Number of Content Store hits
    pub cs_hits: u64,
    /// Number of FIB lookups
    pub fib_lookups: u64,
    /// Total number of packets sent
    pub packets_sent: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total Data packets sent
    pub data_sent: u64,
}

/// Routing Manager service for NDN packet forwarding
pub struct RoutingManager {
    /// NDN Forwarding Engine
    forwarding_engine: Arc<NdnForwardingEngine>,
    /// Routing configuration
    config: Arc<RwLock<RoutingConfig>>,
    /// Strategy table mapping name prefixes to strategies
    strategy_table: Arc<RwLock<HashMap<String, RoutingStrategy>>>,
    /// Routing statistics
    stats: Arc<RwLock<RoutingStats>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
    /// Transport manager for packet transmission
    transport_manager: Arc<RwLock<TransportManager>>,
    /// Face to address mapping
    face_to_addr_map: Arc<RwLock<HashMap<u32, SocketAddr>>>,
}

impl RoutingManager {
    /// Create a new routing manager
    pub fn new(local_address: SocketAddr) -> Self {
        let forwarding_config = ForwardingConfig::default();
        let forwarding_engine = Arc::new(NdnForwardingEngine::new(local_address, forwarding_config));
        
        // Create transport manager with local address and port
        let transport_config = TransportConfig {
            local_port: local_address.port(),
            bind_address: local_address.ip().to_string(),
            ..Default::default()
        };
        let transport_manager = Arc::new(RwLock::new(TransportManager::new(transport_config)));
        
        Self {
            forwarding_engine,
            config: Arc::new(RwLock::new(RoutingConfig::default())),
            strategy_table: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RoutingStats::default())),
            running: Arc::new(RwLock::new(false)),
            transport_manager,
            face_to_addr_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a face-to-address mapping
    pub async fn register_face_address(&self, face_id: u32, address: SocketAddr) {
        let mut face_map = self.face_to_addr_map.write().await;
        face_map.insert(face_id, address);
        debug!("Registered face {} -> {}", face_id, address);
    }

    /// Unregister a face-to-address mapping
    pub async fn unregister_face_address(&self, face_id: u32) {
        let mut face_map = self.face_to_addr_map.write().await;
        if let Some(addr) = face_map.remove(&face_id) {
            debug!("Unregistered face {} -> {}", face_id, addr);
        }
    }

    /// Get the address for a face ID
    pub async fn get_face_address(&self, face_id: u32) -> Option<SocketAddr> {
        let face_map = self.face_to_addr_map.read().await;
        face_map.get(&face_id).copied()
    }

    /// Convert face ID to SocketAddr with fallback
    async fn face_id_to_addr(&self, face_id: u32) -> SocketAddr {
        // Try to get the real address from the face mapping
        if let Some(addr) = self.get_face_address(face_id).await {
            addr
        } else {
            // Fallback to localhost with face ID as port for compatibility
            warn!("Face {} not found in address mapping, using fallback", face_id);
            SocketAddr::from(([127, 0, 0, 1], face_id as u16))
        }
    }

    /// Process incoming Interest packet
    pub async fn process_interest(&self, interest: Interest, incoming_face: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Processing Interest: {} from face {}", interest.name, incoming_face);
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.fib_lookups += 1;
        }

        // Convert face ID to SocketAddr using face mapping
        let incoming_addr = self.face_id_to_addr(incoming_face).await;

        // Forward Interest using the forwarding engine
        match self.forwarding_engine.process_interest(interest.clone(), incoming_addr).await {
            Ok(decision) => {
                match decision {
                    ForwardingDecision::ForwardInterest(interest, next_hops) => {
                        debug!("Forwarding Interest to {} next hops", next_hops.len());
                        
                        // Forward to each next hop
                        for next_hop in next_hops {
                            if let Err(e) = self.send_interest_to_addr(&interest, next_hop).await {
                                warn!("Failed to forward Interest to {}: {}", next_hop, e);
                            }
                        }
                        
                        // Update statistics
                        let mut stats = self.stats.write().await;
                        stats.interests_forwarded += 1;
                    }
                    ForwardingDecision::Drop => {
                        debug!("Dropping Interest");
                        let mut stats = self.stats.write().await;
                        stats.interests_dropped += 1;
                    }
                    ForwardingDecision::Aggregate => {
                        debug!("Aggregating Interest with existing PIT entry");
                        let mut stats = self.stats.write().await;
                        stats.pit_hits += 1;
                    }
                    ForwardingDecision::SendData(data, destinations) => {
                        debug!("Satisfying Interest from Content Store");
                        for dest in destinations {
                            if let Err(e) = self.send_data_to_addr(&data, dest).await {
                                warn!("Failed to send Data to {}: {}", dest, e);
                            }
                        }
                        let mut stats = self.stats.write().await;
                        stats.cs_hits += 1;
                    }
                }
            }
            Err(e) => {
                error!("Error forwarding Interest: {}", e);
                let mut stats = self.stats.write().await;
                stats.interests_dropped += 1;
            }
        }

        Ok(())
    }

    /// Process incoming Data packet
    pub async fn process_data(&self, data: Data, incoming_face: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Processing Data: {} from face {}", data.name, incoming_face);

        // Convert face ID to SocketAddr using face mapping
        let incoming_addr = self.face_id_to_addr(incoming_face).await;

        // Forward Data using the forwarding engine
        match self.forwarding_engine.process_data(data.clone(), incoming_addr).await {
            Ok(decision) => {
                match decision {
                    ForwardingDecision::SendData(data, destinations) => {
                        debug!("Forwarding Data to {} destinations", destinations.len());
                        
                        // Forward to each destination
                        for dest in destinations {
                            if let Err(e) = self.send_data_to_addr(&data, dest).await {
                                warn!("Failed to forward Data to {}: {}", dest, e);
                            }
                        }
                        
                        // Update statistics
                        let mut stats = self.stats.write().await;
                        stats.data_forwarded += 1;
                    }
                    ForwardingDecision::Drop => {
                        debug!("Dropping Data");
                        let mut stats = self.stats.write().await;
                        stats.data_dropped += 1;
                    }
                    ForwardingDecision::Aggregate => {
                        debug!("Unexpected Aggregate decision for Data packet");
                    }
                    ForwardingDecision::ForwardInterest(_, _) => {
                        debug!("Unexpected ForwardInterest decision for Data packet");
                    }
                }
            }
            Err(e) => {
                error!("Error forwarding Data: {}", e);
                let mut stats = self.stats.write().await;
                stats.data_dropped += 1;
            }
        }

        Ok(())
    }

    /// Add a FIB entry
    pub async fn add_fib_entry(&self, prefix: &str, next_hop: SocketAddr, cost: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Adding FIB entry: {} -> {} (cost: {})", prefix, next_hop, cost);
        self.forwarding_engine.add_route(prefix.to_string(), vec![next_hop]).await?;
        Ok(())
    }

    /// Remove a FIB entry
    pub async fn remove_fib_entry(&self, prefix: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Removing FIB entry: {}", prefix);
        self.forwarding_engine.remove_route(prefix).await?;
        Ok(())
    }

    /// Set routing strategy for a name prefix
    pub async fn set_strategy(&self, prefix: String, strategy: RoutingStrategy) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Setting routing strategy for {}: {:?}", prefix, strategy);
        let mut strategy_table = self.strategy_table.write().await;
        strategy_table.insert(prefix, strategy);
        Ok(())
    }

    /// Get routing strategy for a name prefix
    pub async fn get_strategy(&self, prefix: &str) -> RoutingStrategy {
        let strategy_table = self.strategy_table.read().await;
        
        // Find the longest matching prefix
        let mut best_match = None;
        let mut best_length = 0;
        
        for (table_prefix, strategy) in strategy_table.iter() {
            if prefix.starts_with(table_prefix) && table_prefix.len() > best_length {
                best_match = Some(*strategy);
                best_length = table_prefix.len();
            }
        }
        
        best_match.unwrap_or(self.config.read().await.default_strategy)
    }

    /// Get routing statistics
    pub async fn get_stats(&self) -> RoutingStats {
        self.stats.read().await.clone()
    }

    /// Reset routing statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = RoutingStats::default();
    }

    /// Send Interest to a specific address
    async fn send_interest_to_addr(&self, interest: &Interest, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Sending Interest {} to address {}", interest.name, addr);
        
        // Use transport manager to send the Interest
        let transport_manager = self.transport_manager.read().await;
        let bytes_sent = transport_manager.send_interest(interest, addr).await?;
        
        debug!("Sent {} bytes for Interest {} to {}", bytes_sent, interest.name, addr);
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.packets_sent += 1;
            stats.bytes_sent += bytes_sent as u64;
        }
        
        Ok(())
    }

    /// Send Data to a specific address
    async fn send_data_to_addr(&self, data: &Data, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Sending Data {} to address {}", data.name, addr);
        
        // Use transport manager to send the Data
        let transport_manager = self.transport_manager.read().await;
        let bytes_sent = transport_manager.send_data(data, addr).await?;
        
        debug!("Sent {} bytes for Data {} to {}", bytes_sent, data.name, addr);
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.packets_sent += 1;
            stats.bytes_sent += bytes_sent as u64;
            stats.data_sent += 1;
        }
        
        Ok(())
    }

    /// Update routing configuration
    pub async fn update_config(&self, config: RoutingConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Updating routing configuration");
        let mut current_config = self.config.write().await;
        *current_config = config;
        Ok(())
    }

    /// Get current routing configuration
    pub async fn get_config(&self) -> RoutingConfig {
        self.config.read().await.clone()
    }

    /// Check if routing manager is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

#[async_trait]
impl Service for RoutingManager {
    fn name(&self) -> &str {
        "RoutingManager"
    }

    fn is_running(&self) -> bool {
        // Use blocking version for trait requirement
        futures::executor::block_on(async {
            *self.running.read().await
        })
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting Routing Manager");
        
        // Start transport manager
        {
            let mut transport_manager = self.transport_manager.write().await;
            transport_manager.start().await?;
        }
        
        // Mark as running
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Load FIB entries from configuration will be done by the daemon
        
        info!("Routing Manager started successfully");
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Stopping Routing Manager");
        
        // Mark as not running
        {
            let mut running = self.running.write().await;
            *running = false;
        }
        
        // Stop transport manager
        {
            let mut transport_manager = self.transport_manager.write().await;
            transport_manager.stop().await?;
        }

        info!("Routing Manager stopped successfully");
        Ok(())
    }

    async fn restart(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Restarting Routing Manager");
        self.stop().await?;
        self.start().await?;
        Ok(())
    }
}

impl RoutingManager {
    /// Get the transport manager used by this routing manager
    pub fn get_transport_manager(&self) -> Arc<RwLock<TransportManager>> {
        self.transport_manager.clone()
    }
}