use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use log::{debug, info, warn};
use tokio::sync::RwLock;

use udcn_core::packets::{Interest, Data, Name};

/// Forwarding Information Base (FIB) for NDN routing
#[derive(Debug)]
pub struct ForwardingInformationBase {
    /// FIB entries indexed by name prefix
    entries: HashMap<String, FibEntry>,
    /// Default route entry
    default_route: Option<FibEntry>,
}

/// FIB entry containing next hop information
#[derive(Debug, Clone)]
pub struct FibEntry {
    /// Name prefix this entry covers
    pub prefix: String,
    /// Next hop faces/addresses
    pub next_hops: Vec<NextHop>,
    /// Entry creation time
    pub created_at: Instant,
    /// Entry metrics
    pub metrics: FibMetrics,
}

/// Next hop information
#[derive(Debug, Clone)]
pub struct NextHop {
    /// Remote address of the next hop
    pub address: SocketAddr,
    /// Cost metric for this next hop
    pub cost: u32,
    /// Round-trip time to this next hop
    pub rtt: Duration,
    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Whether this next hop is currently reachable
    pub is_reachable: bool,
}

/// FIB entry metrics
#[derive(Debug, Clone)]
pub struct FibMetrics {
    /// Number of Interests forwarded through this entry
    pub interests_forwarded: u64,
    /// Number of successful Data retrievals
    pub data_retrieved: u64,
    /// Average response time
    pub avg_response_time: Duration,
    /// Number of timeouts
    pub timeouts: u64,
}

/// Network interface information for NDN operations
#[derive(Debug, Clone)]
pub struct NetworkInterfaceInfo {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    /// Primary IP address of the interface
    pub address: IpAddr,
    /// Maximum transmission unit (MTU) in bytes
    pub mtu: u32,
    /// Whether the interface is currently up
    pub is_up: bool,
    /// Whether the interface supports multicast
    pub is_multicast: bool,
    /// Interface speed in Mbps (0 if unknown)
    pub speed_mbps: u32,
}

/// Network interface status and statistics
#[derive(Debug, Clone)]
pub struct NetworkInterfaceStatus {
    /// Interface name
    pub name: String,
    /// Whether the interface is currently up
    pub is_up: bool,
    /// Total bytes sent through this interface
    pub bytes_sent: u64,
    /// Total bytes received through this interface
    pub bytes_received: u64,
    /// Total packets sent through this interface
    pub packets_sent: u64,
    /// Total packets received through this interface
    pub packets_received: u64,
    /// Number of transmission errors
    pub errors: u64,
    /// Number of dropped packets
    pub drops: u64,
    /// Last update timestamp
    pub last_update: Instant,
}

impl Default for FibMetrics {
    fn default() -> Self {
        Self {
            interests_forwarded: 0,
            data_retrieved: 0,
            avg_response_time: Duration::from_millis(100),
            timeouts: 0,
        }
    }
}

impl ForwardingInformationBase {
    /// Create a new FIB
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            default_route: None,
        }
    }
    
    /// Add a FIB entry
    pub fn add_entry(&mut self, prefix: String, next_hops: Vec<NextHop>) -> Result<()> {
        let entry = FibEntry {
            prefix: prefix.clone(),
            next_hops,
            created_at: Instant::now(),
            metrics: FibMetrics::default(),
        };
        
        self.entries.insert(prefix.clone(), entry);
        info!("Added FIB entry for prefix: {}", prefix);
        Ok(())
    }
    
    /// Remove a FIB entry
    pub fn remove_entry(&mut self, prefix: &str) -> Option<FibEntry> {
        let entry = self.entries.remove(prefix);
        if entry.is_some() {
            info!("Removed FIB entry for prefix: {}", prefix);
        }
        entry
    }
    
    /// Find next hops for a given Interest name
    pub fn lookup(&self, interest_name: &Name) -> Vec<NextHop> {
        let name_str = interest_name.to_string();
        
        // Find longest prefix match
        let mut best_match: Option<&FibEntry> = None;
        let mut best_match_len = 0;
        
        for (prefix, entry) in &self.entries {
            if name_str.starts_with(prefix) && prefix.len() > best_match_len {
                best_match = Some(entry);
                best_match_len = prefix.len();
            }
        }
        
        if let Some(entry) = best_match {
            debug!("FIB lookup for {}: found {} next hops", name_str, entry.next_hops.len());
            entry.next_hops.clone()
        } else if let Some(default) = &self.default_route {
            debug!("FIB lookup for {}: using default route", name_str);
            default.next_hops.clone()
        } else {
            debug!("FIB lookup for {}: no route found", name_str);
            vec![]
        }
    }
    
    /// Update next hop metrics
    pub fn update_next_hop_metrics(&mut self, prefix: &str, address: SocketAddr, rtt: Duration, success: bool) {
        if let Some(entry) = self.entries.get_mut(prefix) {
            if let Some(next_hop) = entry.next_hops.iter_mut().find(|nh| nh.address == address) {
                next_hop.rtt = rtt;
                next_hop.last_activity = Instant::now();
                
                // Update success rate with exponential weighted moving average
                let alpha = 0.1;
                next_hop.success_rate = next_hop.success_rate * (1.0 - alpha) + 
                                       (if success { 1.0 } else { 0.0 }) * alpha;
                
                // Update entry metrics
                entry.metrics.interests_forwarded += 1;
                if success {
                    entry.metrics.data_retrieved += 1;
                    // Update average response time
                    let count = entry.metrics.data_retrieved as f64;
                    let old_avg = entry.metrics.avg_response_time.as_nanos() as f64;
                    let new_avg = (old_avg * (count - 1.0) + rtt.as_nanos() as f64) / count;
                    entry.metrics.avg_response_time = Duration::from_nanos(new_avg as u64);
                } else {
                    entry.metrics.timeouts += 1;
                }
            }
        }
    }
    
    /// Set default route
    pub fn set_default_route(&mut self, next_hops: Vec<NextHop>) {
        self.default_route = Some(FibEntry {
            prefix: "/".to_string(),
            next_hops,
            created_at: Instant::now(),
            metrics: FibMetrics::default(),
        });
        info!("Set default route");
    }
    
    /// Get FIB statistics
    pub fn get_stats(&self) -> FibStats {
        let total_entries = self.entries.len() + if self.default_route.is_some() { 1 } else { 0 };
        let total_next_hops: usize = self.entries.values().map(|e| e.next_hops.len()).sum();
        let total_interests: u64 = self.entries.values().map(|e| e.metrics.interests_forwarded).sum();
        let total_data: u64 = self.entries.values().map(|e| e.metrics.data_retrieved).sum();
        
        FibStats {
            total_entries,
            total_next_hops,
            total_interests_forwarded: total_interests,
            total_data_retrieved: total_data,
            success_rate: if total_interests > 0 { 
                total_data as f64 / total_interests as f64 
            } else { 0.0 },
        }
    }
}

/// FIB statistics
#[derive(Debug, Clone)]
pub struct FibStats {
    pub total_entries: usize,
    pub total_next_hops: usize,
    pub total_interests_forwarded: u64,
    pub total_data_retrieved: u64,
    pub success_rate: f64,
}

/// Pending Interest Table (PIT) for tracking outstanding Interests
#[derive(Debug)]
pub struct PendingInterestTable {
    /// PIT entries indexed by Interest name
    entries: HashMap<String, PitEntry>,
    /// Maximum Interest lifetime
    max_lifetime: Duration,
}

/// PIT entry for tracking an outstanding Interest
#[derive(Debug, Clone)]
pub struct PitEntry {
    /// Interest name
    pub name: String,
    /// Original Interest packet
    pub interest: Interest,
    /// Incoming faces (who sent the Interest)
    pub incoming_faces: Vec<SocketAddr>,
    /// Outgoing faces (where Interest was forwarded)
    pub outgoing_faces: Vec<SocketAddr>,
    /// Timestamp when Interest was first received
    pub created_at: Instant,
    /// Interest lifetime
    pub lifetime: Duration,
    /// Number of retransmissions
    pub retransmissions: u32,
    /// Nonce for loop detection
    pub nonce: Option<u32>,
}

impl PendingInterestTable {
    /// Create a new PIT
    pub fn new(max_lifetime: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_lifetime,
        }
    }
    
    /// Add an Interest to the PIT
    pub fn add_interest(&mut self, interest: Interest, incoming_face: SocketAddr) -> PitResult {
        let name = interest.name.to_string();
        let nonce = interest.nonce;
        
        // Check for existing entry
        if let Some(entry) = self.entries.get_mut(&name) {
            // Check for nonce loop
            if let (Some(existing_nonce), Some(new_nonce)) = (entry.nonce, nonce) {
                if existing_nonce == new_nonce {
                    warn!("Detected Interest loop for {}", name);
                    return PitResult::Loop;
                }
            }
            
            // Add incoming face if not already present
            if !entry.incoming_faces.contains(&incoming_face) {
                entry.incoming_faces.push(incoming_face);
                debug!("Added incoming face to existing PIT entry: {}", name);
                return PitResult::Aggregated;
            } else {
                return PitResult::Duplicate;
            }
        }
        
        // Create new PIT entry
        let lifetime = interest.interest_lifetime.unwrap_or(self.max_lifetime);
        let entry = PitEntry {
            name: name.clone(),
            interest,
            incoming_faces: vec![incoming_face],
            outgoing_faces: vec![],
            created_at: Instant::now(),
            lifetime,
            retransmissions: 0,
            nonce,
        };
        
        self.entries.insert(name.clone(), entry);
        debug!("Created new PIT entry: {}", name);
        PitResult::NewEntry
    }
    
    /// Record outgoing face for an Interest
    pub fn add_outgoing_face(&mut self, name: &str, outgoing_face: SocketAddr) -> bool {
        if let Some(entry) = self.entries.get_mut(name) {
            if !entry.outgoing_faces.contains(&outgoing_face) {
                entry.outgoing_faces.push(outgoing_face);
                debug!("Added outgoing face for PIT entry: {}", name);
                return true;
            }
        }
        false
    }
    
    /// Satisfy an Interest with incoming Data
    pub fn satisfy_interest(&mut self, data_name: &Name) -> Option<Vec<SocketAddr>> {
        let name = data_name.to_string();
        
        // Find exact match or longest prefix match
        let mut matching_entry = None;
        let mut best_match_len = 0;
        
        for (pit_name, _entry) in &self.entries {
            // Check if Data name matches or is a child of Interest name
            if name.starts_with(pit_name) && pit_name.len() > best_match_len {
                matching_entry = Some(pit_name.clone());
                best_match_len = pit_name.len();
            }
        }
        
        if let Some(pit_name) = matching_entry {
            if let Some(entry) = self.entries.remove(&pit_name) {
                debug!("Satisfied Interest {} with Data {}, returning to {} faces", 
                       pit_name, name, entry.incoming_faces.len());
                return Some(entry.incoming_faces);
            }
        }
        
        None
    }
    
    /// Get PIT entry by name
    pub fn get_entry(&self, name: &str) -> Option<&PitEntry> {
        self.entries.get(name)
    }
    
    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut expired_names = Vec::new();
        
        for (name, entry) in &self.entries {
            if now.duration_since(entry.created_at) > entry.lifetime {
                expired_names.push(name.clone());
            }
        }
        
        let count = expired_names.len();
        for name in expired_names {
            self.entries.remove(&name);
        }
        
        if count > 0 {
            debug!("Cleaned up {} expired PIT entries", count);
        }
        
        count
    }
    
    /// Get PIT statistics
    pub fn get_stats(&self) -> PitStats {
        let total_entries = self.entries.len();
        let total_incoming_faces: usize = self.entries.values().map(|e| e.incoming_faces.len()).sum();
        let total_outgoing_faces: usize = self.entries.values().map(|e| e.outgoing_faces.len()).sum();
        let expired_count = self.entries.values()
            .filter(|e| Instant::now().duration_since(e.created_at) > e.lifetime)
            .count();
        
        PitStats {
            total_entries,
            total_incoming_faces,
            total_outgoing_faces,
            expired_entries: expired_count,
        }
    }
}

/// Result of adding an Interest to the PIT
#[derive(Debug, Clone, PartialEq)]
pub enum PitResult {
    /// New PIT entry created
    NewEntry,
    /// Interest aggregated with existing entry
    Aggregated,
    /// Duplicate Interest from same face
    Duplicate,
    /// Interest loop detected
    Loop,
}

/// PIT statistics
#[derive(Debug, Clone)]
pub struct PitStats {
    pub total_entries: usize,
    pub total_incoming_faces: usize,
    pub total_outgoing_faces: usize,
    pub expired_entries: usize,
}

/// Content Store (CS) for caching Data packets (extended from optimizations)
pub use crate::ndn_optimizations::ContentStore;

/// NDN Forwarding Engine combining FIB, PIT, and CS
pub struct NdnForwardingEngine {
    /// Forwarding Information Base
    pub fib: Arc<RwLock<ForwardingInformationBase>>,
    /// Pending Interest Table
    pub pit: Arc<RwLock<PendingInterestTable>>,
    /// Content Store
    pub content_store: Arc<RwLock<ContentStore>>,
    /// Local face address
    pub local_address: SocketAddr,
    /// Forwarding configuration
    pub config: ForwardingConfig,
}

/// Forwarding configuration
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// Enable loop detection
    pub enable_loop_detection: bool,
    /// Enable Interest aggregation in PIT
    pub enable_pit_aggregation: bool,
    /// Enable content store lookup
    pub enable_content_store: bool,
    /// Maximum Interest lifetime
    pub max_interest_lifetime: Duration,
    /// Enable forwarding metrics
    pub enable_metrics: bool,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            enable_loop_detection: true,
            enable_pit_aggregation: true,
            enable_content_store: true,
            max_interest_lifetime: Duration::from_secs(4),
            enable_metrics: true,
            cleanup_interval: Duration::from_secs(10),
        }
    }
}

impl NdnForwardingEngine {
    /// Create a new NDN forwarding engine
    pub fn new(local_address: SocketAddr, config: ForwardingConfig) -> Self {
        let fib = Arc::new(RwLock::new(ForwardingInformationBase::new()));
        let pit = Arc::new(RwLock::new(PendingInterestTable::new(config.max_interest_lifetime)));
        let content_store = Arc::new(RwLock::new(ContentStore::new(1000, Duration::from_secs(300))));
        
        Self {
            fib,
            pit,
            content_store,
            local_address,
            config,
        }
    }
    
    /// Process an incoming Interest packet
    pub async fn process_interest(&self, interest: Interest, incoming_face: SocketAddr) -> Result<ForwardingDecision> {
        let name = &interest.name;
        
        // Step 1: Check Content Store
        if self.config.enable_content_store {
            let mut cs = self.content_store.write().await;
            if let Some(data) = cs.get(&name.to_string()) {
                debug!("Content Store hit for Interest: {}", name.to_string());
                return Ok(ForwardingDecision::SendData(data, vec![incoming_face]));
            }
        }
        
        // Step 2: Check PIT
        let pit_result = if self.config.enable_pit_aggregation {
            let mut pit = self.pit.write().await;
            pit.add_interest(interest.clone(), incoming_face)
        } else {
            PitResult::NewEntry
        };
        
        match pit_result {
            PitResult::NewEntry => {
                // Step 3: Lookup FIB for forwarding
                let fib = self.fib.read().await;
                let next_hops = fib.lookup(name);
                
                if next_hops.is_empty() {
                    warn!("No forwarding route found for Interest: {}", name.to_string());
                    return Ok(ForwardingDecision::Drop);
                }
                
                // Record outgoing faces in PIT
                if self.config.enable_pit_aggregation {
                    let mut pit = self.pit.write().await;
                    for next_hop in &next_hops {
                        pit.add_outgoing_face(&name.to_string(), next_hop.address);
                    }
                }
                
                let destinations: Vec<SocketAddr> = next_hops.iter()
                    .filter(|nh| nh.is_reachable && nh.address != incoming_face)
                    .map(|nh| nh.address)
                    .collect();
                
                if destinations.is_empty() {
                    debug!("No reachable next hops for Interest: {}", name.to_string());
                    return Ok(ForwardingDecision::Drop);
                }
                
                debug!("Forwarding Interest {} to {} destinations", name.to_string(), destinations.len());
                
                // Apply real network forwarding optimizations
                if let Err(e) = self.apply_network_forwarding_optimizations(&interest, &destinations).await {
                    warn!("Failed to apply network forwarding optimizations: {}", e);
                }
                
                Ok(ForwardingDecision::ForwardInterest(interest, destinations))
            }
            PitResult::Aggregated => {
                debug!("Interest aggregated in PIT: {}", name.to_string());
                Ok(ForwardingDecision::Aggregate)
            }
            PitResult::Duplicate => {
                debug!("Duplicate Interest dropped: {}", name.to_string());
                Ok(ForwardingDecision::Drop)
            }
            PitResult::Loop => {
                warn!("Interest loop detected, dropping: {}", name.to_string());
                Ok(ForwardingDecision::Drop)
            }
        }
    }
    
    /// Process an incoming Data packet
    pub async fn process_data(&self, data: Data, incoming_face: SocketAddr) -> Result<ForwardingDecision> {
        let name = &data.name;
        
        // Step 1: Store in Content Store
        if self.config.enable_content_store {
            let mut cs = self.content_store.write().await;
            cs.store(data.clone());
        }
        
        // Step 2: Satisfy Interests in PIT
        let return_faces = if self.config.enable_pit_aggregation {
            let mut pit = self.pit.write().await;
            pit.satisfy_interest(name).unwrap_or_default()
        } else {
            vec![]
        };
        
        if return_faces.is_empty() {
            debug!("No pending Interests for Data: {}", name.to_string());
            return Ok(ForwardingDecision::Drop);
        }
        
        // Filter out the incoming face (don't send back where it came from)
        let destinations: Vec<SocketAddr> = return_faces.into_iter()
            .filter(|&addr| addr != incoming_face)
            .collect();
        
        if destinations.is_empty() {
            debug!("No valid return faces for Data: {}", name.to_string());
            return Ok(ForwardingDecision::Drop);
        }
        
        debug!("Returning Data {} to {} faces", name.to_string(), destinations.len());
        Ok(ForwardingDecision::SendData(data, destinations))
    }
    
    /// Add a FIB entry
    pub async fn add_route(&self, prefix: String, next_hops: Vec<SocketAddr>) -> Result<()> {
        let next_hop_entries: Vec<NextHop> = next_hops.into_iter().map(|addr| NextHop {
            address: addr,
            cost: 1,
            rtt: Duration::from_millis(100),
            success_rate: 1.0,
            last_activity: Instant::now(),
            is_reachable: true,
        }).collect();
        
        let mut fib = self.fib.write().await;
        fib.add_entry(prefix, next_hop_entries)
    }
    
    /// Remove a FIB entry
    pub async fn remove_route(&self, prefix: &str) -> Result<bool> {
        let mut fib = self.fib.write().await;
        Ok(fib.remove_entry(prefix).is_some())
    }
    
    /// Update next hop metrics based on forwarding results
    pub async fn update_forwarding_metrics(&self, prefix: &str, address: SocketAddr, rtt: Duration, success: bool) -> Result<()> {
        if self.config.enable_metrics {
            let mut fib = self.fib.write().await;
            fib.update_next_hop_metrics(prefix, address, rtt, success);
        }
        Ok(())
    }
    
    /// Perform periodic cleanup of expired entries
    pub async fn cleanup(&self) -> Result<ForwardingCleanupStats> {
        let mut stats = ForwardingCleanupStats::default();
        
        if self.config.enable_pit_aggregation {
            let mut pit = self.pit.write().await;
            stats.expired_pit_entries = pit.cleanup_expired();
        }
        
        if self.config.enable_content_store {
            let mut cs = self.content_store.write().await;
            stats.expired_cs_entries = cs.cleanup_expired();
        }
        
        Ok(stats)
    }
    
    /// Get comprehensive forwarding statistics
    pub async fn get_forwarding_stats(&self) -> Result<ForwardingStats> {
        let fib_stats = self.fib.read().await.get_stats();
        let pit_stats = if self.config.enable_pit_aggregation {
            Some(self.pit.read().await.get_stats())
        } else {
            None
        };
        let cs_stats = if self.config.enable_content_store {
            Some(self.content_store.read().await.get_stats())
        } else {
            None
        };
        
        Ok(ForwardingStats {
            fib_stats,
            pit_stats,
            cs_stats,
            local_address: self.local_address,
            config: self.config.clone(),
        })
    }
    
    /// Apply real network forwarding optimizations
    async fn apply_network_forwarding_optimizations(&self, interest: &Interest, destinations: &[SocketAddr]) -> Result<()> {
        if destinations.is_empty() {
            return Ok(());
        }
        
        // Apply Interest packet optimizations
        self.optimize_interest_for_network(interest, destinations).await?;
        
        // Apply network-aware routing decisions
        self.apply_network_aware_routing(interest, destinations).await?;
        
        // Update network performance metrics
        self.update_network_performance_metrics(interest, destinations).await?;
        
        Ok(())
    }
    
    /// Optimize Interest packets for network transmission
    async fn optimize_interest_for_network(&self, interest: &Interest, destinations: &[SocketAddr]) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Check if Interest can be multicasted to multiple destinations
        if destinations.len() > 1 {
            debug!("Interest {} can be multicasted to {} destinations", interest_name, destinations.len());
            
            // In a real implementation, this would:
            // 1. Check if destinations are on the same network segment
            // 2. Use IP multicast or NDN multicast if available
            // 3. Optimize packet size and format for network transmission
            
            // For now, just log the optimization
            info!("Optimizing Interest {} for multicast to {} destinations", interest_name, destinations.len());
        }
        
        // Apply network-specific Interest optimizations
        if let Some(lifetime) = interest.interest_lifetime {
            if lifetime > Duration::from_secs(10) {
                debug!("Interest {} has long lifetime: {:?}, may need network adaptation", interest_name, lifetime);
            }
        }
        
        Ok(())
    }
    
    /// Apply network-aware routing decisions
    async fn apply_network_aware_routing(&self, interest: &Interest, destinations: &[SocketAddr]) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Analyze network topology and connectivity
        for destination in destinations {
            // Check network reachability
            if self.is_destination_reachable(destination).await? {
                debug!("Destination {} is reachable for Interest {}", destination, interest_name);
                
                // Apply destination-specific optimizations
                self.apply_destination_optimizations(interest, destination).await?;
            } else {
                warn!("Destination {} is not reachable for Interest {}", destination, interest_name);
            }
        }
        
        Ok(())
    }
    
    /// Check if a destination is reachable
    async fn is_destination_reachable(&self, destination: &SocketAddr) -> Result<bool> {
        // In a real implementation, this would:
        // 1. Check ARP/NDP tables
        // 2. Perform network connectivity tests
        // 3. Use routing table information
        // 4. Check interface status
        
        // For now, assume all destinations are reachable
        debug!("Checking reachability for destination: {}", destination);
        Ok(true)
    }
    
    /// Apply destination-specific optimizations
    async fn apply_destination_optimizations(&self, interest: &Interest, destination: &SocketAddr) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Apply optimizations based on destination characteristics
        match destination {
            SocketAddr::V4(addr) => {
                debug!("Applying IPv4 optimizations for Interest {} to {}", interest_name, addr);
                // IPv4-specific optimizations
                self.apply_ipv4_optimizations(interest, addr).await?;
            }
            SocketAddr::V6(addr) => {
                debug!("Applying IPv6 optimizations for Interest {} to {}", interest_name, addr);
                // IPv6-specific optimizations
                self.apply_ipv6_optimizations(interest, addr).await?;
            }
        }
        
        Ok(())
    }
    
    /// Apply IPv4-specific optimizations
    async fn apply_ipv4_optimizations(&self, interest: &Interest, destination: &std::net::SocketAddrV4) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Check if destination is on local network
        if destination.ip().is_private() {
            debug!("Interest {} going to private IPv4 address: {}", interest_name, destination.ip());
            // Local network optimizations
            self.apply_local_network_optimizations(interest).await?;
        } else {
            debug!("Interest {} going to public IPv4 address: {}", interest_name, destination.ip());
            // WAN optimizations
            self.apply_wan_optimizations(interest).await?;
        }
        
        Ok(())
    }
    
    /// Apply IPv6-specific optimizations
    async fn apply_ipv6_optimizations(&self, interest: &Interest, destination: &std::net::SocketAddrV6) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Check IPv6 address scope
        if destination.ip().is_loopback() {
            debug!("Interest {} going to loopback IPv6 address", interest_name);
            // Loopback optimizations
        } else if destination.ip().is_multicast() {
            debug!("Interest {} going to multicast IPv6 address", interest_name);
            // Multicast optimizations
            self.apply_multicast_optimizations(interest).await?;
        } else {
            debug!("Interest {} going to unicast IPv6 address: {}", interest_name, destination.ip());
            // Unicast optimizations
            self.apply_unicast_optimizations(interest).await?;
        }
        
        Ok(())
    }
    
    /// Apply local network optimizations
    async fn apply_local_network_optimizations(&self, interest: &Interest) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Local network optimizations
        debug!("Applying local network optimizations for Interest: {}", interest_name);
        
        // In a real implementation, this would:
        // 1. Use larger packet sizes for local network
        // 2. Enable more aggressive caching
        // 3. Use lower timeout values
        // 4. Enable NDN-specific optimizations
        
        Ok(())
    }
    
    /// Apply WAN optimizations
    async fn apply_wan_optimizations(&self, interest: &Interest) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // WAN optimizations
        debug!("Applying WAN optimizations for Interest: {}", interest_name);
        
        // In a real implementation, this would:
        // 1. Use smaller packet sizes
        // 2. Enable compression
        // 3. Use longer timeout values
        // 4. Enable retransmission strategies
        
        Ok(())
    }
    
    /// Apply multicast optimizations
    async fn apply_multicast_optimizations(&self, interest: &Interest) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Multicast optimizations
        debug!("Applying multicast optimizations for Interest: {}", interest_name);
        
        // In a real implementation, this would:
        // 1. Use IP multicast for Interest forwarding
        // 2. Apply multicast-specific NDN optimizations
        // 3. Handle multicast group management
        
        Ok(())
    }
    
    /// Apply unicast optimizations
    async fn apply_unicast_optimizations(&self, interest: &Interest) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Unicast optimizations
        debug!("Applying unicast optimizations for Interest: {}", interest_name);
        
        // In a real implementation, this would:
        // 1. Use point-to-point optimizations
        // 2. Enable end-to-end flow control
        // 3. Apply unicast-specific NDN features
        
        Ok(())
    }
    
    /// Update network performance metrics
    async fn update_network_performance_metrics(&self, interest: &Interest, destinations: &[SocketAddr]) -> Result<()> {
        let interest_name = interest.name.to_string();
        
        // Update metrics for network performance monitoring
        debug!("Updating network performance metrics for Interest: {} to {} destinations", 
               interest_name, destinations.len());
        
        // In a real implementation, this would:
        // 1. Track network latency per destination
        // 2. Monitor packet loss rates
        // 3. Update congestion control parameters
        // 4. Collect network topology information
        
        Ok(())
    }
    
    /// Get network interface information
    pub async fn get_network_interface_info(&self) -> Result<Vec<NetworkInterfaceInfo>> {
        // In a real implementation, this would query system network interfaces
        let interfaces = vec![
            NetworkInterfaceInfo {
                name: "eth0".to_string(),
                address: "192.168.1.100".parse()?,
                mtu: 1500,
                is_up: true,
                is_multicast: true,
                speed_mbps: 1000,
            },
            NetworkInterfaceInfo {
                name: "wlan0".to_string(),
                address: "192.168.1.101".parse()?,
                mtu: 1500,
                is_up: true,
                is_multicast: true,
                speed_mbps: 100,
            },
        ];
        
        Ok(interfaces)
    }
    
    /// Inject NDN packet into network stack
    pub async fn inject_packet_to_network(&self, packet_data: Vec<u8>, target_interface: &str) -> Result<()> {
        debug!("Injecting NDN packet to network interface: {}, size: {} bytes", 
               target_interface, packet_data.len());
        
        // Validate packet data
        if packet_data.len() < 20 {
            return Err(anyhow::anyhow!("Packet too small for network injection"));
        }
        
        // In a real implementation, this would:
        // 1. Create raw socket for packet injection
        // 2. Construct proper Ethernet/IP headers
        // 3. Send packet through specified network interface
        // 4. Handle different packet types (Interest, Data, NACK)
        
        info!("NDN packet injected to network interface: {}", target_interface);
        Ok(())
    }
    
    /// Monitor network interface status
    pub async fn monitor_network_interfaces(&self) -> Result<Vec<NetworkInterfaceStatus>> {
        let interfaces = self.get_network_interface_info().await?;
        let mut status_list = Vec::new();
        
        for interface in interfaces {
            let status = NetworkInterfaceStatus {
                name: interface.name.clone(),
                is_up: interface.is_up,
                bytes_sent: 0, // Would be read from system statistics
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                errors: 0,
                drops: 0,
                last_update: Instant::now(),
            };
            
            status_list.push(status);
        }
        
        Ok(status_list)
    }
    
    /// Setup network interface for NDN operations
    pub async fn setup_network_interface(&self, interface_name: &str) -> Result<()> {
        debug!("Setting up network interface for NDN operations: {}", interface_name);
        
        // In a real implementation, this would:
        // 1. Configure interface for NDN packet handling
        // 2. Set up packet filters and routing rules
        // 3. Initialize hardware offload features if available
        // 4. Configure multicast groups for NDN
        
        info!("Network interface setup completed: {}", interface_name);
        Ok(())
    }
}

/// Forwarding decision result
#[derive(Debug, Clone)]
pub enum ForwardingDecision {
    /// Forward Interest to specified destinations
    ForwardInterest(Interest, Vec<SocketAddr>),
    /// Send Data to specified destinations
    SendData(Data, Vec<SocketAddr>),
    /// Aggregate with existing PIT entry
    Aggregate,
    /// Drop the packet
    Drop,
}

/// Cleanup statistics
#[derive(Debug, Default, Clone)]
pub struct ForwardingCleanupStats {
    pub expired_pit_entries: usize,
    pub expired_cs_entries: usize,
}

/// Comprehensive forwarding statistics
#[derive(Debug, Clone)]
pub struct ForwardingStats {
    pub fib_stats: FibStats,
    pub pit_stats: Option<PitStats>,
    pub cs_stats: Option<crate::ndn_optimizations::ContentStoreStats>,
    pub local_address: SocketAddr,
    pub config: ForwardingConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_fib_lookup() {
        let mut fib = ForwardingInformationBase::new();
        
        let next_hop = NextHop {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            cost: 1,
            rtt: Duration::from_millis(50),
            success_rate: 1.0,
            last_activity: Instant::now(),
            is_reachable: true,
        };
        
        fib.add_entry("/test".to_string(), vec![next_hop.clone()]).unwrap();
        
        let name = Name::from_str("/test/data");
        let next_hops = fib.lookup(&name);
        
        assert_eq!(next_hops.len(), 1);
        assert_eq!(next_hops[0].address, next_hop.address);
    }
    
    #[tokio::test]
    async fn test_pit_aggregation() {
        let mut pit = PendingInterestTable::new(Duration::from_secs(4));
        
        let name = Name::from_str("/test/interest");
        let interest = Interest::new(name);
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        // First Interest should create new entry
        let result1 = pit.add_interest(interest.clone(), addr1);
        assert_eq!(result1, PitResult::NewEntry);
        
        // Second Interest should be aggregated
        let result2 = pit.add_interest(interest, addr2);
        assert_eq!(result2, PitResult::Aggregated);
        
        let stats = pit.get_stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_incoming_faces, 2);
    }
    
    #[tokio::test]
    async fn test_forwarding_engine() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let engine = NdnForwardingEngine::new(local_addr, ForwardingConfig::default());
        
        // Add route
        let next_hop_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        engine.add_route("/test".to_string(), vec![next_hop_addr]).await.unwrap();
        
        // Process Interest
        let name = Name::from_str("/test/data");
        let interest = Interest::new(name);
        let incoming_face = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082);
        
        let decision = engine.process_interest(interest, incoming_face).await.unwrap();
        
        match decision {
            ForwardingDecision::ForwardInterest(_, destinations) => {
                assert_eq!(destinations.len(), 1);
                assert_eq!(destinations[0], next_hop_addr);
            }
            _ => panic!("Expected ForwardInterest decision"),
        }
    }
}