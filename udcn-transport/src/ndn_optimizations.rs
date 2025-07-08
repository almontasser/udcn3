use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use log::{debug, info};
use tokio::sync::RwLock;

use udcn_core::packets::{Interest, Data, Name};

/// Interest aggregation engine for reducing duplicate Interests
#[derive(Debug)]
pub struct InterestAggregator {
    /// Aggregated Interests indexed by name
    aggregated_interests: HashMap<String, AggregatedInterest>,
    /// Maximum aggregation window
    aggregation_window: Duration,
    /// Maximum number of Interests to aggregate
    max_aggregation_count: usize,
}

/// Aggregated Interest information
#[derive(Debug, Clone)]
pub struct AggregatedInterest {
    /// Original Interest
    pub interest: Interest,
    /// List of requesters waiting for this Interest
    pub requesters: Vec<SocketAddr>,
    /// Timestamp when first Interest was received
    pub first_received: Instant,
    /// Number of aggregated Interests
    pub count: usize,
    /// Whether the Interest has been forwarded
    pub forwarded: bool,
}

impl InterestAggregator {
    /// Create a new Interest aggregator
    pub fn new(aggregation_window: Duration, max_aggregation_count: usize) -> Self {
        Self {
            aggregated_interests: HashMap::new(),
            aggregation_window,
            max_aggregation_count,
        }
    }
    
    /// Try to aggregate an incoming Interest
    /// Returns true if Interest was aggregated, false if it should be forwarded
    pub fn try_aggregate(&mut self, interest: &Interest, requester: SocketAddr) -> bool {
        let name = interest.name.to_string();
        
        match self.aggregated_interests.get_mut(&name) {
            Some(aggregated) => {
                // Check if aggregation window is still valid
                if aggregated.first_received.elapsed() <= self.aggregation_window &&
                   aggregated.count < self.max_aggregation_count {
                    
                    // Add requester if not already present
                    if !aggregated.requesters.contains(&requester) {
                        aggregated.requesters.push(requester);
                        aggregated.count += 1;
                        debug!("Aggregated Interest: {} (count: {})", name, aggregated.count);
                        return true;
                    }
                }
                
                // Aggregation expired or full, clean up and forward
                self.aggregated_interests.remove(&name);
                false
            }
            None => {
                // First Interest for this name
                let aggregated = AggregatedInterest {
                    interest: interest.clone(),
                    requesters: vec![requester],
                    first_received: Instant::now(),
                    count: 1,
                    forwarded: false,
                };
                
                self.aggregated_interests.insert(name.clone(), aggregated);
                debug!("Started aggregating Interest: {}", name);
                false // Don't forward immediately, wait for aggregation window
            }
        }
    }
    
    /// Get Interests ready for forwarding (aggregation window expired)
    pub fn get_ready_interests(&mut self) -> Vec<(Interest, Vec<SocketAddr>)> {
        let mut ready = Vec::new();
        let now = Instant::now();
        
        let mut to_remove = Vec::new();
        for (name, aggregated) in self.aggregated_interests.iter_mut() {
            if !aggregated.forwarded && now.duration_since(aggregated.first_received) >= self.aggregation_window {
                ready.push((aggregated.interest.clone(), aggregated.requesters.clone()));
                aggregated.forwarded = true;
                to_remove.push(name.clone());
            }
        }
        
        // Remove forwarded Interests
        for name in to_remove {
            self.aggregated_interests.remove(&name);
        }
        
        if !ready.is_empty() {
            debug!("Ready to forward {} aggregated Interests", ready.len());
        }
        
        ready
    }
    
    /// Handle incoming Data and distribute to aggregated requesters
    pub fn handle_data(&mut self, data: &Data) -> Vec<SocketAddr> {
        let name = data.name.to_string();
        
        if let Some(aggregated) = self.aggregated_interests.remove(&name) {
            debug!("Distributing Data {} to {} requesters", name, aggregated.requesters.len());
            aggregated.requesters
        } else {
            vec![]
        }
    }
    
    /// Clean up expired aggregations
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut expired_names = Vec::new();
        
        for (name, aggregated) in &self.aggregated_interests {
            if now.duration_since(aggregated.first_received) > self.aggregation_window * 2 {
                expired_names.push(name.clone());
            }
        }
        
        let count = expired_names.len();
        for name in expired_names {
            self.aggregated_interests.remove(&name);
        }
        
        if count > 0 {
            debug!("Cleaned up {} expired Interest aggregations", count);
        }
        
        count
    }
    
    /// Get aggregation statistics
    pub fn get_stats(&self) -> InterestAggregationStats {
        let total_interests: usize = self.aggregated_interests.values().map(|a| a.count).sum();
        let total_requesters: usize = self.aggregated_interests.values()
            .map(|a| a.requesters.len()).sum();
        
        InterestAggregationStats {
            active_aggregations: self.aggregated_interests.len(),
            total_aggregated_interests: total_interests,
            total_requesters,
            aggregation_window: self.aggregation_window,
            max_aggregation_count: self.max_aggregation_count,
        }
    }
}

/// Interest aggregation statistics
#[derive(Debug, Clone)]
pub struct InterestAggregationStats {
    pub active_aggregations: usize,
    pub total_aggregated_interests: usize,
    pub total_requesters: usize,
    pub aggregation_window: Duration,
    pub max_aggregation_count: usize,
}

/// Content Store for caching Data packets
#[derive(Debug)]
pub struct ContentStore {
    /// Cached Data indexed by name
    cache: HashMap<String, CachedData>,
    /// LRU queue for cache eviction
    lru_queue: VecDeque<String>,
    /// Maximum cache size (number of entries)
    max_cache_size: usize,
    /// Maximum Data freshness before eviction
    max_freshness: Duration,
}

/// Cached Data entry
#[derive(Debug, Clone)]
pub struct CachedData {
    /// The Data packet
    pub data: Data,
    /// Timestamp when Data was cached
    pub cached_at: Instant,
    /// Number of cache hits
    pub hit_count: u64,
    /// Last access time for LRU
    pub last_accessed: Instant,
}

impl ContentStore {
    /// Create a new content store
    pub fn new(max_cache_size: usize, max_freshness: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            lru_queue: VecDeque::new(),
            max_cache_size,
            max_freshness,
        }
    }
    
    /// Store Data in the cache
    pub fn store(&mut self, data: Data) -> bool {
        let name = data.name.to_string();
        
        // Check if Data is cacheable (has freshness info)
        if !self.is_cacheable(&data) {
            return false;
        }
        
        // Remove from LRU queue if already present
        if let Some(pos) = self.lru_queue.iter().position(|n| n == &name) {
            self.lru_queue.remove(pos);
        }
        
        // Add to front of LRU queue
        self.lru_queue.push_front(name.clone());
        
        // Evict if cache is full
        while self.cache.len() >= self.max_cache_size && !self.lru_queue.is_empty() {
            if let Some(oldest_name) = self.lru_queue.pop_back() {
                self.cache.remove(&oldest_name);
            }
        }
        
        // Store the Data
        let cached_data = CachedData {
            data,
            cached_at: Instant::now(),
            hit_count: 0,
            last_accessed: Instant::now(),
        };
        
        self.cache.insert(name.clone(), cached_data);
        debug!("Cached Data: {} (cache size: {})", name, self.cache.len());
        true
    }
    
    /// Retrieve Data from cache
    pub fn get(&mut self, name: &str) -> Option<Data> {
        if let Some(cached) = self.cache.get_mut(name) {
            // Check if Data is still fresh
            if cached.cached_at.elapsed() <= self.max_freshness {
                // Update LRU information
                cached.hit_count += 1;
                cached.last_accessed = Instant::now();
                
                // Move to front of LRU queue
                if let Some(pos) = self.lru_queue.iter().position(|n| n == name) {
                    let name_owned = self.lru_queue.remove(pos).unwrap();
                    self.lru_queue.push_front(name_owned);
                }
                
                debug!("Cache hit: {} (hit count: {})", name, cached.hit_count);
                return Some(cached.data.clone());
            } else {
                // Data expired, remove from cache
                self.cache.remove(name);
                if let Some(pos) = self.lru_queue.iter().position(|n| n == name) {
                    self.lru_queue.remove(pos);
                }
                debug!("Cache expired: {}", name);
            }
        }
        
        None
    }
    
    /// Check if Data is cacheable
    fn is_cacheable(&self, data: &Data) -> bool {
        // Check if Data has meta info and freshness period
        data.meta_info.is_some() && 
        data.meta_info.as_ref().unwrap().freshness_period.is_some() &&
        data.meta_info.as_ref().unwrap().freshness_period.unwrap() > Duration::from_secs(0)
    }
    
    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut expired_names = Vec::new();
        
        for (name, cached) in &self.cache {
            if now.duration_since(cached.cached_at) > self.max_freshness {
                expired_names.push(name.clone());
            }
        }
        
        let count = expired_names.len();
        for name in &expired_names {
            self.cache.remove(name);
            if let Some(pos) = self.lru_queue.iter().position(|n| n == name) {
                self.lru_queue.remove(pos);
            }
        }
        
        if count > 0 {
            debug!("Cleaned up {} expired cache entries", count);
        }
        
        count
    }
    
    /// Get cache statistics
    pub fn get_stats(&self) -> ContentStoreStats {
        let total_hits: u64 = self.cache.values().map(|c| c.hit_count).sum();
        let total_size: usize = self.cache.values().map(|c| c.data.content.len()).sum();
        
        ContentStoreStats {
            cache_entries: self.cache.len(),
            max_cache_size: self.max_cache_size,
            total_hits,
            total_size_bytes: total_size,
            hit_ratio: if self.cache.is_empty() { 0.0 } else { 
                total_hits as f64 / self.cache.len() as f64 
            },
        }
    }
    
    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
        self.lru_queue.clear();
        info!("Content store cleared");
    }
}

/// Content store statistics
#[derive(Debug, Clone)]
pub struct ContentStoreStats {
    pub cache_entries: usize,
    pub max_cache_size: usize,
    pub total_hits: u64,
    pub total_size_bytes: usize,
    pub hit_ratio: f64,
}

/// NDN packet flow optimizer for QUIC streams
#[derive(Debug)]
pub struct PacketFlowOptimizer {
    /// Stream assignments for different packet types
    stream_assignments: HashMap<String, u64>, // Name prefix -> Stream ID
    /// Stream load balancing information
    stream_loads: HashMap<u64, StreamLoadInfo>,
    /// Next stream ID to assign
    next_stream_id: u64,
    /// Maximum number of concurrent streams
    max_streams: u64,
}

/// Stream load information
#[derive(Debug, Clone)]
pub struct StreamLoadInfo {
    /// Number of active packets on this stream
    pub active_packets: usize,
    /// Bytes transferred on this stream
    pub bytes_transferred: u64,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Average RTT for this stream
    pub avg_rtt: Duration,
}

impl PacketFlowOptimizer {
    /// Create a new packet flow optimizer
    pub fn new(max_streams: u64) -> Self {
        Self {
            stream_assignments: HashMap::new(),
            stream_loads: HashMap::new(),
            next_stream_id: 1,
            max_streams,
        }
    }
    
    /// Get optimal stream for an Interest
    pub fn get_optimal_stream_for_interest(&mut self, interest: &Interest) -> u64 {
        let name_prefix = self.extract_name_prefix(&interest.name);
        
        // Check if we have a stream assignment for this prefix
        if let Some(&stream_id) = self.stream_assignments.get(&name_prefix) {
            if let Some(load_info) = self.stream_loads.get_mut(&stream_id) {
                load_info.active_packets += 1;
                load_info.last_activity = Instant::now();
                return stream_id;
            }
        }
        
        // Find least loaded stream or create new one
        let stream_id = self.find_least_loaded_stream();
        self.stream_assignments.insert(name_prefix, stream_id);
        
        // Update stream load
        self.stream_loads.entry(stream_id).or_insert_with(|| StreamLoadInfo {
            active_packets: 1,
            bytes_transferred: 0,
            last_activity: Instant::now(),
            avg_rtt: Duration::from_millis(100), // Default RTT
        });
        
        debug!("Assigned Interest {} to stream {}", interest.name.to_string(), stream_id);
        stream_id
    }
    
    /// Get optimal stream for Data
    pub fn get_optimal_stream_for_data(&mut self, data: &Data) -> u64 {
        let name_prefix = self.extract_name_prefix(&data.name);
        
        // Try to use the same stream as the corresponding Interest
        if let Some(&stream_id) = self.stream_assignments.get(&name_prefix) {
            if let Some(load_info) = self.stream_loads.get_mut(&stream_id) {
                load_info.bytes_transferred += data.content.len() as u64;
                load_info.last_activity = Instant::now();
                return stream_id;
            }
        }
        
        // Fallback to least loaded stream
        let stream_id = self.find_least_loaded_stream();
        self.stream_loads.entry(stream_id).or_insert_with(|| StreamLoadInfo {
            active_packets: 0,
            bytes_transferred: data.content.len() as u64,
            last_activity: Instant::now(),
            avg_rtt: Duration::from_millis(100),
        }).bytes_transferred += data.content.len() as u64;
        
        debug!("Assigned Data {} to stream {}", data.name.to_string(), stream_id);
        stream_id
    }
    
    /// Extract name prefix for stream assignment
    fn extract_name_prefix(&self, name: &Name) -> String {
        // Use first component as prefix for stream assignment to group related interests
        // For names with <= 2 components, use first component
        // For names with > 2 components, use first 2 components
        let prefix_len = if name.len() <= 2 { 1 } else { 2 };
        let actual_len = std::cmp::min(prefix_len, name.len());
        name.get_prefix(actual_len).to_string()
    }
    
    /// Find the least loaded stream
    fn find_least_loaded_stream(&mut self) -> u64 {
        if self.stream_loads.is_empty() || self.stream_loads.len() < self.max_streams as usize {
            // Create new stream
            let stream_id = self.next_stream_id;
            self.next_stream_id += 1;
            return stream_id;
        }
        
        // Find least loaded existing stream
        self.stream_loads
            .iter()
            .min_by_key(|(_, load)| load.active_packets + (load.bytes_transferred / 1024) as usize)
            .map(|(&stream_id, _)| stream_id)
            .unwrap_or(1)
    }
    
    /// Update stream RTT measurement
    pub fn update_stream_rtt(&mut self, stream_id: u64, rtt: Duration) {
        if let Some(load_info) = self.stream_loads.get_mut(&stream_id) {
            // Simple exponential weighted moving average
            load_info.avg_rtt = Duration::from_nanos(
                (load_info.avg_rtt.as_nanos() as f64 * 0.875 + rtt.as_nanos() as f64 * 0.125) as u64
            );
        }
    }
    
    /// Mark packet completion on stream
    pub fn mark_packet_complete(&mut self, stream_id: u64) {
        if let Some(load_info) = self.stream_loads.get_mut(&stream_id) {
            if load_info.active_packets > 0 {
                load_info.active_packets -= 1;
            }
        }
    }
    
    /// Get stream optimization statistics
    pub fn get_stats(&self) -> PacketFlowStats {
        let total_active: usize = self.stream_loads.values().map(|l| l.active_packets).sum();
        let total_bytes: u64 = self.stream_loads.values().map(|l| l.bytes_transferred).sum();
        let avg_rtt = if self.stream_loads.is_empty() {
            Duration::from_millis(0)
        } else {
            let total_rtt_ms: u64 = self.stream_loads.values()
                .map(|l| l.avg_rtt.as_millis() as u64).sum();
            Duration::from_millis(total_rtt_ms / self.stream_loads.len() as u64)
        };
        
        PacketFlowStats {
            active_streams: self.stream_loads.len(),
            total_active_packets: total_active,
            total_bytes_transferred: total_bytes,
            average_rtt: avg_rtt,
            stream_assignments: self.stream_assignments.len(),
        }
    }
}

/// Packet flow optimization statistics
#[derive(Debug, Clone)]
pub struct PacketFlowStats {
    pub active_streams: usize,
    pub total_active_packets: usize,
    pub total_bytes_transferred: u64,
    pub average_rtt: Duration,
    pub stream_assignments: usize,
}

/// Comprehensive NDN transport optimizer
pub struct NdnTransportOptimizer {
    /// Interest aggregation engine
    pub interest_aggregator: Arc<RwLock<InterestAggregator>>,
    /// Content store for Data caching
    pub content_store: Arc<RwLock<ContentStore>>,
    /// Packet flow optimizer
    pub flow_optimizer: Arc<RwLock<PacketFlowOptimizer>>,
    /// Optimization configuration
    pub config: NdnOptimizationConfig,
}

/// NDN optimization configuration
#[derive(Debug, Clone)]
pub struct NdnOptimizationConfig {
    /// Enable Interest aggregation
    pub enable_aggregation: bool,
    /// Interest aggregation window
    pub aggregation_window: Duration,
    /// Maximum Interests to aggregate
    pub max_aggregation_count: usize,
    /// Enable content store
    pub enable_content_store: bool,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Maximum Data freshness
    pub max_cache_freshness: Duration,
    /// Enable packet flow optimization
    pub enable_flow_optimization: bool,
    /// Maximum concurrent streams
    pub max_concurrent_streams: u64,
}

impl Default for NdnOptimizationConfig {
    fn default() -> Self {
        Self {
            enable_aggregation: true,
            aggregation_window: Duration::from_millis(10), // 10ms aggregation window
            max_aggregation_count: 10,
            enable_content_store: true,
            max_cache_size: 1000,
            max_cache_freshness: Duration::from_secs(300), // 5 minutes
            enable_flow_optimization: true,
            max_concurrent_streams: 100,
        }
    }
}

impl NdnTransportOptimizer {
    /// Create a new NDN transport optimizer
    pub fn new(config: NdnOptimizationConfig) -> Self {
        let interest_aggregator = Arc::new(RwLock::new(InterestAggregator::new(
            config.aggregation_window,
            config.max_aggregation_count,
        )));
        
        let content_store = Arc::new(RwLock::new(ContentStore::new(
            config.max_cache_size,
            config.max_cache_freshness,
        )));
        
        let flow_optimizer = Arc::new(RwLock::new(PacketFlowOptimizer::new(
            config.max_concurrent_streams,
        )));
        
        Self {
            interest_aggregator,
            content_store,
            flow_optimizer,
            config,
        }
    }
    
    /// Optimize outgoing Interest
    pub async fn optimize_outgoing_interest(
        &self,
        interest: &Interest,
        requester: SocketAddr,
    ) -> Result<OptimizationResult> {
        let mut result = OptimizationResult::Forward;
        
        // Check content store first
        if self.config.enable_content_store {
            let mut cs = self.content_store.write().await;
            if let Some(data) = cs.get(&interest.name.to_string()) {
                debug!("Content store hit for Interest: {}", interest.name.to_string());
                return Ok(OptimizationResult::CacheHit(data));
            }
        }
        
        // Try Interest aggregation
        if self.config.enable_aggregation {
            let mut aggregator = self.interest_aggregator.write().await;
            if aggregator.try_aggregate(interest, requester) {
                debug!("Interest aggregated: {}", interest.name.to_string());
                result = OptimizationResult::Aggregated;
            }
        }
        
        Ok(result)
    }
    
    /// Optimize incoming Data
    pub async fn optimize_incoming_data(&self, data: &Data) -> Result<Vec<SocketAddr>> {
        let mut requesters = Vec::new();
        
        // Store in content store
        if self.config.enable_content_store {
            let mut cs = self.content_store.write().await;
            cs.store(data.clone());
        }
        
        // Handle aggregated Interests
        if self.config.enable_aggregation {
            let mut aggregator = self.interest_aggregator.write().await;
            requesters = aggregator.handle_data(data);
        }
        
        Ok(requesters)
    }
    
    /// Get optimal stream for packet
    pub async fn get_optimal_stream(&self, packet_type: PacketType, name: &Name) -> Result<u64> {
        if !self.config.enable_flow_optimization {
            return Ok(1); // Default stream
        }
        
        let mut optimizer = self.flow_optimizer.write().await;
        
        match packet_type {
            PacketType::Interest => {
                // Create a dummy Interest for stream assignment
                let interest = Interest::new(name.clone());
                Ok(optimizer.get_optimal_stream_for_interest(&interest))
            }
            PacketType::Data => {
                // Create a dummy Data for stream assignment
                let data = Data::new(name.clone(), vec![]);
                Ok(optimizer.get_optimal_stream_for_data(&data))
            }
        }
    }
    
    /// Process ready aggregated Interests
    pub async fn process_aggregated_interests(&self) -> Result<Vec<(Interest, Vec<SocketAddr>)>> {
        if !self.config.enable_aggregation {
            return Ok(vec![]);
        }
        
        let mut aggregator = self.interest_aggregator.write().await;
        Ok(aggregator.get_ready_interests())
    }
    
    /// Perform periodic cleanup
    pub async fn cleanup(&self) -> Result<CleanupStats> {
        let mut stats = CleanupStats::default();
        
        if self.config.enable_aggregation {
            let mut aggregator = self.interest_aggregator.write().await;
            stats.expired_aggregations = aggregator.cleanup_expired();
        }
        
        if self.config.enable_content_store {
            let mut cs = self.content_store.write().await;
            stats.expired_cache_entries = cs.cleanup_expired();
        }
        
        Ok(stats)
    }
    
    /// Get comprehensive optimization statistics
    pub async fn get_optimization_stats(&self) -> Result<NdnOptimizationStats> {
        let aggregation_stats = if self.config.enable_aggregation {
            Some(self.interest_aggregator.read().await.get_stats())
        } else {
            None
        };
        
        let content_store_stats = if self.config.enable_content_store {
            Some(self.content_store.read().await.get_stats())
        } else {
            None
        };
        
        let flow_stats = if self.config.enable_flow_optimization {
            Some(self.flow_optimizer.read().await.get_stats())
        } else {
            None
        };
        
        Ok(NdnOptimizationStats {
            aggregation_stats,
            content_store_stats,
            flow_stats,
            config: self.config.clone(),
        })
    }
}

/// Optimization result for Interest processing
#[derive(Debug, Clone)]
pub enum OptimizationResult {
    /// Forward the Interest normally
    Forward,
    /// Interest was aggregated, don't forward
    Aggregated,
    /// Cache hit, return cached Data
    CacheHit(Data),
}

/// Packet type for optimization
#[derive(Debug, Clone, Copy)]
pub enum PacketType {
    Interest,
    Data,
}

/// Cleanup statistics
#[derive(Debug, Default, Clone)]
pub struct CleanupStats {
    pub expired_aggregations: usize,
    pub expired_cache_entries: usize,
}

/// Comprehensive NDN optimization statistics
#[derive(Debug, Clone)]
pub struct NdnOptimizationStats {
    pub aggregation_stats: Option<InterestAggregationStats>,
    pub content_store_stats: Option<ContentStoreStats>,
    pub flow_stats: Option<PacketFlowStats>,
    pub config: NdnOptimizationConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_interest_aggregator() {
        let mut aggregator = InterestAggregator::new(
            Duration::from_millis(100),
            5
        );
        
        let name = Name::from_str("/test/interest");
        let interest = Interest::new(name);
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        // First Interest should not be aggregated (starts aggregation)
        assert!(!aggregator.try_aggregate(&interest, addr1));
        
        // Second Interest should be aggregated
        assert!(aggregator.try_aggregate(&interest, addr2));
        
        let stats = aggregator.get_stats();
        assert_eq!(stats.active_aggregations, 1);
        assert_eq!(stats.total_aggregated_interests, 2);
    }
    
    #[test]
    fn test_content_store_basic_operations() {
        let mut cs = ContentStore::new(100, Duration::from_secs(300));
        
        let name = Name::from_str("/test/data");
        let mut data = Data::new(name.clone(), b"test content".to_vec());
        
        // Add meta info with freshness period to make it cacheable
        data.meta_info = Some(udcn_core::packets::MetaInfo {
            content_type: udcn_core::ContentType::Blob,
            freshness_period: Some(Duration::from_secs(60)),
            final_block_id: None,
            other_fields: std::collections::HashMap::new(),
        });
        
        // Store data
        assert!(cs.store(data.clone()));
        
        // Retrieve data
        let retrieved = cs.get(&name.to_string());
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, data.content);
        
        let stats = cs.get_stats();
        assert_eq!(stats.cache_entries, 1);
        assert_eq!(stats.total_hits, 1);
    }
    
    #[test]
    fn test_packet_flow_optimizer() {
        let mut optimizer = PacketFlowOptimizer::new(10);
        
        let name1 = Name::from_str("/app1/data1");
        let name2 = Name::from_str("/app1/data2");
        let name3 = Name::from_str("/app2/data1");
        
        let interest1 = Interest::new(name1.clone());
        let interest2 = Interest::new(name2.clone());
        let interest3 = Interest::new(name3.clone());
        
        let stream1 = optimizer.get_optimal_stream_for_interest(&interest1);
        let stream2 = optimizer.get_optimal_stream_for_interest(&interest2);
        let stream3 = optimizer.get_optimal_stream_for_interest(&interest3);
        
        // Same prefix should use same stream
        assert_eq!(stream1, stream2);
        // Different prefix should use different stream
        assert_ne!(stream1, stream3);
        
        let stats = optimizer.get_stats();
        assert_eq!(stats.active_streams, 2);
        assert_eq!(stats.total_active_packets, 3);
    }
}