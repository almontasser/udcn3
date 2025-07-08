use std::collections::HashMap;
use std::sync::Arc;
use std::net::SocketAddr;
use anyhow::Result;
use log::debug;
use tokio::sync::{RwLock, Mutex, oneshot};
use tokio::time::{Duration, Instant};
use quinn::{Connection, SendStream, RecvStream};

use crate::ndn_quic::NdnFrame;

/// Stream multiplexer configuration
#[derive(Debug, Clone)]
pub struct StreamMultiplexerConfig {
    /// Maximum number of streams per connection
    pub max_streams_per_connection: usize,
    /// Stream idle timeout before cleanup
    pub stream_idle_timeout: Duration,
    /// Enable bidirectional streams for request/response
    pub enable_bidirectional_streams: bool,
    /// Stream pool size for reuse
    pub stream_pool_size: usize,
    /// Maximum pending requests per stream
    pub max_pending_per_stream: usize,
    /// Stream cleanup interval
    pub cleanup_interval: Duration,
    /// Enable stream priority handling
    pub enable_stream_priority: bool,
    /// Default stream priority (lower = higher priority)
    pub default_priority: u8,
}

impl Default for StreamMultiplexerConfig {
    fn default() -> Self {
        Self {
            max_streams_per_connection: 100,
            stream_idle_timeout: Duration::from_secs(30),
            enable_bidirectional_streams: true,
            stream_pool_size: 10,
            max_pending_per_stream: 10,
            cleanup_interval: Duration::from_secs(5),
            enable_stream_priority: true,
            default_priority: 5,
        }
    }
}

/// Stream type for different use cases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Unidirectional stream for one-way communication
    Unidirectional,
    /// Bidirectional stream for request/response patterns
    Bidirectional,
}

/// Stream priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StreamPriority {
    High = 1,
    Medium = 5,
    Low = 9,
}

impl From<u8> for StreamPriority {
    fn from(value: u8) -> Self {
        match value {
            1..=3 => StreamPriority::High,
            4..=6 => StreamPriority::Medium,
            _ => StreamPriority::Low,
        }
    }
}

/// Unique stream identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId {
    /// Connection identifier (remote address)
    pub connection_id: SocketAddr,
    /// QUIC stream ID from Quinn
    pub quic_stream_id: u64,
    /// Stream type
    pub stream_type: StreamType,
}

impl StreamId {
    pub fn new(connection_id: SocketAddr, quic_stream_id: u64, stream_type: StreamType) -> Self {
        Self {
            connection_id,
            quic_stream_id,
            stream_type,
        }
    }
}

/// Stream state for lifecycle management
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is being established
    Connecting,
    /// Stream is active and ready for use
    Active,
    /// Stream is idle but can be reused
    Idle,
    /// Stream is closing
    Closing,
    /// Stream is closed and should be cleaned up
    Closed,
    /// Stream encountered an error
    Error(String),
}

/// Stream entry in the multiplexer
#[derive(Debug)]
pub struct StreamEntry {
    /// Stream identifier
    pub id: StreamId,
    /// Send stream (for unidirectional or bidirectional)
    pub send_stream: Option<SendStream>,
    /// Receive stream (for bidirectional only)
    pub recv_stream: Option<RecvStream>,
    /// Current state
    pub state: StreamState,
    /// Priority level
    pub priority: StreamPriority,
    /// Creation time
    pub created_at: Instant,
    /// Last used time
    pub last_used: Instant,
    /// Number of pending requests on this stream
    pub pending_requests: usize,
    /// Stream statistics
    pub stats: StreamStats,
}

/// Stream usage statistics
#[derive(Debug, Default)]
pub struct StreamStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Number of times reused
    pub reuse_count: u64,
    /// Last error (if any)
    pub last_error: Option<String>,
}

/// Request/response tracking for bidirectional streams
#[derive(Debug)]
pub struct PendingRequest {
    /// Request sequence number
    pub sequence: u64,
    /// Response channel
    pub response_tx: oneshot::Sender<Result<NdnFrame>>,
    /// Request timestamp
    pub timestamp: Instant,
    /// Request timeout
    pub timeout: Duration,
}

/// Stream pool for managing reusable streams
#[derive(Debug)]
pub struct StreamPool {
    /// Available idle streams by priority
    idle_streams: HashMap<StreamPriority, Vec<StreamId>>,
    /// All streams indexed by ID
    streams: HashMap<StreamId, StreamEntry>,
    /// Pending requests for bidirectional streams
    pending_requests: HashMap<u64, PendingRequest>,
    /// Next sequence number for requests
    next_sequence: u64,
    /// Pool configuration
    config: StreamMultiplexerConfig,
}

impl StreamPool {
    pub fn new(config: StreamMultiplexerConfig) -> Self {
        Self {
            idle_streams: HashMap::new(),
            streams: HashMap::new(),
            pending_requests: HashMap::new(),
            next_sequence: 0,
            config,
        }
    }

    /// Get an available stream or create a new one
    pub async fn get_stream(
        &mut self,
        connection: &Connection,
        stream_type: StreamType,
        priority: StreamPriority,
    ) -> Result<StreamId> {
        // Try to reuse an idle stream of the same type and priority
        if let Some(stream_ids) = self.idle_streams.get_mut(&priority) {
            if let Some(stream_id) = stream_ids.pop() {
                if let Some(stream_entry) = self.streams.get_mut(&stream_id) {
                    if stream_entry.id.stream_type == stream_type && stream_entry.state == StreamState::Idle {
                        stream_entry.state = StreamState::Active;
                        stream_entry.last_used = Instant::now();
                        stream_entry.stats.reuse_count += 1;
                        debug!("Reused stream: {:?}", stream_id);
                        return Ok(stream_id);
                    }
                }
            }
        }

        // Check if we've reached the limit
        let active_streams = self.streams.values()
            .filter(|s| s.id.connection_id == connection.remote_address() && 
                       matches!(s.state, StreamState::Active | StreamState::Connecting))
            .count();

        if active_streams >= self.config.max_streams_per_connection {
            return Err(anyhow::anyhow!("Maximum streams per connection reached"));
        }

        // Create a new stream
        self.create_new_stream(connection, stream_type, priority).await
    }

    /// Create a new stream
    async fn create_new_stream(
        &mut self,
        connection: &Connection,
        stream_type: StreamType,
        priority: StreamPriority,
    ) -> Result<StreamId> {
        let remote_addr = connection.remote_address();
        
        let (send_stream, recv_stream, quic_stream_id) = match stream_type {
            StreamType::Unidirectional => {
                let send_stream = connection.open_uni().await?;
                let quic_stream_id = send_stream.id().index();
                (Some(send_stream), None, quic_stream_id)
            }
            StreamType::Bidirectional => {
                let (send_stream, recv_stream) = connection.open_bi().await?;
                let quic_stream_id = send_stream.id().index();
                (Some(send_stream), Some(recv_stream), quic_stream_id)
            }
        };

        let stream_id = StreamId::new(remote_addr, quic_stream_id, stream_type);
        
        let stream_entry = StreamEntry {
            id: stream_id,
            send_stream,
            recv_stream,
            state: StreamState::Active,
            priority,
            created_at: Instant::now(),
            last_used: Instant::now(),
            pending_requests: 0,
            stats: StreamStats::default(),
        };

        self.streams.insert(stream_id, stream_entry);
        
        debug!("Created new stream: {:?} with priority {:?}", stream_id, priority);
        Ok(stream_id)
    }

    /// Return a stream to the idle pool
    pub fn return_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if let Some(stream_entry) = self.streams.get_mut(&stream_id) {
            if stream_entry.pending_requests == 0 {
                stream_entry.state = StreamState::Idle;
                stream_entry.last_used = Instant::now();
                
                // Add to idle pool
                self.idle_streams
                    .entry(stream_entry.priority)
                    .or_insert_with(Vec::new)
                    .push(stream_id);
                
                debug!("Returned stream to idle pool: {:?}", stream_id);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Cannot return stream with pending requests"))
            }
        } else {
            Err(anyhow::anyhow!("Stream not found: {:?}", stream_id))
        }
    }

    /// Remove a stream from the pool
    pub fn remove_stream(&mut self, stream_id: StreamId) -> Result<StreamEntry> {
        // Remove from idle pools
        for (_, stream_ids) in &mut self.idle_streams {
            stream_ids.retain(|&id| id != stream_id);
        }

        // Remove from main pool
        self.streams.remove(&stream_id)
            .ok_or_else(|| anyhow::anyhow!("Stream not found: {:?}", stream_id))
    }

    /// Clean up expired streams
    pub fn cleanup_expired_streams(&mut self) -> usize {
        let now = Instant::now();
        let mut expired_streams = Vec::new();

        for (stream_id, stream_entry) in &self.streams {
            if stream_entry.state == StreamState::Idle && 
               now.duration_since(stream_entry.last_used) > self.config.stream_idle_timeout {
                expired_streams.push(*stream_id);
            }
        }

        let count = expired_streams.len();
        for stream_id in expired_streams {
            if let Ok(mut stream_entry) = self.remove_stream(stream_id) {
                stream_entry.state = StreamState::Closed;
                debug!("Cleaned up expired stream: {:?}", stream_id);
            }
        }

        count
    }

    /// Get stream statistics
    pub fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        
        let total_streams = self.streams.len() as u64;
        let active_streams = self.streams.values()
            .filter(|s| s.state == StreamState::Active)
            .count() as u64;
        let idle_streams = self.streams.values()
            .filter(|s| s.state == StreamState::Idle)
            .count() as u64;
        
        let total_packets_sent: u64 = self.streams.values()
            .map(|s| s.stats.packets_sent)
            .sum();
        let total_packets_received: u64 = self.streams.values()
            .map(|s| s.stats.packets_received)
            .sum();
        let total_reuses: u64 = self.streams.values()
            .map(|s| s.stats.reuse_count)
            .sum();

        stats.insert("total_streams".to_string(), total_streams);
        stats.insert("active_streams".to_string(), active_streams);
        stats.insert("idle_streams".to_string(), idle_streams);
        stats.insert("total_packets_sent".to_string(), total_packets_sent);
        stats.insert("total_packets_received".to_string(), total_packets_received);
        stats.insert("total_reuses".to_string(), total_reuses);
        stats.insert("pending_requests".to_string(), self.pending_requests.len() as u64);

        stats
    }

    /// Get next sequence number for request tracking
    pub fn next_sequence(&mut self) -> u64 {
        self.next_sequence += 1;
        self.next_sequence
    }

    /// Add pending request for bidirectional stream
    pub fn add_pending_request(&mut self, sequence: u64, request: PendingRequest) {
        self.pending_requests.insert(sequence, request);
    }

    /// Remove and get pending request
    pub fn take_pending_request(&mut self, sequence: u64) -> Option<PendingRequest> {
        self.pending_requests.remove(&sequence)
    }

    /// Clean up expired requests
    pub fn cleanup_expired_requests(&mut self) -> usize {
        let now = Instant::now();
        let mut expired_sequences = Vec::new();

        for (sequence, request) in &self.pending_requests {
            if now.duration_since(request.timestamp) > request.timeout {
                expired_sequences.push(*sequence);
            }
        }

        let count = expired_sequences.len();
        for sequence in expired_sequences {
            if let Some(request) = self.pending_requests.remove(&sequence) {
                let _ = request.response_tx.send(Err(anyhow::anyhow!("Request timeout")));
                debug!("Cleaned up expired request: {}", sequence);
            }
        }

        count
    }
}

/// Stream multiplexer for managing multiple concurrent NDN streams
pub struct StreamMultiplexer {
    /// Stream pools per connection
    pools: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<StreamPool>>>>>,
    /// Multiplexer configuration
    config: StreamMultiplexerConfig,
    /// Cleanup task handle
    cleanup_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl StreamMultiplexer {
    /// Create a new stream multiplexer
    pub fn new(config: StreamMultiplexerConfig) -> Self {
        let multiplexer = Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
            cleanup_task: Arc::new(RwLock::new(None)),
        };

        // Start cleanup task
        multiplexer.start_cleanup_task();
        
        multiplexer
    }

    /// Start the cleanup task for expired streams and requests
    fn start_cleanup_task(&self) {
        let pools = self.pools.clone();
        let cleanup_interval = self.config.cleanup_interval;

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                let pool_map = pools.read().await;
                for (addr, pool) in pool_map.iter() {
                    let mut pool = pool.lock().await;
                    let expired_streams = pool.cleanup_expired_streams();
                    let expired_requests = pool.cleanup_expired_requests();
                    
                    if expired_streams > 0 || expired_requests > 0 {
                        debug!("Cleaned up {} streams and {} requests for {}", 
                               expired_streams, expired_requests, addr);
                    }
                }
            }
        });

        if let Ok(mut handle) = self.cleanup_task.try_write() {
            *handle = Some(task);
        }
    }

    /// Stop the cleanup task
    pub async fn stop_cleanup_task(&self) {
        let mut handle = self.cleanup_task.write().await;
        if let Some(task) = handle.take() {
            task.abort();
            debug!("Stopped stream multiplexer cleanup task");
        }
    }

    /// Get or create a stream pool for a connection
    async fn get_pool(&self, addr: SocketAddr) -> Arc<Mutex<StreamPool>> {
        let pools = self.pools.read().await;
        if let Some(pool) = pools.get(&addr) {
            return pool.clone();
        }
        drop(pools);

        // Create new pool
        let mut pools = self.pools.write().await;
        let pool = Arc::new(Mutex::new(StreamPool::new(self.config.clone())));
        pools.insert(addr, pool.clone());
        pool
    }

    /// Get a stream for sending data
    pub async fn get_send_stream(
        &self,
        connection: &Connection,
        priority: Option<StreamPriority>,
    ) -> Result<StreamId> {
        let addr = connection.remote_address();
        let pool = self.get_pool(addr).await;
        let mut pool = pool.lock().await;
        
        let priority = priority.unwrap_or(StreamPriority::from(self.config.default_priority));
        let stream_type = if self.config.enable_bidirectional_streams {
            StreamType::Bidirectional
        } else {
            StreamType::Unidirectional
        };

        pool.get_stream(connection, stream_type, priority).await
    }

    /// Send data on a specific stream
    pub async fn send_on_stream(
        &self,
        stream_id: StreamId,
        frame: &NdnFrame,
    ) -> Result<()> {
        let pool = self.get_pool(stream_id.connection_id).await;
        let mut pool = pool.lock().await;

        if let Some(stream_entry) = pool.streams.get_mut(&stream_id) {
            if let Some(ref mut send_stream) = stream_entry.send_stream {
                let frame_bytes = frame.to_bytes();
                send_stream.write_all(&frame_bytes).await?;
                
                // Update statistics
                stream_entry.stats.packets_sent += 1;
                stream_entry.stats.bytes_sent += frame_bytes.len() as u64;
                stream_entry.last_used = Instant::now();

                debug!("Sent frame on stream {:?}: {} bytes", stream_id, frame_bytes.len());
                Ok(())
            } else {
                Err(anyhow::anyhow!("Stream has no send capability: {:?}", stream_id))
            }
        } else {
            Err(anyhow::anyhow!("Stream not found: {:?}", stream_id))
        }
    }

    /// Send a request and wait for response (bidirectional streams only)
    pub async fn send_request(
        &self,
        connection: &Connection,
        request_frame: &NdnFrame,
        timeout: Duration,
        priority: Option<StreamPriority>,
    ) -> Result<NdnFrame> {
        if !self.config.enable_bidirectional_streams {
            return Err(anyhow::anyhow!("Bidirectional streams not enabled"));
        }

        let stream_id = self.get_send_stream(connection, priority).await?;
        let addr = connection.remote_address();
        let pool = self.get_pool(addr).await;
        
        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();
        
        // Add to pending requests
        let sequence = {
            let mut pool = pool.lock().await;
            let sequence = pool.next_sequence();
            
            let pending_request = PendingRequest {
                sequence,
                response_tx,
                timestamp: Instant::now(),
                timeout,
            };
            
            pool.add_pending_request(sequence, pending_request);
            
            // Update pending count
            if let Some(stream_entry) = pool.streams.get_mut(&stream_id) {
                stream_entry.pending_requests += 1;
            }
            
            sequence
        };

        // Send request with sequence number in header
        let mut request_frame = request_frame.clone();
        request_frame.header.sequence = sequence;
        
        self.send_on_stream(stream_id, &request_frame).await?;

        // Wait for response
        match tokio::time::timeout(timeout, response_rx).await {
            Ok(Ok(response)) => {
                // Decrement pending count
                let mut pool = pool.lock().await;
                if let Some(stream_entry) = pool.streams.get_mut(&stream_id) {
                    stream_entry.pending_requests = stream_entry.pending_requests.saturating_sub(1);
                }
                response
            }
            Ok(Err(_)) => Err(anyhow::anyhow!("Response channel closed")),
            Err(_) => {
                // Remove from pending requests on timeout
                let mut pool = pool.lock().await;
                pool.take_pending_request(sequence);
                if let Some(stream_entry) = pool.streams.get_mut(&stream_id) {
                    stream_entry.pending_requests = stream_entry.pending_requests.saturating_sub(1);
                }
                Err(anyhow::anyhow!("Request timeout"))
            }
        }
    }

    /// Return a stream to the pool for reuse
    pub async fn return_stream(&self, stream_id: StreamId) -> Result<()> {
        let pool = self.get_pool(stream_id.connection_id).await;
        let mut pool = pool.lock().await;
        pool.return_stream(stream_id)
    }

    /// Close a specific stream
    pub async fn close_stream(&self, stream_id: StreamId) -> Result<()> {
        let pool = self.get_pool(stream_id.connection_id).await;
        let mut pool = pool.lock().await;
        
        if let Ok(mut stream_entry) = pool.remove_stream(stream_id) {
            stream_entry.state = StreamState::Closing;
            
            // Close Quinn streams
            if let Some(mut send_stream) = stream_entry.send_stream {
                let _ = send_stream.finish().await;
            }
            
            debug!("Closed stream: {:?}", stream_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Stream not found: {:?}", stream_id))
        }
    }

    /// Get multiplexer statistics
    pub async fn get_stats(&self) -> HashMap<String, u64> {
        let mut global_stats = HashMap::new();
        let pools = self.pools.read().await;
        
        let mut total_connections = 0u64;
        let mut total_streams = 0u64;
        let mut total_active_streams = 0u64;
        let mut total_idle_streams = 0u64;
        let mut total_packets_sent = 0u64;
        let mut total_packets_received = 0u64;
        let mut total_reuses = 0u64;
        let mut total_pending_requests = 0u64;

        for pool in pools.values() {
            let pool = pool.lock().await;
            let stats = pool.get_stats();
            
            total_connections += 1;
            total_streams += stats.get("total_streams").unwrap_or(&0);
            total_active_streams += stats.get("active_streams").unwrap_or(&0);
            total_idle_streams += stats.get("idle_streams").unwrap_or(&0);
            total_packets_sent += stats.get("total_packets_sent").unwrap_or(&0);
            total_packets_received += stats.get("total_packets_received").unwrap_or(&0);
            total_reuses += stats.get("total_reuses").unwrap_or(&0);
            total_pending_requests += stats.get("pending_requests").unwrap_or(&0);
        }

        global_stats.insert("total_connections".to_string(), total_connections);
        global_stats.insert("total_streams".to_string(), total_streams);
        global_stats.insert("total_active_streams".to_string(), total_active_streams);
        global_stats.insert("total_idle_streams".to_string(), total_idle_streams);
        global_stats.insert("total_packets_sent".to_string(), total_packets_sent);
        global_stats.insert("total_packets_received".to_string(), total_packets_received);
        global_stats.insert("total_reuses".to_string(), total_reuses);
        global_stats.insert("total_pending_requests".to_string(), total_pending_requests);

        global_stats
    }

    /// Clean up all pools for a specific connection
    pub async fn cleanup_connection(&self, addr: SocketAddr) -> Result<()> {
        let mut pools = self.pools.write().await;
        if let Some(pool) = pools.remove(&addr) {
            let mut pool = pool.lock().await;
            
            // Close all streams in the pool
            let stream_ids: Vec<StreamId> = pool.streams.keys().cloned().collect();
            for stream_id in stream_ids {
                if let Ok(mut stream_entry) = pool.remove_stream(stream_id) {
                    stream_entry.state = StreamState::Closed;
                    
                    // Close Quinn streams
                    if let Some(mut send_stream) = stream_entry.send_stream {
                        let _ = send_stream.finish().await;
                    }
                }
            }
            
            debug!("Cleaned up all streams for connection: {}", addr);
        }
        
        Ok(())
    }
}

impl Drop for StreamMultiplexer {
    fn drop(&mut self) {
        // Cleanup task will be aborted automatically when the handle is dropped
        debug!("Stream multiplexer dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_stream_id_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let stream_id = StreamId::new(addr, 12345, StreamType::Bidirectional);
        
        assert_eq!(stream_id.connection_id, addr);
        assert_eq!(stream_id.quic_stream_id, 12345);
        assert_eq!(stream_id.stream_type, StreamType::Bidirectional);
    }

    #[test]
    fn test_stream_priority_conversion() {
        assert_eq!(StreamPriority::from(1), StreamPriority::High);
        assert_eq!(StreamPriority::from(3), StreamPriority::High);
        assert_eq!(StreamPriority::from(5), StreamPriority::Medium);
        assert_eq!(StreamPriority::from(9), StreamPriority::Low);
    }

    #[test]
    fn test_stream_pool_creation() {
        let config = StreamMultiplexerConfig::default();
        let pool = StreamPool::new(config);
        
        assert_eq!(pool.streams.len(), 0);
        assert_eq!(pool.pending_requests.len(), 0);
        assert_eq!(pool.next_sequence, 0);
    }

    #[test]
    fn test_stream_pool_sequence_generation() {
        let config = StreamMultiplexerConfig::default();
        let mut pool = StreamPool::new(config);
        
        assert_eq!(pool.next_sequence(), 1);
        assert_eq!(pool.next_sequence(), 2);
        assert_eq!(pool.next_sequence(), 3);
    }

    #[tokio::test]
    async fn test_multiplexer_creation() {
        let config = StreamMultiplexerConfig::default();
        let multiplexer = StreamMultiplexer::new(config);
        
        let stats = multiplexer.get_stats().await;
        assert_eq!(stats.get("total_connections"), Some(&0));
        assert_eq!(stats.get("total_streams"), Some(&0));
        
        multiplexer.stop_cleanup_task().await;
    }
}