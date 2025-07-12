use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use log::{info, debug, warn, error};
use tokio::sync::{RwLock, Notify};
use quinn::{Connection, SendStream, RecvStream};
use tokio::time::{sleep, Duration, interval, Instant};

use udcn_core::packets::{Packet, Interest, Data};
use crate::quic::QuicTransport;
use crate::stream_multiplexer::{StreamMultiplexer, StreamMultiplexerConfig, StreamPriority};

/// NDN-over-QUIC frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NdnFrameType {
    /// NDN Interest packet
    Interest = 0x01,
    /// NDN Data packet
    Data = 0x02,
    /// NDN Network NACK
    NetworkNack = 0x03,
    /// NDN Link Protocol (LP) packet
    LinkProtocol = 0x04,
    /// Keep-alive frame
    KeepAlive = 0x05,
}

impl TryFrom<u8> for NdnFrameType {
    type Error = anyhow::Error;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(NdnFrameType::Interest),
            0x02 => Ok(NdnFrameType::Data),
            0x03 => Ok(NdnFrameType::NetworkNack),
            0x04 => Ok(NdnFrameType::LinkProtocol),
            0x05 => Ok(NdnFrameType::KeepAlive),
            _ => Err(anyhow::anyhow!("Invalid NDN frame type: {:#x}", value)),
        }
    }
}

/// NDN-over-QUIC frame header
#[derive(Debug, Clone)]
pub struct NdnFrameHeader {
    /// Frame type
    pub frame_type: NdnFrameType,
    /// Frame length (payload size)
    pub length: u32,
    /// Sequence number for ordering
    pub sequence: u64,
    /// Flags for frame options
    pub flags: u8,
}

/// NDN-over-QUIC frame flags
pub mod frame_flags {
    /// Frame requires acknowledgment
    pub const ACK_REQUIRED: u8 = 0x01;
    /// Frame is fragmented
    pub const FRAGMENTED: u8 = 0x02;
    /// Frame is compressed
    pub const COMPRESSED: u8 = 0x04;
    /// Frame contains priority hints
    pub const PRIORITY: u8 = 0x08;
}

/// Fragment reassembly buffer for tracking partial frames
#[derive(Debug, Clone)]
struct FragmentBuffer {
    /// Expected total number of fragments
    total_fragments: u16,
    /// Received fragments indexed by fragment number
    fragments: HashMap<u16, Vec<u8>>,
    /// When this reassembly was started
    start_time: Instant,
    /// Original frame header (from first fragment)
    original_header: NdnFrameHeader,
}

impl FragmentBuffer {
    fn new(total_fragments: u16, original_header: NdnFrameHeader) -> Self {
        Self {
            total_fragments,
            fragments: HashMap::new(),
            start_time: Instant::now(),
            original_header,
        }
    }
    
    /// Add a fragment to the buffer
    fn add_fragment(&mut self, fragment_index: u16, data: Vec<u8>) {
        self.fragments.insert(fragment_index, data);
    }
    
    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total_fragments as usize
    }
    
    /// Check if this buffer has expired
    fn is_expired(&self, timeout: Duration) -> bool {
        self.start_time.elapsed() > timeout
    }
    
    /// Reassemble all fragments into the original payload
    fn reassemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(anyhow::anyhow!("Cannot reassemble incomplete fragment set"));
        }
        
        let mut reassembled = Vec::new();
        
        // Add fragments in order
        for i in 0..self.total_fragments {
            if let Some(fragment_data) = self.fragments.get(&i) {
                reassembled.extend_from_slice(fragment_data);
            } else {
                return Err(anyhow::anyhow!("Missing fragment {}", i));
            }
        }
        
        Ok(reassembled)
    }
}

impl NdnFrameHeader {
    /// Create a new NDN frame header
    pub fn new(frame_type: NdnFrameType, length: u32, sequence: u64) -> Self {
        Self {
            frame_type,
            length,
            sequence,
            flags: 0,
        }
    }
    
    /// Set frame flags
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }
    
    /// Check if a flag is set
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
    
    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.push(self.frame_type as u8);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.push(self.flags);
        bytes
    }
    
    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 14 {
            return Err(anyhow::anyhow!("NDN frame header too short: {} bytes", bytes.len()));
        }
        
        let frame_type = NdnFrameType::try_from(bytes[0])?;
        let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let sequence = u64::from_be_bytes([
            bytes[5], bytes[6], bytes[7], bytes[8],
            bytes[9], bytes[10], bytes[11], bytes[12]
        ]);
        let flags = bytes[13];
        
        Ok(Self {
            frame_type,
            length,
            sequence,
            flags,
        })
    }
    
    /// Get the size of the header in bytes
    pub const fn size() -> usize {
        14 // 1 + 4 + 8 + 1
    }
    
    /// Get the size of the header in bytes (instance method)
    pub fn header_size(&self) -> usize {
        Self::size()
    }
}

/// NDN-over-QUIC frame
#[derive(Debug, Clone)]
pub struct NdnFrame {
    /// Frame header
    pub header: NdnFrameHeader,
    /// Frame payload
    pub payload: Vec<u8>,
}

impl NdnFrame {
    /// Create a new NDN frame
    pub fn new(frame_type: NdnFrameType, payload: Vec<u8>, sequence: u64) -> Self {
        let header = NdnFrameHeader::new(frame_type, payload.len() as u32, sequence);
        Self { header, payload }
    }
    
    /// Create an NDN frame from a packet
    pub fn from_packet(packet: &Packet, sequence: u64) -> Result<Self> {
        let (frame_type, payload) = match packet {
            Packet::Interest(interest) => {
                let encoded = interest.encode()?;
                (NdnFrameType::Interest, encoded)
            }
            Packet::Data(data) => {
                let encoded = data.encode()?;
                (NdnFrameType::Data, encoded)
            }
        };
        
        Ok(Self::new(frame_type, payload, sequence))
    }
    
    /// Convert frame to packet
    pub fn to_packet(&self) -> Result<Packet> {
        match self.header.frame_type {
            NdnFrameType::Interest => {
                let (interest, _) = Interest::decode(&self.payload)?;
                Ok(Packet::Interest(interest))
            }
            NdnFrameType::Data => {
                let (data, _) = Data::decode(&self.payload)?;
                Ok(Packet::Data(data))
            }
            _ => Err(anyhow::anyhow!("Cannot convert frame type {:?} to packet", self.header.frame_type)),
        }
    }
    
    /// Serialize frame to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.header_size() + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
    
    /// Deserialize frame from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NdnFrameHeader::size() {
            return Err(anyhow::anyhow!("Frame too short for header"));
        }
        
        let header = NdnFrameHeader::from_bytes(&bytes[..NdnFrameHeader::size()])?;
        
        let expected_payload_size = header.length as usize;
        let actual_payload_size = bytes.len() - NdnFrameHeader::size();
        
        if actual_payload_size != expected_payload_size {
            return Err(anyhow::anyhow!(
                "Frame payload size mismatch: expected {}, actual {}",
                expected_payload_size,
                actual_payload_size
            ));
        }
        
        let payload = bytes[NdnFrameHeader::size()..].to_vec();
        
        Ok(Self { header, payload })
    }
}

/// NDN-specific QUIC transport configuration
#[derive(Debug, Clone)]
pub struct NdnQuicConfig {
    /// Maximum Interest lifetime in milliseconds
    pub max_interest_lifetime: u64,
    /// Maximum Data freshness period in milliseconds
    pub max_data_freshness: u64,
    /// Enable Interest aggregation
    pub interest_aggregation: bool,
    /// Enable Data content store
    pub content_store: bool,
    /// Maximum packet size for fragmentation
    pub max_packet_size: usize,
    /// Enable packet compression
    pub compression: bool,
    /// Interest retransmission timeout
    pub interest_timeout: std::time::Duration,
    /// Maximum number of retransmissions
    pub max_retransmissions: u32,
    /// Exponential backoff multiplier for retransmissions
    pub backoff_multiplier: f64,
    /// Maximum backoff duration
    pub max_backoff: std::time::Duration,
    /// Enable adaptive timeout based on RTT
    pub adaptive_timeout: bool,
    /// Timeout cleanup interval
    pub cleanup_interval: std::time::Duration,
    /// RTT-based timeout calculation weight
    pub rtt_timeout_weight: f64,
    /// Enable proactive timeout management
    pub proactive_timeout_management: bool,
    /// Minimum timeout value to prevent too aggressive timeouts
    pub min_timeout: std::time::Duration,
    /// Enable stream multiplexing
    pub enable_stream_multiplexing: bool,
    /// Stream multiplexer configuration
    pub stream_multiplexer_config: StreamMultiplexerConfig,
}

impl Default for NdnQuicConfig {
    fn default() -> Self {
        Self {
            max_interest_lifetime: 4000, // 4 seconds
            max_data_freshness: 3600000, // 1 hour
            interest_aggregation: true,
            content_store: true,
            max_packet_size: 8192, // 8KB
            compression: false,
            interest_timeout: std::time::Duration::from_millis(1000),
            max_retransmissions: 3,
            backoff_multiplier: 2.0,
            max_backoff: std::time::Duration::from_secs(10),
            adaptive_timeout: true,
            cleanup_interval: std::time::Duration::from_millis(500), // 500ms cleanup interval
            rtt_timeout_weight: 0.3, // 30% weight for RTT-based adjustment
            proactive_timeout_management: true,
            min_timeout: std::time::Duration::from_millis(100), // Minimum 100ms timeout
            enable_stream_multiplexing: true,
            stream_multiplexer_config: StreamMultiplexerConfig::default(),
        }
    }
}

/// NDN-over-QUIC transport implementation
#[derive(Clone)]
pub struct NdnQuicTransport {
    /// Underlying QUIC transport
    quic_transport: Arc<QuicTransport>,
    /// NDN-specific configuration
    config: NdnQuicConfig,
    /// Sequence number generator
    next_sequence: Arc<RwLock<u64>>,
    /// Pending Interest table for tracking outgoing Interests
    pending_interests: Arc<RwLock<PendingInterestTable>>,
    /// Timeout management task handle
    timeout_task_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Stream multiplexer for managing concurrent streams
    stream_multiplexer: Option<Arc<StreamMultiplexer>>,
    /// Fragment reassembly buffers indexed by (sequence, frame_type)
    fragment_buffers: Arc<RwLock<HashMap<(u64, NdnFrameType), FragmentBuffer>>>,
    /// Active response listeners per connection
    active_listeners: Arc<RwLock<HashMap<SocketAddr, bool>>>,
}

/// Timeout event types
#[derive(Debug, Clone)]
pub enum TimeoutEvent {
    /// Interest expired without satisfaction
    InterestExpired {
        name: String,
        remote_addr: SocketAddr,
        elapsed: std::time::Duration,
        retransmissions: u32,
    },
    /// Interest retry attempt
    InterestRetry {
        name: String,
        remote_addr: SocketAddr,
        attempt: u32,
        backoff_duration: std::time::Duration,
    },
    /// Connection timeout detected
    ConnectionTimeout {
        remote_addr: SocketAddr,
        idle_duration: std::time::Duration,
    },
}

/// Timeout event callback type
pub type TimeoutEventCallback = Arc<dyn Fn(TimeoutEvent) + Send + Sync>;

/// RTT measurement for adaptive timeouts
#[derive(Debug, Clone)]
pub struct RttMeasurement {
    /// Most recent RTT measurement
    pub rtt: std::time::Duration,
    /// Smoothed RTT (SRTT)
    pub srtt: std::time::Duration,
    /// RTT variance
    pub rttvar: std::time::Duration,
    /// Last update timestamp
    pub last_update: std::time::Instant,
    /// Number of measurements
    pub sample_count: u32,
}

impl Default for RttMeasurement {
    fn default() -> Self {
        Self {
            rtt: std::time::Duration::from_millis(100),
            srtt: std::time::Duration::from_millis(100),
            rttvar: std::time::Duration::from_millis(50),
            last_update: std::time::Instant::now(),
            sample_count: 0,
        }
    }
}

impl RttMeasurement {
    /// Update RTT measurement with new sample
    pub fn update(&mut self, new_rtt: std::time::Duration) {
        self.rtt = new_rtt;
        self.last_update = std::time::Instant::now();
        
        if self.sample_count == 0 {
            // First measurement
            self.srtt = new_rtt;
            self.rttvar = new_rtt / 2;
        } else {
            // RFC 6298 algorithm
            let alpha = 1.0 / 8.0;
            let beta = 1.0 / 4.0;
            
            let rtt_diff = if new_rtt > self.srtt {
                new_rtt - self.srtt
            } else {
                self.srtt - new_rtt
            };
            
            self.rttvar = std::time::Duration::from_nanos(
                ((1.0 - beta) * self.rttvar.as_nanos() as f64 + beta * rtt_diff.as_nanos() as f64) as u64
            );
            
            self.srtt = std::time::Duration::from_nanos(
                ((1.0 - alpha) * self.srtt.as_nanos() as f64 + alpha * new_rtt.as_nanos() as f64) as u64
            );
        }
        
        self.sample_count += 1;
    }
    
    /// Calculate adaptive timeout based on RTT measurements
    pub fn calculate_timeout(&self, base_timeout: std::time::Duration, weight: f64) -> std::time::Duration {
        // RTO = SRTT + max(G, K * RTTVAR) where G is clock granularity and K is 4
        let rto = self.srtt + (self.rttvar * 4).max(std::time::Duration::from_millis(1));
        
        // Blend base timeout with RTT-calculated timeout
        let adaptive_timeout = std::time::Duration::from_nanos(
            ((1.0 - weight) * base_timeout.as_nanos() as f64 + weight * rto.as_nanos() as f64) as u64
        );
        
        adaptive_timeout
    }
}

/// Pending Interest Table entry
#[derive(Debug, Clone)]
pub struct PendingInterestEntry {
    /// Interest name
    pub name: String,
    /// Remote peer address
    pub remote_addr: SocketAddr,
    /// Timestamp when Interest was sent
    pub sent_at: std::time::Instant,
    /// Interest lifetime
    pub lifetime: std::time::Duration,
    /// Number of retransmissions
    pub retransmissions: u32,
    /// Sequence number of the Interest
    pub sequence: u64,
    /// Last retransmission time
    pub last_retry: Option<std::time::Instant>,
    /// Current retry timeout
    pub retry_timeout: std::time::Duration,
    /// Alternative destination addresses to try
    pub alternative_addrs: Vec<SocketAddr>,
    /// Current destination index
    pub current_addr_index: usize,
    /// RTT measurements for this destination
    pub rtt_measurement: RttMeasurement,
    /// Adaptive timeout value
    pub adaptive_timeout: Option<std::time::Duration>,
}

/// Interest transmission result
#[derive(Debug, Clone)]
pub enum TransmissionResult {
    /// Successfully sent to destination
    Success {
        destination: SocketAddr,
        sequence: u64,
        rtt_estimate: Option<Duration>,
    },
    /// Failed after all retries
    Failed {
        last_error: String,
        attempts: u32,
        destinations_tried: Vec<SocketAddr>,
    },
    /// Timed out waiting for response
    Timeout {
        elapsed: Duration,
        attempts: u32,
    },
}

/// Interest transmission configuration
#[derive(Debug, Clone)]
pub struct TransmissionConfig {
    /// Maximum number of destinations to try
    pub max_destinations: usize,
    /// Enable parallel transmission to multiple destinations
    pub parallel_transmission: bool,
    /// Retry delay multiplier
    pub retry_delay_multiplier: f64,
    /// Maximum retry delay
    pub max_retry_delay: Duration,
    /// Connection health threshold for destination selection
    pub health_threshold: f64,
}

/// Pending Interest Table
pub struct PendingInterestTable {
    /// Entries indexed by Interest name
    entries: std::collections::HashMap<String, PendingInterestEntry>,
    /// Timeout event callback
    timeout_callback: Option<TimeoutEventCallback>,
    /// Cleanup task cancellation notify
    cleanup_notify: Arc<Notify>,
}

impl std::fmt::Debug for PendingInterestTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInterestTable")
            .field("entries", &self.entries)
            .field("timeout_callback", &self.timeout_callback.as_ref().map(|_| "Some(callback)"))
            .field("cleanup_notify", &self.cleanup_notify)
            .finish()
    }
}

impl Default for PendingInterestTable {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            timeout_callback: None,
            cleanup_notify: Arc::new(Notify::new()),
        }
    }
}

impl PendingInterestTable {
    /// Create a new PendingInterestTable with timeout callback
    pub fn new(timeout_callback: Option<TimeoutEventCallback>) -> Self {
        Self {
            entries: HashMap::new(),
            timeout_callback,
            cleanup_notify: Arc::new(Notify::new()),
        }
    }
    
    /// Add a pending Interest
    pub fn add_interest(&mut self, entry: PendingInterestEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }
    
    /// Remove a pending Interest
    pub fn remove_interest(&mut self, name: &str) -> Option<PendingInterestEntry> {
        self.entries.remove(name)
    }
    
    /// Get a pending Interest
    pub fn get_interest(&self, name: &str) -> Option<&PendingInterestEntry> {
        self.entries.get(name)
    }
    
    /// Get a mutable reference to a pending Interest
    pub fn get_interest_mut(&mut self, name: &str) -> Option<&mut PendingInterestEntry> {
        self.entries.get_mut(name)
    }
    
    /// Update RTT for a specific Interest
    pub fn update_rtt(&mut self, name: &str, rtt: std::time::Duration) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.rtt_measurement.update(rtt);
        }
    }
    
    /// Get all expired Interests
    pub fn get_expired_interests(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        self.entries
            .iter()
            .filter_map(|(name, entry)| {
                let effective_timeout = entry.adaptive_timeout.unwrap_or(entry.lifetime);
                if now.duration_since(entry.sent_at) > effective_timeout {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Get Interests ready for retry
    pub fn get_retry_interests(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        self.entries
            .iter()
            .filter_map(|(name, entry)| {
                if entry.retransmissions >= 3 {
                    return None; // Max retries reached
                }
                
                let should_retry = if let Some(last_retry) = entry.last_retry {
                    now.duration_since(last_retry) >= entry.retry_timeout
                } else {
                    now.duration_since(entry.sent_at) >= entry.retry_timeout
                };
                
                if should_retry {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Clean up expired Interests with timeout event notification
    pub fn cleanup_expired(&mut self) -> usize {
        let expired_names = self.get_expired_interests();
        let count = expired_names.len();
        
        for name in expired_names {
            if let Some(entry) = self.entries.remove(&name) {
                // Notify timeout event if callback is set
                if let Some(ref callback) = self.timeout_callback {
                    let elapsed = std::time::Instant::now().duration_since(entry.sent_at);
                    let event = TimeoutEvent::InterestExpired {
                        name: entry.name.clone(),
                        remote_addr: entry.remote_addr,
                        elapsed,
                        retransmissions: entry.retransmissions,
                    };
                    callback(event);
                }
            }
        }
        
        count
    }
    
    /// Process retry interests with timeout event notification
    pub fn process_retries(&mut self) -> Vec<PendingInterestEntry> {
        let retry_names = self.get_retry_interests();
        let mut retry_entries = Vec::new();
        
        for name in retry_names {
            if let Some(entry) = self.entries.get_mut(&name) {
                entry.retransmissions += 1;
                entry.last_retry = Some(std::time::Instant::now());
                
                // Update retry timeout with exponential backoff
                entry.retry_timeout = std::time::Duration::from_millis(
                    (entry.retry_timeout.as_millis() as f64 * 2.0) as u64
                );
                
                // Notify retry event if callback is set
                if let Some(ref callback) = self.timeout_callback {
                    let event = TimeoutEvent::InterestRetry {
                        name: entry.name.clone(),
                        remote_addr: entry.remote_addr,
                        attempt: entry.retransmissions,
                        backoff_duration: entry.retry_timeout,
                    };
                    callback(event);
                }
                
                retry_entries.push(entry.clone());
            }
        }
        
        retry_entries
    }
    
    /// Set timeout event callback
    pub fn set_timeout_callback(&mut self, callback: TimeoutEventCallback) {
        self.timeout_callback = Some(callback);
    }
    
    /// Get number of pending Interests
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl NdnQuicTransport {
    /// Create a new NDN-over-QUIC transport
    pub fn new(quic_transport: Arc<QuicTransport>, config: NdnQuicConfig) -> Self {
        // Initialize stream multiplexer if enabled
        let stream_multiplexer = if config.enable_stream_multiplexing {
            Some(Arc::new(StreamMultiplexer::new(config.stream_multiplexer_config.clone())))
        } else {
            None
        };

        let transport = Self {
            quic_transport,
            config: config.clone(),
            next_sequence: Arc::new(RwLock::new(0)),
            pending_interests: Arc::new(RwLock::new(PendingInterestTable::default())),
            timeout_task_handle: Arc::new(RwLock::new(None)),
            stream_multiplexer,
            fragment_buffers: Arc::new(RwLock::new(HashMap::new())),
            active_listeners: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Start proactive timeout management if enabled
        if config.proactive_timeout_management {
            transport.start_timeout_management();
        }
        
        transport
    }
    
    /// Set timeout event callback
    pub async fn set_timeout_callback(&self, callback: TimeoutEventCallback) {
        let mut pit = self.pending_interests.write().await;
        pit.set_timeout_callback(callback);
    }
    
    /// Start proactive timeout management service
    pub fn start_timeout_management(&self) {
        let pending_interests = self.pending_interests.clone();
        let fragment_buffers = self.fragment_buffers.clone();
        let cleanup_interval = self.config.cleanup_interval;
        let _config = self.config.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                // Perform cleanup and retries
                {
                    let mut pit = pending_interests.write().await;
                    
                    // Clean up expired Interests
                    let expired_count = pit.cleanup_expired();
                    if expired_count > 0 {
                        debug!("Cleaned up {} expired Interests", expired_count);
                    }
                    
                    // Process retries
                    let retry_entries = pit.process_retries();
                    if !retry_entries.is_empty() {
                        debug!("Processed {} Interest retries", retry_entries.len());
                    }
                }
                
                // Clean up expired fragment buffers
                {
                    let timeout = Duration::from_secs(30);
                    let mut buffers = fragment_buffers.write().await;
                    let initial_count = buffers.len();
                    
                    buffers.retain(|key, buffer| {
                        let expired = buffer.is_expired(timeout);
                        if expired {
                            warn!("Fragment reassembly expired for sequence {} type {:?}", key.0, key.1);
                        }
                        !expired
                    });
                    
                    let cleaned_count = initial_count - buffers.len();
                    if cleaned_count > 0 {
                        debug!("Cleaned up {} expired fragment buffers", cleaned_count);
                    }
                }
                
                // Check if we should continue running
                {
                    let pit = pending_interests.read().await;
                    if pit.is_empty() {
                        // Wait before checking again when no pending Interests
                        sleep(cleanup_interval * 2).await;
                    }
                }
            }
        });
        
        // Store the task handle
        if let Ok(mut handle) = self.timeout_task_handle.try_write() {
            *handle = Some(task);
        }
    }
    
    /// Stop proactive timeout management service
    pub async fn stop_timeout_management(&self) {
        let mut handle = self.timeout_task_handle.write().await;
        if let Some(task) = handle.take() {
            task.abort();
            debug!("Stopped timeout management service");
        }
    }
    
    /// Calculate adaptive timeout for an Interest
    pub fn calculate_adaptive_timeout(
        &self,
        rtt_measurement: &RttMeasurement,
        base_timeout: std::time::Duration,
    ) -> std::time::Duration {
        if !self.config.adaptive_timeout {
            return base_timeout;
        }
        
        let adaptive_timeout = rtt_measurement.calculate_timeout(base_timeout, self.config.rtt_timeout_weight);
        
        // Ensure timeout is within reasonable bounds
        adaptive_timeout.max(self.config.min_timeout).min(self.config.max_backoff)
    }
    
    /// Get the next sequence number
    async fn next_sequence(&self) -> u64 {
        let mut seq = self.next_sequence.write().await;
        *seq += 1;
        *seq
    }
    
    /// Send an NDN Interest packet (basic version)
    pub async fn send_interest(&self, interest: &Interest, remote_addr: SocketAddr) -> Result<()> {
        let transmission_config = TransmissionConfig {
            max_destinations: 1,
            parallel_transmission: false,
            retry_delay_multiplier: self.config.backoff_multiplier,
            max_retry_delay: self.config.max_backoff,
            health_threshold: 0.7,
        };
        
        let result = self.transmit_interest_with_retry(interest, vec![remote_addr], &transmission_config).await?;
        
        match result {
            TransmissionResult::Success { destination, sequence, .. } => {
                debug!("Successfully sent Interest: {} to {}, seq: {}", interest.name, destination, sequence);
                Ok(())
            }
            TransmissionResult::Failed { last_error, attempts, destinations_tried } => {
                error!("Failed to send Interest: {} after {} attempts to destinations {:?}: {}", 
                       interest.name, attempts, destinations_tried, last_error);
                Err(anyhow::anyhow!("Interest transmission failed: {}", last_error))
            }
            TransmissionResult::Timeout { elapsed, attempts } => {
                error!("Interest transmission timed out: {} after {} attempts in {:?}", 
                       interest.name, attempts, elapsed);
                Err(anyhow::anyhow!("Interest transmission timed out after {:?}", elapsed))
            }
        }
    }

    /// Enhanced Interest transmission with retry logic and multiple destinations
    pub async fn transmit_interest_with_retry(
        &self, 
        interest: &Interest, 
        destinations: Vec<SocketAddr>,
        config: &TransmissionConfig
    ) -> Result<TransmissionResult> {
        if destinations.is_empty() {
            return Ok(TransmissionResult::Failed {
                last_error: "No destinations provided".to_string(),
                attempts: 0,
                destinations_tried: vec![],
            });
        }

        let sequence = self.next_sequence().await;
        let frame = NdnFrame::from_packet(&Packet::Interest(interest.clone()), sequence)?;
        let name = interest.name.to_string();
        
        // Calculate adaptive timeout if enabled
        let base_timeout = interest.interest_lifetime.unwrap_or_else(|| {
            std::time::Duration::from_millis(self.config.max_interest_lifetime)
        });
        
        let rtt_measurement = RttMeasurement::default();
        let adaptive_timeout = if self.config.adaptive_timeout {
            Some(self.calculate_adaptive_timeout(&rtt_measurement, base_timeout))
        } else {
            None
        };
        
        // Create initial PIT entry
        let entry = PendingInterestEntry {
            name: name.clone(),
            remote_addr: destinations[0],
            sent_at: std::time::Instant::now(),
            lifetime: base_timeout,
            retransmissions: 0,
            sequence,
            last_retry: None,
            retry_timeout: self.config.interest_timeout,
            alternative_addrs: destinations.clone(),
            current_addr_index: 0,
            rtt_measurement,
            adaptive_timeout,
        };

        // Add to pending Interest table
        {
            let mut pit = self.pending_interests.write().await;
            pit.add_interest(entry.clone());
        }

        let transmission_start = std::time::Instant::now();
        let mut last_error = String::new();
        let mut destinations_tried = Vec::new();
        let mut total_attempts = 0;

        // Try each destination with retries
        for (dest_index, &destination) in destinations.iter().enumerate() {
            if dest_index >= config.max_destinations {
                break;
            }

            destinations_tried.push(destination);
            
            // Attempt transmission to this destination with retries
            let mut attempts = 0;
            let mut current_timeout = self.config.interest_timeout;
            
            while attempts <= self.config.max_retransmissions {
                total_attempts += 1;
                attempts += 1;
                
                // Check if we've exceeded the Interest lifetime
                if transmission_start.elapsed() > entry.lifetime {
                    return Ok(TransmissionResult::Timeout {
                        elapsed: transmission_start.elapsed(),
                        attempts: total_attempts,
                    });
                }

                // Send the frame
                match self.send_frame(&frame, destination).await {
                    Ok(()) => {
                        // Update PIT entry
                        {
                            let mut pit = self.pending_interests.write().await;
                            if let Some(pit_entry) = pit.entries.get_mut(&name) {
                                pit_entry.retransmissions = attempts - 1;
                                pit_entry.last_retry = Some(std::time::Instant::now());
                                pit_entry.current_addr_index = dest_index;
                                pit_entry.remote_addr = destination;
                            }
                        }

                        debug!("Sent Interest: {} to {} (attempt {}/{})", 
                               name, destination, attempts, self.config.max_retransmissions + 1);

                        // For successful transmission, return success
                        // In a real implementation, you'd wait for Data response here
                        return Ok(TransmissionResult::Success {
                            destination,
                            sequence,
                            rtt_estimate: None, // Would be calculated from response timing
                        });
                    }
                    Err(e) => {
                        last_error = e.to_string();
                        error!("Failed to send Interest: {} to {} (attempt {}): {}", 
                               name, destination, attempts, last_error);
                        
                        // Don't retry if this was the last attempt for this destination
                        if attempts > self.config.max_retransmissions {
                            break;
                        }
                        
                        // Exponential backoff
                        let delay = Duration::from_millis(
                            (current_timeout.as_millis() as f64 * config.retry_delay_multiplier) as u64
                        ).min(config.max_retry_delay);
                        
                        debug!("Retrying Interest: {} to {} in {:?}", name, destination, delay);
                        sleep(delay).await;
                        current_timeout = delay;
                    }
                }
            }
        }

        // Clean up PIT entry on complete failure
        {
            let mut pit = self.pending_interests.write().await;
            pit.remove_interest(&name);
        }

        Ok(TransmissionResult::Failed {
            last_error,
            attempts: total_attempts,
            destinations_tried,
        })
    }

    /// Send Interest with parallel transmission to multiple destinations
    pub async fn send_interest_multicast(
        &self, 
        interest: &Interest, 
        destinations: Vec<SocketAddr>,
        config: &TransmissionConfig
    ) -> Result<TransmissionResult> {
        if !config.parallel_transmission {
            return self.transmit_interest_with_retry(interest, destinations, config).await;
        }

        let sequence = self.next_sequence().await;
        let frame = NdnFrame::from_packet(&Packet::Interest(interest.clone()), sequence)?;
        let name = interest.name.to_string();

        // Create PIT entry
        let entry = PendingInterestEntry {
            name: name.clone(),
            remote_addr: destinations[0],
            sent_at: std::time::Instant::now(),
            lifetime: interest.interest_lifetime.unwrap_or_else(|| {
                std::time::Duration::from_millis(self.config.max_interest_lifetime)
            }),
            retransmissions: 0,
            sequence,
            last_retry: None,
            retry_timeout: self.config.interest_timeout,
            alternative_addrs: destinations.clone(),
            current_addr_index: 0,
            rtt_measurement: RttMeasurement::default(),
            adaptive_timeout: None,
        };

        {
            let mut pit = self.pending_interests.write().await;
            pit.add_interest(entry.clone());
        }

        // Send to all destinations in parallel
        let tasks: Vec<_> = destinations.iter().take(config.max_destinations).map(|&dest| {
            let frame = frame.clone();
            let transport = self.clone();
            
            tokio::spawn(async move {
                transport.send_frame(&frame, dest).await.map(|_| dest)
            })
        }).collect();

        let _transmission_start = std::time::Instant::now();
        let mut destinations_tried = Vec::new();
        let mut last_error = String::new();

        // Wait for first successful transmission
        for task in tasks {
            match task.await {
                Ok(Ok(destination)) => {
                    destinations_tried.push(destination);
                    debug!("Multicast Interest: {} successfully sent to {}", name, destination);
                    
                    return Ok(TransmissionResult::Success {
                        destination,
                        sequence,
                        rtt_estimate: None,
                    });
                }
                Ok(Err(e)) => {
                    last_error = e.to_string();
                }
                Err(e) => {
                    last_error = e.to_string();
                }
            }
        }

        // Clean up PIT entry on complete failure
        {
            let mut pit = self.pending_interests.write().await;
            pit.remove_interest(&name);
        }

        Ok(TransmissionResult::Failed {
            last_error,
            attempts: destinations_tried.len() as u32,
            destinations_tried,
        })
    }
    
    /// Handle incoming Data packet (satisfies pending Interest)
    pub async fn handle_data_reception(&self, data: &Data, _remote_addr: SocketAddr) -> Result<()> {
        let name = data.name.to_string();
        let now = std::time::Instant::now();
        
        // Remove corresponding Interest from PIT and measure RTT
        let mut _rtt_measurement = None;
        {
            let mut pit = self.pending_interests.write().await;
            if let Some(entry) = pit.remove_interest(&name) {
                let rtt = now.duration_since(entry.sent_at);
                _rtt_measurement = Some(rtt);
                
                debug!("Satisfied Interest: {} from {} (RTT: {:?})", 
                       name, entry.remote_addr, rtt);
                
                // Update global RTT statistics if performance monitoring is enabled
                info!("Interest satisfied: {} RTT: {:?} attempts: {}", 
                      name, rtt, entry.retransmissions + 1);
            }
        }
        
        Ok(())
    }
    
    /// Send an NDN Data packet
    pub async fn send_data(&self, data: &Data, remote_addr: SocketAddr) -> Result<()> {
        let sequence = self.next_sequence().await;
        let frame = NdnFrame::from_packet(&Packet::Data(data.clone()), sequence)?;
        
        // Remove corresponding Interest from PIT
        let name = data.name.to_string();
        {
            let mut pit = self.pending_interests.write().await;
            if let Some(entry) = pit.remove_interest(&name) {
                debug!("Satisfied Interest: {} from {}", name, entry.remote_addr);
            }
        }
        
        // Send the frame
        self.send_frame(&frame, remote_addr).await?;
        
        debug!("Sent Data: {} to {}", name, remote_addr);
        Ok(())
    }

    /// Send an NDN Data packet on an existing QUIC connection
    pub async fn send_data_on_connection(&self, data: &Data, connection: &Connection) -> Result<()> {
        let sequence = self.next_sequence().await;
        let frame = NdnFrame::from_packet(&Packet::Data(data.clone()), sequence)?;
        
        // Send frame bytes directly on the existing connection
        let frame_bytes = frame.to_bytes();
        // Create an Arc for the connection to match the expected type
        let connection_arc = Arc::new(connection.clone());
        self.quic_transport.send_to_connection(&connection_arc, &frame_bytes).await?;
        
        debug!("Sent Data response {} via existing QUIC connection", data.name);
        Ok(())
    }

    /// Send an NDN Data packet on a specific bidirectional stream
    pub async fn send_data_on_stream(&self, data: &Data, mut send_stream: quinn::SendStream, sequence: u64) -> Result<()> {
        // Create frame with the original sequence number to match the request
        let frame = NdnFrame::from_packet(&Packet::Data(data.clone()), sequence)?;
        
        // Send frame bytes directly on the bidirectional stream
        let frame_bytes = frame.to_bytes();
        
        // Write the response to the bidirectional stream
        send_stream.write_all(&frame_bytes).await
            .map_err(|e| anyhow::anyhow!("Failed to write to bidirectional stream: {}", e))?;
        
        // Finish the send side to signal completion
        send_stream.finish().await
            .map_err(|e| anyhow::anyhow!("Failed to finish bidirectional stream: {}", e))?;
        
        debug!("Sent Data response {} on bidirectional stream with sequence {}", data.name, sequence);
        Ok(())
    }

    // ==================== STREAM MULTIPLEXING METHODS ====================

    /// Send Interest using stream multiplexing (if enabled)
    pub async fn send_interest_multiplexed(
        &self,
        interest: &Interest,
        remote_addr: SocketAddr,
        priority: Option<StreamPriority>,
    ) -> Result<()> {
        if let Some(ref multiplexer) = self.stream_multiplexer {
            // Get connection
            let connection = self.quic_transport.connect(remote_addr).await?;
            
            // Create frame
            let sequence = self.next_sequence().await;
            let frame = NdnFrame::from_packet(&Packet::Interest(interest.clone()), sequence)?;
            
            // Get stream and send
            let stream_id = multiplexer.get_send_stream(&connection, priority).await?;
            multiplexer.send_on_stream(stream_id, &frame).await?;
            
            // Add to PIT
            let entry = PendingInterestEntry {
                name: interest.name.to_string(),
                remote_addr,
                sent_at: std::time::Instant::now(),
                lifetime: interest.interest_lifetime.unwrap_or_else(|| {
                    std::time::Duration::from_millis(self.config.max_interest_lifetime)
                }),
                retransmissions: 0,
                sequence,
                last_retry: None,
                retry_timeout: self.config.interest_timeout,
                alternative_addrs: vec![remote_addr],
                current_addr_index: 0,
                rtt_measurement: RttMeasurement::default(),
                adaptive_timeout: None,
            };

            {
                let mut pit = self.pending_interests.write().await;
                pit.add_interest(entry);
            }

            // Return stream to pool for reuse
            multiplexer.return_stream(stream_id).await?;
            
            debug!("Sent Interest via multiplexed stream: {} to {}", interest.name, remote_addr);
            Ok(())
        } else {
            // Fall back to non-multiplexed method
            self.send_interest(interest, remote_addr).await
        }
    }

    /// Send Data using stream multiplexing (if enabled)
    pub async fn send_data_multiplexed(
        &self,
        data: &Data,
        remote_addr: SocketAddr,
        priority: Option<StreamPriority>,
    ) -> Result<()> {
        if let Some(ref multiplexer) = self.stream_multiplexer {
            // Get connection
            let connection = self.quic_transport.connect(remote_addr).await?;
            
            // Create frame
            let sequence = self.next_sequence().await;
            let frame = NdnFrame::from_packet(&Packet::Data(data.clone()), sequence)?;
            
            // Get stream and send
            let stream_id = multiplexer.get_send_stream(&connection, priority).await?;
            multiplexer.send_on_stream(stream_id, &frame).await?;
            
            // Remove corresponding Interest from PIT
            let name = data.name.to_string();
            {
                let mut pit = self.pending_interests.write().await;
                if let Some(entry) = pit.remove_interest(&name) {
                    debug!("Satisfied Interest: {} from {}", name, entry.remote_addr);
                }
            }

            // Return stream to pool for reuse
            multiplexer.return_stream(stream_id).await?;
            
            debug!("Sent Data via multiplexed stream: {} to {}", name, remote_addr);
            Ok(())
        } else {
            // Fall back to non-multiplexed method
            self.send_data(data, remote_addr).await
        }
    }

    /// Ensure response listener is running for this connection
    async fn ensure_response_listener(&self, connection: &Connection, multiplexer: Arc<StreamMultiplexer>) -> Result<()> {
        let remote_addr = connection.remote_address();
        
        // Check if we already have a listener for this connection
        {
            let mut listeners = self.active_listeners.write().await;
            if listeners.contains_key(&remote_addr) {
                return Ok(());
            }
            
            // Mark that we're starting a listener for this connection
            listeners.insert(remote_addr, true);
        }
        
        // Start background task to listen for responses on this connection
        let connection_clone = connection.clone();
        let multiplexer_clone = multiplexer.clone();
        let listeners_clone = self.active_listeners.clone();
        
        tokio::spawn(async move {
            debug!("Starting response listener for {}", remote_addr);
            
            // Listen for responses until connection is closed
            loop {
                // Try to receive frames from bidirectional streams
                match tokio::time::timeout(
                    Duration::from_secs(30), 
                    Self::receive_response_frame(&connection_clone)
                ).await {
                    Ok(Ok(response_frame)) => {
                        debug!("Received response frame sequence {} from {}", 
                               response_frame.header.sequence, remote_addr);
                        
                        // Forward response to multiplexer
                        if let Err(e) = multiplexer_clone.handle_incoming_response(&connection_clone, response_frame).await {
                            debug!("Failed to handle response from {}: {}", remote_addr, e);
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("Response receive error from {}: {}", remote_addr, e);
                        break;
                    }
                    Err(_timeout) => {
                        // Continue listening - timeout is normal
                        continue;
                    }
                }
            }
            
            // Remove from active listeners when done
            let mut listeners = listeners_clone.write().await;
            listeners.remove(&remote_addr);
            debug!("Response listener stopped for {}", remote_addr);
        });
        
        Ok(())
    }

    /// Receive a response frame from bidirectional streams 
    /// This accepts NEW bidirectional streams initiated by the remote peer
    async fn receive_response_frame(connection: &Connection) -> Result<NdnFrame> {
        // Wait for the remote peer to initiate a bidirectional stream (for responses)
        let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
        
        // Read the response data with timeout-based reading
        let mut buffer = Vec::new();
        let mut temp_buffer = [0u8; 8192];
        
        loop {
            match tokio::time::timeout(Duration::from_millis(1000), recv_stream.read(&mut temp_buffer)).await {
                Ok(Ok(Some(0))) => break, // Stream closed
                Ok(Ok(Some(n))) => {
                    buffer.extend_from_slice(&temp_buffer[..n]);
                    // Check if we've received what looks like a complete frame
                    if buffer.len() >= 4 {
                        // Read the length from the frame header
                        let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                        if buffer.len() >= length + 4 {
                            // We have a complete frame
                            break;
                        }
                    }
                }
                Ok(Ok(None)) => {
                    // No more data available, but stream not closed
                    if !buffer.is_empty() {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_timeout) => {
                    // Timeout - if we have any data, use it
                    if !buffer.is_empty() {
                        break;
                    }
                    return Err(anyhow::anyhow!("Timeout reading response from bidirectional stream"));
                }
            }
        }
        
        if buffer.is_empty() {
            return Err(anyhow::anyhow!("No data received on response stream"));
        }
        
        // Parse NDN frame
        let frame = NdnFrame::from_bytes(&buffer)?;
        
        // Close the send side since we're only receiving
        let _ = send_stream.finish();
        
        Ok(frame)
    }

    /// Send Interest request and wait for Data response using bidirectional stream multiplexing
    pub async fn send_interest_request_multiplexed(
        &self,
        interest: &Interest,
        remote_addr: SocketAddr,
        timeout: Duration,
        priority: Option<StreamPriority>,
    ) -> Result<Data> {
        if let Some(ref multiplexer) = self.stream_multiplexer {
            // Get connection
            let connection = self.quic_transport.connect(remote_addr).await?;
            
            // Start response listener for this connection if not already started
            self.ensure_response_listener(&connection, multiplexer.clone()).await?;
            
            // Create request frame
            let sequence = self.next_sequence().await;
            let frame = NdnFrame::from_packet(&Packet::Interest(interest.clone()), sequence)?;
            
            // Send request and wait for response
            let response_frame = multiplexer.send_request(&connection, &frame, timeout, priority).await?;
            
            // Convert response frame back to Data packet
            match response_frame.to_packet()? {
                Packet::Data(data) => {
                    debug!("Received Data response via multiplexed stream: {}", data.name);
                    Ok(data)
                }
                _ => Err(anyhow::anyhow!("Expected Data response, got different packet type")),
            }
        } else {
            return Err(anyhow::anyhow!("Stream multiplexing not enabled"));
        }
    }

    /// Send multiple concurrent Interest requests using stream multiplexing
    pub async fn send_concurrent_interests_multiplexed(
        &self,
        interests: Vec<Interest>,
        remote_addr: SocketAddr,
        timeout: Duration,
        priority: Option<StreamPriority>,
    ) -> Result<Vec<Result<Data>>> {
        if let Some(ref multiplexer) = self.stream_multiplexer {
            let connection = self.quic_transport.connect(remote_addr).await?;
            let mut tasks = Vec::new();

            // Launch concurrent requests
            for interest in interests {
                let connection = connection.clone();
                let multiplexer = multiplexer.clone();
                let frame = NdnFrame::from_packet(&Packet::Interest(interest.clone()), 
                                                 self.next_sequence().await)?;
                
                let task = tokio::spawn(async move {
                    let response_frame = multiplexer.send_request(&connection, &frame, timeout, priority).await?;
                    match response_frame.to_packet()? {
                        Packet::Data(data) => Ok(data),
                        _ => Err(anyhow::anyhow!("Expected Data response")),
                    }
                });
                
                tasks.push(task);
            }

            // Collect results
            let mut results = Vec::new();
            for task in tasks {
                match task.await {
                    Ok(result) => results.push(result),
                    Err(e) => results.push(Err(anyhow::anyhow!("Task error: {}", e))),
                }
            }

            debug!("Completed {} concurrent Interest requests", results.len());
            Ok(results)
        } else {
            return Err(anyhow::anyhow!("Stream multiplexing not enabled"));
        }
    }

    /// Get stream multiplexer statistics
    pub async fn get_stream_multiplexer_stats(&self) -> Result<HashMap<String, u64>> {
        if let Some(ref multiplexer) = self.stream_multiplexer {
            Ok(multiplexer.get_stats().await)
        } else {
            Err(anyhow::anyhow!("Stream multiplexing not enabled"))
        }
    }

    /// Close all streams for a specific connection
    pub async fn close_connection_streams(&self, remote_addr: SocketAddr) -> Result<()> {
        if let Some(ref multiplexer) = self.stream_multiplexer {
            multiplexer.cleanup_connection(remote_addr).await
        } else {
            Ok(()) // No-op if multiplexing not enabled
        }
    }

    // ==================== END STREAM MULTIPLEXING METHODS ====================
    
    /// Send an NDN frame over QUIC
    async fn send_frame(&self, frame: &NdnFrame, remote_addr: SocketAddr) -> Result<()> {
        let frame_bytes = frame.to_bytes();
        
        // Check if fragmentation is needed
        if frame_bytes.len() > self.config.max_packet_size {
            return self.send_fragmented_frame(frame, remote_addr).await;
        }
        
        // Send the frame directly
        self.quic_transport.send_to(remote_addr, &frame_bytes).await?;
        
        debug!("Sent NDN frame: type={:?}, size={} bytes, seq={}", 
               frame.header.frame_type, frame_bytes.len(), frame.header.sequence);
        Ok(())
    }
    
    /// Send a fragmented NDN frame
    async fn send_fragmented_frame(&self, frame: &NdnFrame, remote_addr: SocketAddr) -> Result<()> {
        // Chunk only the payload, not the entire frame bytes
        let chunk_size = self.config.max_packet_size - NdnFrameHeader::size() - 4; // Reserve space for fragment info
        
        let chunks: Vec<_> = frame.payload.chunks(chunk_size).collect();
        let total_chunks = chunks.len();
        
        for (i, chunk) in chunks.iter().enumerate() {
            let mut fragment_header = frame.header.clone();
            fragment_header.flags |= frame_flags::FRAGMENTED;
            // Length should only include the actual payload data (chunk + 4 bytes fragment metadata)
            fragment_header.length = (chunk.len() + 4) as u32;
            
            // Create fragment payload with fragment info
            let mut fragment_payload = Vec::with_capacity(chunk.len() + 4);
            fragment_payload.extend_from_slice(&(i as u16).to_be_bytes()); // Fragment index
            fragment_payload.extend_from_slice(&(total_chunks as u16).to_be_bytes()); // Total fragments
            fragment_payload.extend_from_slice(chunk);
            
            let fragment = NdnFrame {
                header: fragment_header,
                payload: fragment_payload,
            };
            
            self.quic_transport.send_to(remote_addr, &fragment.to_bytes()).await?;
        }
        
        info!("Sent fragmented NDN frame: {} fragments, total size={} bytes", 
              total_chunks, frame.payload.len());
        Ok(())
    }
    
    /// Receive an NDN frame from QUIC
    /// Returns the frame and optionally a send stream for bidirectional responses
    pub async fn receive_frame(&self, connection: &Connection) -> Result<(NdnFrame, Option<quinn::SendStream>)> {
        loop {
            let (frame_bytes, send_stream) = self.quic_transport.receive_from(connection).await?;
            let frame = NdnFrame::from_bytes(&frame_bytes)?;
            
            debug!("Received NDN frame: type={:?}, size={} bytes, seq={}", 
                   frame.header.frame_type, frame_bytes.len(), frame.header.sequence);
            
            // Handle fragmented frames
            if frame.header.has_flag(frame_flags::FRAGMENTED) {
                match self.handle_fragmented_frame(frame, connection).await {
                    Ok(reassembled_frame) => {
                        info!("Successfully reassembled fragmented frame for sequence {}", 
                              reassembled_frame.header.sequence);
                        return Ok((reassembled_frame, send_stream));
                    }
                    Err(e) => {
                        // Check if it's an incomplete fragment error (expected)
                        if e.to_string().contains("Fragment reassembly incomplete") {
                            debug!("Waiting for more fragments: {}", e);
                            // Continue the loop to receive more fragments
                            continue;
                        } else {
                            // Other errors should be propagated
                            return Err(e);
                        }
                    }
                }
            } else {
                // Non-fragmented frame, return directly
                return Ok((frame, send_stream));
            }
        }
    }
    
    /// Handle fragmented NDN frames
    async fn handle_fragmented_frame(&self, fragment: NdnFrame, _connection: &Connection) -> Result<NdnFrame> {
        if fragment.payload.len() < 4 {
            return Err(anyhow::anyhow!("Fragment payload too short for metadata"));
        }
        
        // Extract fragment metadata
        let fragment_index = u16::from_be_bytes([fragment.payload[0], fragment.payload[1]]);
        let total_fragments = u16::from_be_bytes([fragment.payload[2], fragment.payload[3]]);
        let fragment_data = fragment.payload[4..].to_vec();
        
        debug!("Received fragment {}/{} for sequence {}", 
               fragment_index + 1, total_fragments, fragment.header.sequence);
        
        let reassembly_key = (fragment.header.sequence, fragment.header.frame_type);
        
        // Get or create fragment buffer
        let mut buffers = self.fragment_buffers.write().await;
        let buffer = buffers.entry(reassembly_key).or_insert_with(|| {
            // Create original header without fragmented flag for reassembled frame
            let mut original_header = fragment.header.clone();
            original_header.flags &= !frame_flags::FRAGMENTED;
            FragmentBuffer::new(total_fragments, original_header)
        });
        
        // Add this fragment
        buffer.add_fragment(fragment_index, fragment_data);
        
        // Check if reassembly is complete
        if buffer.is_complete() {
            debug!("Fragment reassembly complete for sequence {}", fragment.header.sequence);
            
            // Reassemble the original payload
            let reassembled_payload = buffer.reassemble()?;
            
            // Create the reassembled frame
            let mut reassembled_header = buffer.original_header.clone();
            reassembled_header.length = reassembled_payload.len() as u32;
            
            let reassembled_frame = NdnFrame {
                header: reassembled_header,
                payload: reassembled_payload,
            };
            
            // Remove the completed buffer
            buffers.remove(&reassembly_key);
            
            Ok(reassembled_frame)
        } else {
            // More fragments needed - return an error to indicate incomplete
            Err(anyhow::anyhow!("Fragment reassembly incomplete: {}/{} fragments received", 
                                buffer.fragments.len(), total_fragments))
        }
    }
    
    /// Receive an NDN Interest packet
    pub async fn receive_interest(&self, connection: &Connection) -> Result<Interest> {
        let (frame, _send_stream) = self.receive_frame(connection).await?;
        
        match frame.header.frame_type {
            NdnFrameType::Interest => {
                let packet = frame.to_packet()?;
                if let Packet::Interest(interest) = packet {
                    debug!("Received Interest: {}", interest.name.to_string());
                    Ok(interest)
                } else {
                    Err(anyhow::anyhow!("Frame type mismatch: expected Interest"))
                }
            }
            _ => Err(anyhow::anyhow!("Expected Interest frame, got {:?}", frame.header.frame_type)),
        }
    }
    
    /// Receive an NDN Data packet
    pub async fn receive_data(&self, connection: &Connection) -> Result<Data> {
        let (frame, _send_stream) = self.receive_frame(connection).await?;
        
        match frame.header.frame_type {
            NdnFrameType::Data => {
                let packet = frame.to_packet()?;
                if let Packet::Data(data) = packet {
                    debug!("Received Data: {}", data.name.to_string());
                    Ok(data)
                } else {
                    Err(anyhow::anyhow!("Frame type mismatch: expected Data"))
                }
            }
            _ => Err(anyhow::anyhow!("Expected Data frame, got {:?}", frame.header.frame_type)),
        }
    }
    
    /// Send a keep-alive frame
    pub async fn send_keep_alive(&self, remote_addr: SocketAddr) -> Result<()> {
        let sequence = self.next_sequence().await;
        let frame = NdnFrame::new(NdnFrameType::KeepAlive, vec![], sequence);
        
        self.send_frame(&frame, remote_addr).await?;
        debug!("Sent keep-alive to {}", remote_addr);
        Ok(())
    }
    
    /// Clean up expired Interests
    pub async fn cleanup_expired_interests(&self) -> Result<usize> {
        let mut pit = self.pending_interests.write().await;
        let count = pit.cleanup_expired();
        
        if count > 0 {
            debug!("Cleaned up {} expired Interests", count);
        }
        
        Ok(count)
    }
    
    /// Clean up expired fragment reassembly buffers
    pub async fn cleanup_expired_fragments(&self) -> Result<usize> {
        let timeout = Duration::from_secs(30); // 30 second timeout for fragment reassembly
        let mut buffers = self.fragment_buffers.write().await;
        let initial_count = buffers.len();
        
        buffers.retain(|key, buffer| {
            let expired = buffer.is_expired(timeout);
            if expired {
                warn!("Fragment reassembly expired for sequence {} type {:?}", key.0, key.1);
            }
            !expired
        });
        
        let cleaned_count = initial_count - buffers.len();
        if cleaned_count > 0 {
            debug!("Cleaned up {} expired fragment buffers", cleaned_count);
        }
        
        Ok(cleaned_count)
    }
    
    /// Get pending Interest statistics
    pub async fn get_pending_interest_stats(&self) -> Result<HashMap<String, u64>> {
        let pit = self.pending_interests.read().await;
        let mut stats = HashMap::new();
        
        stats.insert("total_pending".to_string(), pit.entries.len() as u64);
        stats.insert("expired_count".to_string(), pit.get_expired_interests().len() as u64);
        
        Ok(stats)
    }
    
    /// Get the underlying QUIC transport
    pub fn quic_transport(&self) -> &Arc<QuicTransport> {
        &self.quic_transport
    }
    
    /// Get the NDN configuration
    pub fn config(&self) -> &NdnQuicConfig {
        &self.config
    }

    /// Get the stream multiplexer (if enabled)
    pub fn stream_multiplexer(&self) -> Option<&Arc<StreamMultiplexer>> {
        self.stream_multiplexer.as_ref()
    }

    /// Retry expired Interests with exponential backoff
    pub async fn retry_expired_interests(&self) -> Result<usize> {
        let mut retried_count = 0;
        let expired_interests = {
            let pit = self.pending_interests.read().await;
            pit.get_expired_interests()
        };

        for interest_name in expired_interests {
            // Get the PIT entry
            let entry = {
                let pit = self.pending_interests.read().await;
                pit.get_interest(&interest_name).cloned()
            };

            if let Some(entry) = entry {
                // Check if we can retry
                if entry.retransmissions < self.config.max_retransmissions {
                    // Calculate backoff delay
                    let backoff_delay = Duration::from_millis(
                        (entry.retry_timeout.as_millis() as f64 * self.config.backoff_multiplier) as u64
                    ).min(self.config.max_backoff);

                    // Check if enough time has passed since last retry
                    if let Some(last_retry) = entry.last_retry {
                        if last_retry.elapsed() < backoff_delay {
                            continue; // Not ready to retry yet
                        }
                    }

                    // Try next destination in the list
                    let next_addr_index = (entry.current_addr_index + 1) % entry.alternative_addrs.len();
                    let next_addr = entry.alternative_addrs[next_addr_index];

                    // Create Interest packet for retry
                    let name = udcn_core::packets::Name::from_str(&entry.name);
                    let interest = Interest::new(name).with_lifetime(entry.lifetime);

                    // Retry transmission
                    match self.send_interest(&interest, next_addr).await {
                        Ok(()) => {
                            // Update PIT entry
                            {
                                let mut pit = self.pending_interests.write().await;
                                if let Some(pit_entry) = pit.entries.get_mut(&interest_name) {
                                    pit_entry.retransmissions += 1;
                                    pit_entry.last_retry = Some(std::time::Instant::now());
                                    pit_entry.retry_timeout = backoff_delay;
                                    pit_entry.current_addr_index = next_addr_index;
                                    pit_entry.remote_addr = next_addr;
                                }
                            }
                            
                            debug!("Retried Interest: {} to {} (attempt {})", 
                                   interest_name, next_addr, entry.retransmissions + 1);
                            retried_count += 1;
                        }
                        Err(e) => {
                            warn!("Failed to retry Interest: {} to {}: {}", 
                                  interest_name, next_addr, e);
                        }
                    }
                } else {
                    // Remove from PIT if max retries exceeded
                    {
                        let mut pit = self.pending_interests.write().await;
                        pit.remove_interest(&interest_name);
                    }
                    
                    warn!("Interest exceeded max retries and was removed: {}", interest_name);
                }
            }
        }

        Ok(retried_count)
    }

    /// Get comprehensive Interest transmission statistics
    pub async fn get_transmission_stats(&self) -> Result<HashMap<String, u64>> {
        let pit = self.pending_interests.read().await;
        let mut stats = HashMap::new();
        
        let mut total_retransmissions = 0;
        let mut active_interests = 0;
        let mut expired_interests = 0;
        
        for entry in pit.entries.values() {
            active_interests += 1;
            total_retransmissions += entry.retransmissions as u64;
            
            if std::time::Instant::now().duration_since(entry.sent_at) > entry.lifetime {
                expired_interests += 1;
            }
        }
        
        stats.insert("active_interests".to_string(), active_interests);
        stats.insert("total_retransmissions".to_string(), total_retransmissions);
        stats.insert("expired_interests".to_string(), expired_interests);
        stats.insert("avg_retransmissions".to_string(), 
                     if active_interests > 0 { total_retransmissions / active_interests } else { 0 });
        
        Ok(stats)
    }
}

/// NDN-over-QUIC stream handler for bidirectional communication
pub struct NdnQuicStreamHandler {
    /// Send stream for outgoing packets
    send_stream: SendStream,
    /// Receive stream for incoming packets
    recv_stream: RecvStream,
    /// Frame sequence number
    sequence: u64,
}

impl NdnQuicStreamHandler {
    /// Create a new stream handler
    pub fn new(send_stream: SendStream, recv_stream: RecvStream) -> Self {
        Self {
            send_stream,
            recv_stream,
            sequence: 0,
        }
    }
    
    /// Send a packet over the stream
    pub async fn send_packet(&mut self, packet: &Packet) -> Result<()> {
        self.sequence += 1;
        let frame = NdnFrame::from_packet(packet, self.sequence)?;
        let frame_bytes = frame.to_bytes();
        
        self.send_stream.write_all(&frame_bytes).await?;
        Ok(())
    }
    
    /// Receive a packet from the stream
    pub async fn receive_packet(&mut self) -> Result<Packet> {
        let mut buffer = vec![0; 8192]; // 8KB buffer
        let bytes_read = self.recv_stream.read(&mut buffer).await?;
        
        if let Some(0) = bytes_read {
            return Err(anyhow::anyhow!("Stream closed"));
        }
        
        if let Some(len) = bytes_read {
            buffer.truncate(len);
        }
        let frame = NdnFrame::from_bytes(&buffer)?;
        frame.to_packet()
    }
}

/// Utility functions for NDN-over-QUIC integration
pub mod utils {
    use super::*;
    
    /// Validate NDN packet before sending over QUIC
    pub fn validate_packet_for_quic(packet: &Packet) -> Result<()> {
        match packet {
            Packet::Interest(interest) => {
                if interest.name.is_empty() {
                    return Err(anyhow::anyhow!("Interest name cannot be empty"));
                }
                
                if let Some(lifetime) = interest.interest_lifetime {
                    if lifetime == std::time::Duration::from_secs(0) {
                        return Err(anyhow::anyhow!("Interest lifetime cannot be zero"));
                    }
                }
                
                Ok(())
            }
            Packet::Data(data) => {
                if data.name.is_empty() {
                    return Err(anyhow::anyhow!("Data name cannot be empty"));
                }
                
                Ok(())
            }
        }
    }
    
    /// Calculate optimal QUIC stream configuration for NDN workloads
    pub fn calculate_optimal_stream_config(
        expected_interests_per_sec: u32,
        average_data_size: usize,
    ) -> (u32, u32) {
        // Calculate concurrent streams based on expected load
        let concurrent_streams = (expected_interests_per_sec / 10).max(10).min(1000);
        
        // Calculate stream bandwidth based on data size
        let stream_bandwidth = (average_data_size * expected_interests_per_sec as usize).max(1024 * 1024);
        
        (concurrent_streams, stream_bandwidth as u32)
    }
    
    /// Create NDN-optimized QUIC configuration
    pub fn create_ndn_optimized_quic_config(
        ndn_config: &NdnQuicConfig,
        expected_load: Option<(u32, usize)>,
    ) -> crate::quic::QuicConfig {
        let (concurrent_streams, stream_bandwidth) = if let Some((interests_per_sec, avg_data_size)) = expected_load {
            calculate_optimal_stream_config(interests_per_sec, avg_data_size)
        } else {
            (100, 1024 * 1024) // Default values
        };
        
        crate::quic::QuicConfig {
            max_idle_timeout: ndn_config.interest_timeout * 3, // 3x Interest timeout
            max_concurrent_streams: concurrent_streams,
            max_stream_bandwidth: stream_bandwidth,
            keep_alive_interval: ndn_config.interest_timeout / 2, // Half of Interest timeout
            tls_config: crate::quic::TlsSecurityConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use udcn_core::packets::Name;
    
    #[test]
    fn test_ndn_frame_header_serialization() {
        let header = NdnFrameHeader::new(NdnFrameType::Interest, 1024, 12345);
        let bytes = header.to_bytes();
        let decoded = NdnFrameHeader::from_bytes(&bytes).unwrap();
        
        assert_eq!(header.frame_type, decoded.frame_type);
        assert_eq!(header.length, decoded.length);
        assert_eq!(header.sequence, decoded.sequence);
        assert_eq!(header.flags, decoded.flags);
    }
    
    #[test]
    fn test_ndn_frame_with_flags() {
        let header = NdnFrameHeader::new(NdnFrameType::Data, 2048, 67890)
            .with_flags(frame_flags::ACK_REQUIRED | frame_flags::COMPRESSED);
        
        assert!(header.has_flag(frame_flags::ACK_REQUIRED));
        assert!(header.has_flag(frame_flags::COMPRESSED));
        assert!(!header.has_flag(frame_flags::FRAGMENTED));
    }
    
    #[test]
    fn test_ndn_frame_serialization() {
        let payload = b"Hello, NDN-over-QUIC!".to_vec();
        let frame = NdnFrame::new(NdnFrameType::Interest, payload.clone(), 123);
        
        let bytes = frame.to_bytes();
        let decoded = NdnFrame::from_bytes(&bytes).unwrap();
        
        assert_eq!(frame.header.frame_type, decoded.header.frame_type);
        assert_eq!(frame.header.length, decoded.header.length);
        assert_eq!(frame.header.sequence, decoded.header.sequence);
        assert_eq!(frame.payload, decoded.payload);
    }
    
    #[test]
    fn test_pending_interest_table() {
        let mut pit = PendingInterestTable::default();
        
        let entry = PendingInterestEntry {
            name: "/test/interest".to_string(),
            remote_addr: "127.0.0.1:8080".parse().unwrap(),
            sent_at: std::time::Instant::now(),
            lifetime: std::time::Duration::from_secs(4),
            retransmissions: 0,
            sequence: 1,
            last_retry: None,
            retry_timeout: std::time::Duration::from_millis(100),
            alternative_addrs: Vec::new(),
            current_addr_index: 0,
            rtt_measurement: RttMeasurement::default(),
            adaptive_timeout: None,
        };
        
        pit.add_interest(entry.clone());
        
        assert!(pit.get_interest("/test/interest").is_some());
        assert_eq!(pit.get_interest("/test/interest").unwrap().name, "/test/interest");
        
        let removed = pit.remove_interest("/test/interest");
        assert!(removed.is_some());
        assert!(pit.get_interest("/test/interest").is_none());
    }
}