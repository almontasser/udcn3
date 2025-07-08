use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use log::{info, debug, warn, error};
use tokio::sync::RwLock;
use quinn::{Connection, SendStream, RecvStream};
use tokio::time::{sleep, Duration};

use udcn_core::packets::{Packet, Interest, Data};
use crate::quic::QuicTransport;

/// NDN-over-QUIC frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Default)]
pub struct PendingInterestTable {
    /// Entries indexed by Interest name
    entries: std::collections::HashMap<String, PendingInterestEntry>,
}

impl PendingInterestTable {
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
    
    /// Get all expired Interests
    pub fn get_expired_interests(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        self.entries
            .iter()
            .filter_map(|(name, entry)| {
                if now.duration_since(entry.sent_at) > entry.lifetime {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Clean up expired Interests
    pub fn cleanup_expired(&mut self) -> usize {
        let expired_names = self.get_expired_interests();
        let count = expired_names.len();
        
        for name in expired_names {
            self.entries.remove(&name);
        }
        
        count
    }
}

impl NdnQuicTransport {
    /// Create a new NDN-over-QUIC transport
    pub fn new(quic_transport: Arc<QuicTransport>, config: NdnQuicConfig) -> Self {
        Self {
            quic_transport,
            config,
            next_sequence: Arc::new(RwLock::new(0)),
            pending_interests: Arc::new(RwLock::new(PendingInterestTable::default())),
        }
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
        
        // Create initial PIT entry
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
        let frame_bytes = frame.to_bytes();
        let chunk_size = self.config.max_packet_size - NdnFrameHeader::size() - 4; // Reserve space for fragment info
        
        let chunks: Vec<_> = frame_bytes.chunks(chunk_size).collect();
        let total_chunks = chunks.len();
        
        for (i, chunk) in chunks.iter().enumerate() {
            let mut fragment_header = frame.header.clone();
            fragment_header.flags |= frame_flags::FRAGMENTED;
            fragment_header.length = chunk.len() as u32;
            
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
              total_chunks, frame_bytes.len());
        Ok(())
    }
    
    /// Receive an NDN frame from QUIC
    pub async fn receive_frame(&self, connection: &Connection) -> Result<NdnFrame> {
        let frame_bytes = self.quic_transport.receive_from(connection).await?;
        let frame = NdnFrame::from_bytes(&frame_bytes)?;
        
        debug!("Received NDN frame: type={:?}, size={} bytes, seq={}", 
               frame.header.frame_type, frame_bytes.len(), frame.header.sequence);
        
        // Handle fragmented frames
        if frame.header.has_flag(frame_flags::FRAGMENTED) {
            return self.handle_fragmented_frame(frame, connection).await;
        }
        
        Ok(frame)
    }
    
    /// Handle fragmented NDN frames
    async fn handle_fragmented_frame(&self, fragment: NdnFrame, _connection: &Connection) -> Result<NdnFrame> {
        // This is a simplified implementation
        // A production implementation would need to handle fragment reassembly
        warn!("Received fragmented frame - reassembly not yet implemented");
        Ok(fragment)
    }
    
    /// Receive an NDN Interest packet
    pub async fn receive_interest(&self, connection: &Connection) -> Result<Interest> {
        let frame = self.receive_frame(connection).await?;
        
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
        let frame = self.receive_frame(connection).await?;
        
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
        };
        
        pit.add_interest(entry.clone());
        
        assert!(pit.get_interest("/test/interest").is_some());
        assert_eq!(pit.get_interest("/test/interest").unwrap().name, "/test/interest");
        
        let removed = pit.remove_interest("/test/interest");
        assert!(removed.is_some());
        assert!(pit.get_interest("/test/interest").is_none());
    }
}