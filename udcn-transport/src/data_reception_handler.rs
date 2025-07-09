use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use udcn_core::packets::Data;
use crate::file_chunking::{ChunkInfo, FileChunk};
use crate::file_reassembly::FileReassemblyEngine;
use crate::ndn_quic::NdnQuicTransport;

/// Configuration for data reception handling
#[derive(Debug, Clone)]
pub struct DataReceptionConfig {
    /// Maximum number of packets to buffer
    pub max_buffer_size: usize,
    /// Timeout for packet processing
    pub processing_timeout: Duration,
    /// Maximum chunk size expected
    pub max_chunk_size: usize,
    /// Enable duplicate detection
    pub enable_duplicate_detection: bool,
    /// Size of duplicate detection cache
    pub duplicate_cache_size: usize,
    /// Maximum time to keep packets in buffer
    pub buffer_retention_time: Duration,
    /// Number of worker threads for processing
    pub worker_threads: usize,
}

impl Default for DataReceptionConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 1000,
            processing_timeout: Duration::from_secs(5),
            max_chunk_size: 8192, // 8KB chunks
            enable_duplicate_detection: true,
            duplicate_cache_size: 500,
            buffer_retention_time: Duration::from_secs(30),
            worker_threads: 4,
        }
    }
}

/// Status of received data packet
#[derive(Debug, Clone, PartialEq)]
pub enum DataPacketStatus {
    /// Packet received and validated
    Valid,
    /// Packet failed validation
    Invalid(String),
    /// Packet is duplicate
    Duplicate,
    /// Packet processing timed out
    TimedOut,
    /// Packet buffer overflow
    BufferOverflow,
}

/// Buffered data packet with metadata
#[derive(Debug, Clone)]
pub struct BufferedDataPacket {
    /// The data packet
    pub packet: Data,
    /// Chunk information extracted from packet
    pub chunk_info: ChunkInfo,
    /// Timestamp when packet was received
    pub received_at: Instant,
    /// Processing status
    pub status: DataPacketStatus,
    /// Number of processing attempts
    pub processing_attempts: usize,
}

impl BufferedDataPacket {
    /// Create a new buffered data packet
    pub fn new(packet: Data, chunk_info: ChunkInfo) -> Self {
        Self {
            packet,
            chunk_info,
            received_at: Instant::now(),
            status: DataPacketStatus::Valid,
            processing_attempts: 0,
        }
    }

    /// Check if packet has expired based on retention time
    pub fn is_expired(&self, retention_time: Duration) -> bool {
        self.received_at.elapsed() > retention_time
    }

    /// Mark packet as invalid with reason
    pub fn mark_invalid(&mut self, reason: String) {
        self.status = DataPacketStatus::Invalid(reason);
    }

    /// Increment processing attempts
    pub fn increment_attempts(&mut self) {
        self.processing_attempts += 1;
    }
}

/// Statistics for data reception
#[derive(Debug, Clone, Default)]
pub struct DataReceptionStats {
    /// Total packets received
    pub total_received: usize,
    /// Valid packets processed
    pub valid_packets: usize,
    /// Invalid packets rejected
    pub invalid_packets: usize,
    /// Duplicate packets detected
    pub duplicate_packets: usize,
    /// Packets timed out during processing
    pub timed_out_packets: usize,
    /// Buffer overflow events
    pub buffer_overflows: usize,
    /// Average processing time per packet
    pub avg_processing_time: Duration,
    /// Current buffer size
    pub current_buffer_size: usize,
    /// Total bytes processed
    pub total_bytes_processed: u64,
}

/// Data Reception Handler for NDN file transfers
pub struct DataReceptionHandler {
    /// Configuration
    config: DataReceptionConfig,
    /// Transport layer
    transport: Arc<NdnQuicTransport>,
    /// Buffered data packets awaiting processing
    packet_buffer: Arc<RwLock<HashMap<String, BufferedDataPacket>>>,
    /// Duplicate detection cache (packet name -> received timestamp)
    duplicate_cache: Arc<RwLock<HashMap<String, Instant>>>,
    /// Statistics
    stats: Arc<RwLock<DataReceptionStats>>,
    /// Channel for processed packets
    processed_packet_sender: mpsc::UnboundedSender<FileChunk>,
    /// Receiver for processed packets (for consumers)
    processed_packet_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<FileChunk>>>>,
    /// Optional file reassembly engine for automatic reassembly
    reassembly_engine: Option<Arc<FileReassemblyEngine>>,
}

impl DataReceptionHandler {
    /// Create a new DataReceptionHandler
    pub fn new(config: DataReceptionConfig, transport: Arc<NdnQuicTransport>) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            transport,
            packet_buffer: Arc::new(RwLock::new(HashMap::new())),
            duplicate_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DataReceptionStats::default())),
            processed_packet_sender: sender,
            processed_packet_receiver: Arc::new(RwLock::new(Some(receiver))),
            reassembly_engine: None,
        }
    }

    /// Set the file reassembly engine for automatic reassembly
    pub fn with_reassembly_engine(mut self, engine: Arc<FileReassemblyEngine>) -> Self {
        self.reassembly_engine = Some(engine);
        self
    }

    /// Set the file reassembly engine for automatic reassembly (by reference)
    pub fn set_reassembly_engine(&mut self, engine: Arc<FileReassemblyEngine>) {
        self.reassembly_engine = Some(engine);
    }

    /// Start the data reception handler
    pub async fn start(&self) -> Result<()> {
        info!("Starting data reception handler");
        
        // Start cleanup task for expired packets
        self.start_cleanup_task().await;
        
        // Start duplicate cache cleanup
        self.start_duplicate_cache_cleanup().await;
        
        Ok(())
    }

    /// Receive and process a data packet
    pub async fn receive_data_packet(&self, packet: Data) -> Result<DataPacketStatus> {
        let start_time = Instant::now();
        
        // Update total received count
        {
            let mut stats = self.stats.write().await;
            stats.total_received += 1;
        }

        // Validate packet first
        let validation_result = self.validate_packet(&packet).await?;
        if validation_result != DataPacketStatus::Valid {
            return Ok(validation_result);
        }

        // Check for duplicates
        if self.config.enable_duplicate_detection {
            if let Some(duplicate_status) = self.check_duplicate(&packet).await? {
                return Ok(duplicate_status);
            }
        }

        // Extract chunk information from packet
        let chunk_info = self.extract_chunk_info(&packet).await?;
        
        // Create buffered packet
        let buffered_packet = BufferedDataPacket::new(packet, chunk_info);
        
        // Add to buffer
        let packet_key = self.generate_packet_key(&buffered_packet.packet);
        let buffer_result = self.add_to_buffer(packet_key.clone(), buffered_packet).await?;
        
        if buffer_result != DataPacketStatus::Valid {
            return Ok(buffer_result);
        }

        // Process the packet
        self.process_buffered_packet(&packet_key).await?;
        
        // Update processing time statistics
        let processing_time = start_time.elapsed();
        self.update_processing_stats(processing_time).await;
        
        Ok(DataPacketStatus::Valid)
    }

    /// Validate incoming data packet
    async fn validate_packet(&self, packet: &Data) -> Result<DataPacketStatus> {
        // Check packet size
        if packet.content.len() > self.config.max_chunk_size {
            warn!("Packet size {} exceeds maximum {}", packet.content.len(), self.config.max_chunk_size);
            return Ok(DataPacketStatus::Invalid("Packet size exceeds maximum".to_string()));
        }

        // Validate packet structure (basic checks)
        if packet.content.is_empty() {
            return Ok(DataPacketStatus::Invalid("Empty packet content".to_string()));
        }

        // Additional validation can be added here
        debug!("Packet validation passed for {}", packet.name);
        Ok(DataPacketStatus::Valid)
    }

    /// Check if packet is a duplicate
    async fn check_duplicate(&self, packet: &Data) -> Result<Option<DataPacketStatus>> {
        let packet_key = self.generate_packet_key(packet);
        let mut cache = self.duplicate_cache.write().await;
        
        if cache.contains_key(&packet_key) {
            warn!("Duplicate packet detected: {}", packet_key);
            let mut stats = self.stats.write().await;
            stats.duplicate_packets += 1;
            return Ok(Some(DataPacketStatus::Duplicate));
        }

        // Add to duplicate cache
        cache.insert(packet_key, Instant::now());
        
        // Cleanup old entries if cache is too large
        if cache.len() > self.config.duplicate_cache_size {
            let threshold = Instant::now() - self.config.buffer_retention_time;
            cache.retain(|_, &mut timestamp| timestamp > threshold);
        }

        Ok(None)
    }

    /// Extract chunk information from data packet
    async fn extract_chunk_info(&self, packet: &Data) -> Result<ChunkInfo> {
        // Parse chunk number from packet name
        // Expected format: /file/path/chunk/<chunk_number>
        let name_components = packet.name.to_string();
        let parts: Vec<&str> = name_components.split('/').collect();
        
        if parts.len() < 3 || parts[parts.len()-2] != "chunk" {
            return Err(anyhow!("Invalid chunk name format: {}", name_components));
        }

        let chunk_number: usize = parts[parts.len()-1]
            .parse()
            .map_err(|_| anyhow!("Invalid chunk number in name: {}", name_components))?;

        Ok(ChunkInfo {
            sequence: chunk_number,
            offset: (chunk_number * self.config.max_chunk_size) as u64,
            size: packet.content.len(),
            is_final: false, // Will be determined by higher-level logic
            file_metadata: None,
            chunk_hash: None,
            hash_algorithm: None,
        })
    }

    /// Add packet to buffer
    async fn add_to_buffer(&self, key: String, packet: BufferedDataPacket) -> Result<DataPacketStatus> {
        let mut buffer = self.packet_buffer.write().await;
        
        // Check buffer size
        if buffer.len() >= self.config.max_buffer_size {
            warn!("Buffer overflow, dropping packet: {}", key);
            let mut stats = self.stats.write().await;
            stats.buffer_overflows += 1;
            return Ok(DataPacketStatus::BufferOverflow);
        }

        buffer.insert(key, packet);
        
        // Update buffer size stat
        {
            let mut stats = self.stats.write().await;
            stats.current_buffer_size = buffer.len();
        }

        Ok(DataPacketStatus::Valid)
    }

    /// Process a buffered packet
    async fn process_buffered_packet(&self, packet_key: &str) -> Result<()> {
        let buffered_packet = {
            let buffer = self.packet_buffer.read().await;
            buffer.get(packet_key).cloned()
        };

        if let Some(packet) = buffered_packet {
            debug!("Processing packet: {}", packet_key);
            
            // Convert to FileChunk for downstream processing
            let file_chunk = FileChunk {
                name: packet.packet.name.clone(),
                data: packet.packet.clone(),
                chunk_info: packet.chunk_info.clone(),
            };

            // Send to processing pipeline
            if let Err(e) = self.processed_packet_sender.send(file_chunk.clone()) {
                error!("Failed to send processed chunk: {}", e);
            }

            // Forward to reassembly engine if available
            if let Some(reassembly_engine) = &self.reassembly_engine {
                let chunk_sender = reassembly_engine.get_chunk_sender();
                if let Err(e) = chunk_sender.send(file_chunk) {
                    error!("Failed to send chunk to reassembly engine: {}", e);
                }
            }

            // Remove from buffer
            {
                let mut buffer = self.packet_buffer.write().await;
                buffer.remove(packet_key);
            }

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.valid_packets += 1;
                stats.total_bytes_processed += packet.packet.content.len() as u64;
                stats.current_buffer_size = self.packet_buffer.read().await.len();
            }
        }

        Ok(())
    }

    /// Generate unique key for packet
    fn generate_packet_key(&self, packet: &Data) -> String {
        format!("{}#{}", packet.name, packet.content.len())
    }

    /// Start cleanup task for expired packets
    async fn start_cleanup_task(&self) {
        let buffer = self.packet_buffer.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                
                let expired_count = {
                    let mut buffer_guard = buffer.write().await;
                    let initial_size = buffer_guard.len();
                    
                    buffer_guard.retain(|_, packet| {
                        !packet.is_expired(config.buffer_retention_time)
                    });
                    
                    initial_size - buffer_guard.len()
                };
                
                if expired_count > 0 {
                    debug!("Cleaned up {} expired packets", expired_count);
                    let mut stats_guard = stats.write().await;
                    stats_guard.current_buffer_size = buffer.read().await.len();
                }
            }
        });
    }

    /// Start duplicate cache cleanup task
    async fn start_duplicate_cache_cleanup(&self) {
        let cache = self.duplicate_cache.clone();
        let retention_time = self.config.buffer_retention_time;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                let threshold = Instant::now() - retention_time;
                let mut cache_guard = cache.write().await;
                let initial_size = cache_guard.len();
                
                cache_guard.retain(|_, &mut timestamp| timestamp > threshold);
                
                let cleaned = initial_size - cache_guard.len();
                if cleaned > 0 {
                    debug!("Cleaned up {} old duplicate cache entries", cleaned);
                }
            }
        });
    }

    /// Update processing time statistics
    async fn update_processing_stats(&self, processing_time: Duration) {
        let mut stats = self.stats.write().await;
        
        // Simple moving average for processing time
        if stats.valid_packets == 0 {
            stats.avg_processing_time = processing_time;
        } else {
            let total_time = stats.avg_processing_time * stats.valid_packets as u32;
            let new_total = total_time + processing_time;
            stats.avg_processing_time = new_total / (stats.valid_packets + 1) as u32;
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> DataReceptionStats {
        self.stats.read().await.clone()
    }

    /// Get processed packet receiver (for consumers)
    pub async fn get_packet_receiver(&self) -> Option<mpsc::UnboundedReceiver<FileChunk>> {
        self.processed_packet_receiver.write().await.take()
    }

    /// Clear all buffers and reset state
    pub async fn reset(&self) -> Result<()> {
        info!("Resetting data reception handler");
        
        {
            let mut buffer = self.packet_buffer.write().await;
            buffer.clear();
        }
        
        {
            let mut cache = self.duplicate_cache.write().await;
            cache.clear();
        }
        
        {
            let mut stats = self.stats.write().await;
            *stats = DataReceptionStats::default();
        }
        
        Ok(())
    }
}

impl Clone for DataReceptionHandler {
    fn clone(&self) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        
        Self {
            config: self.config.clone(),
            transport: self.transport.clone(),
            packet_buffer: self.packet_buffer.clone(),
            duplicate_cache: self.duplicate_cache.clone(),
            stats: self.stats.clone(),
            processed_packet_sender: sender,
            processed_packet_receiver: Arc::new(RwLock::new(Some(receiver))),
            reassembly_engine: self.reassembly_engine.clone(),
        }
    }
}

// Tests will be added in integration tests to avoid mock setup complexity