use std::collections::HashMap;
use crate::progress_tracker::{ProgressTracker, TransferSessionId};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use udcn_core::packets::{Data, Interest, Name, MetaInfo, ContentType, SignatureInfo, KeyLocator};
use crate::file_chunking::{FileChunk, FileMetadata, ChunkingError};
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};

/// Configuration for data packet publication
#[derive(Debug, Clone)]
pub struct PublisherConfig {
    /// Default freshness period for published data packets
    pub default_freshness_period: Option<Duration>,
    /// Whether to include digital signatures
    pub enable_signatures: bool,
    /// Signature type to use (if enabled)
    pub signature_type: u8,
    /// Key locator for signatures
    pub key_locator: Option<KeyLocator>,
    /// Maximum number of cached packets
    pub max_cache_size: usize,
    /// Default content type for published packets
    pub default_content_type: ContentType,
    /// Whether to include chunk metadata in first segment
    pub include_chunk_metadata: bool,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            default_freshness_period: Some(Duration::from_secs(3600)), // 1 hour
            enable_signatures: false, // Disabled by default for testing
            signature_type: 1, // SHA256withRSA
            key_locator: None,
            max_cache_size: 1000,
            default_content_type: ContentType::Blob,
            include_chunk_metadata: true,
        }
    }
}

impl PublisherConfig {
    /// Create config optimized for file transfer
    pub fn for_file_transfer() -> Self {
        Self {
            default_freshness_period: Some(Duration::from_secs(7200)), // 2 hours
            enable_signatures: false,
            signature_type: 1,
            key_locator: None,
            max_cache_size: 2000,
            default_content_type: ContentType::Blob,
            include_chunk_metadata: true,
        }
    }

    /// Create config for real-time streaming
    pub fn for_streaming() -> Self {
        Self {
            default_freshness_period: Some(Duration::from_secs(30)), // 30 seconds
            enable_signatures: false,
            signature_type: 1,
            key_locator: None,
            max_cache_size: 500,
            default_content_type: ContentType::Blob,
            include_chunk_metadata: false, // Skip metadata for streaming
        }
    }

    /// Enable digital signatures with the given key locator
    pub fn with_signatures(mut self, key_locator: KeyLocator, signature_type: u8) -> Self {
        self.enable_signatures = true;
        self.key_locator = Some(key_locator);
        self.signature_type = signature_type;
        self
    }
}

/// Statistics for published data packets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishStats {
    /// Total number of packets published
    pub packets_published: u64,
    /// Total bytes published
    pub bytes_published: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Number of Interest packets processed
    pub interests_processed: u64,
    /// Number of failed publications
    pub publication_failures: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Last publication timestamp
    pub last_publication_time: Option<u64>,
}

impl Default for PublishStats {
    fn default() -> Self {
        Self {
            packets_published: 0,
            bytes_published: 0,
            cache_hits: 0,
            cache_misses: 0,
            interests_processed: 0,
            publication_failures: 0,
            avg_packet_size: 0.0,
            last_publication_time: None,
        }
    }
}

impl PublishStats {
    /// Update statistics after successful publication
    pub fn record_publication(&mut self, packet_size: usize) {
        self.packets_published += 1;
        self.bytes_published += packet_size as u64;
        
        // Update average packet size
        self.avg_packet_size = self.bytes_published as f64 / self.packets_published as f64;
        
        // Update timestamp
        self.last_publication_time = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
    }

    /// Record a publication failure
    pub fn record_failure(&mut self) {
        self.publication_failures += 1;
    }

    /// Record cache hit/miss
    pub fn record_cache_result(&mut self, hit: bool) {
        if hit {
            self.cache_hits += 1;
        } else {
            self.cache_misses += 1;
        }
    }

    /// Record Interest processing
    pub fn record_interest(&mut self) {
        self.interests_processed += 1;
    }

    /// Calculate cache hit ratio
    pub fn cache_hit_ratio(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

/// Published packet information for caching
#[derive(Debug, Clone)]
pub struct PublishedPacket {
    /// The actual Data packet
    pub data: Data,
    /// Encoded packet bytes for quick serving
    pub encoded: Vec<u8>,
    /// Publication timestamp
    pub published_at: SystemTime,
    /// Number of times this packet has been served
    pub serve_count: u64,
}

impl PublishedPacket {
    pub fn new(data: Data) -> Result<Self, PublishingError> {
        let encoded = data.encode().map_err(|e| PublishingError::EncodingError(e.to_string()))?;
        
        Ok(Self {
            data,
            encoded,
            published_at: SystemTime::now(),
            serve_count: 0,
        })
    }

    /// Check if the packet is still fresh
    pub fn is_fresh(&self) -> bool {
        if let Some(meta_info) = &self.data.meta_info {
            if let Some(freshness_period) = meta_info.freshness_period {
                if let Ok(elapsed) = self.published_at.elapsed() {
                    return elapsed < freshness_period;
                }
            }
        }
        true // Consider fresh if no freshness period specified
    }

    /// Record that this packet was served
    pub fn record_serve(&mut self) {
        self.serve_count += 1;
    }
}

/// Errors that can occur during data packet publication
#[derive(Debug, thiserror::Error)]
pub enum PublishingError {
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Chunking error: {0}")]
    ChunkingError(#[from] ChunkingError),
    #[error("No data available for name: {0}")]
    NoDataAvailable(String),
    #[error("Interest does not match available data: {0}")]
    InterestMismatch(String),
    #[error("Progress tracking error: {0}")]
    TrackingError(String),
}

/// Main data packet publisher for NDN file chunks
pub struct DataPacketPublisher {
    config: PublisherConfig,
    packet_cache: Arc<RwLock<HashMap<String, PublishedPacket>>>,
    stats: Arc<Mutex<PublishStats>>,
    signature_value: Option<Vec<u8>>, // For demo purposes - real implementation would use crypto
    progress_tracker: Option<Arc<crate::progress_tracker::ProgressTracker>>,
}

impl DataPacketPublisher {
    /// Create a new data packet publisher
    pub fn new(config: PublisherConfig) -> Self {
        Self {
            config,
            packet_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Mutex::new(PublishStats::default())),
            signature_value: None,
            progress_tracker: None,
        }
    }

    /// Create publisher with default configuration
    pub fn default() -> Self {
        Self::new(PublisherConfig::default())
    }

    /// Set signature value for signed packets (demo implementation)
    pub fn with_signature_value(mut self, signature: Vec<u8>) -> Self {
        self.signature_value = Some(signature);
        self
    }

    /// Set progress tracker for monitoring file transfers
    pub fn with_progress_tracker(mut self, tracker: Arc<ProgressTracker>) -> Self {
        self.progress_tracker = Some(tracker);
        self
    }

    /// Publish a file chunk as an NDN Data packet
    pub async fn publish_chunk(&self, chunk: FileChunk) -> Result<PublishedPacket, PublishingError> {
        let mut data = chunk.data.clone();

        // Apply publisher configuration to the Data packet
        self.apply_publisher_config(&mut data, &chunk)?;

        // Add signature if enabled
        if self.config.enable_signatures {
            self.add_signature(&mut data)?;
        }

        // Create published packet
        let published_packet = PublishedPacket::new(data)?;

        // Cache the packet
        self.cache_packet(&chunk.name.to_string(), published_packet.clone()).await?;

        // Update statistics
        self.update_stats_publication(published_packet.encoded.len()).await;

        info!(
            "Published chunk {}: {} bytes",
            chunk.name.to_string(),
            published_packet.encoded.len()
        );

        Ok(published_packet)
    }

    /// Publish multiple file chunks
    pub async fn publish_chunks<I>(&self, chunks: I) -> Result<Vec<PublishedPacket>, PublishingError>
    where
        I: IntoIterator<Item = FileChunk>,
    {
        let mut published_packets = Vec::new();

        for chunk in chunks {
            match self.publish_chunk(chunk).await {
                Ok(packet) => published_packets.push(packet),
                Err(e) => {
                    error!("Failed to publish chunk: {}", e);
                    self.update_stats_failure().await;
                    return Err(e);
                }
            }
        }

        info!("Published {} chunks successfully", published_packets.len());
        Ok(published_packets)
    }

    /// Handle an Interest packet and return matching Data packet if available
    pub async fn handle_interest(&self, interest: &Interest) -> Result<Option<PublishedPacket>, PublishingError> {
        // Update Interest statistics
        self.update_stats_interest().await;

        let interest_name = interest.name.to_string();
        debug!("Handling Interest for: {}", interest_name);

        // Look up packet in cache
        if let Some(mut packet) = self.lookup_cached_packet(&interest_name).await? {
            // Check if packet is still fresh
            if packet.is_fresh() {
                packet.record_serve();
                self.update_cache_with_packet(&interest_name, packet.clone()).await?;
                self.update_stats_cache_hit().await;
                
                debug!("Serving cached packet for: {}", interest_name);
                return Ok(Some(packet));
            } else {
                // Remove stale packet from cache
                self.remove_from_cache(&interest_name).await?;
                debug!("Removed stale packet from cache: {}", interest_name);
            }
        }

        self.update_stats_cache_miss().await;
        debug!("No fresh data available for Interest: {}", interest_name);
        Ok(None)
    }

    /// Get current publication statistics
    pub async fn get_stats(&self) -> PublishStats {
        self.stats.lock().await.clone()
    }

    /// Clear the packet cache
    pub async fn clear_cache(&self) -> Result<(), PublishingError> {
        let mut cache = self.packet_cache.write()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire write lock: {}", e)))?;
        
        let cache_size = cache.len();
        cache.clear();
        
        info!("Cleared {} packets from cache", cache_size);
        Ok(())
    }

    /// Get cache status information
    pub async fn get_cache_info(&self) -> Result<(usize, usize), PublishingError> {
        let cache = self.packet_cache.read()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire read lock: {}", e)))?;
        
        Ok((cache.len(), self.config.max_cache_size))
    }

    /// List all cached packet names
    pub async fn list_cached_packets(&self) -> Result<Vec<String>, PublishingError> {
        let cache = self.packet_cache.read()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire read lock: {}", e)))?;
        
        Ok(cache.keys().cloned().collect())
    }

    /// Publish a complete file with progress tracking
    pub async fn publish_file_with_progress(
        &self,
        chunks: Vec<FileChunk>,
        session_id: TransferSessionId,
        file_name: String,
        file_size: u64,
    ) -> Result<Vec<PublishedPacket>, PublishingError> {
        let total_chunks = chunks.len() as u32;
        
        // Start progress tracking if available
        if let Some(tracker) = &self.progress_tracker {
            tracker.start_transfer(session_id.clone(), file_name.clone(), file_size, total_chunks)
                .map_err(|e| PublishingError::TrackingError(e))?;
            
            tracker.update_state(&session_id, crate::progress_tracker::TransferState::Active)
                .map_err(|e| PublishingError::TrackingError(e))?;
        }

        let mut published_packets = Vec::new();
        let mut chunk_id = 0u32;

        for chunk in chunks {
            let chunk_size = chunk.data.content.len() as u64;
            
            match self.publish_chunk(chunk).await {
                Ok(packet) => {
                    published_packets.push(packet);
                    
                    // Update progress tracking
                    if let Some(tracker) = &self.progress_tracker {
                        tracker.update_chunk_sent(&session_id, chunk_id, chunk_size)
                            .map_err(|e| PublishingError::TrackingError(e))?;
                    }
                    
                    chunk_id += 1;
                }
                Err(e) => {
                    error!("Failed to publish chunk {}: {}", chunk_id, e);
                    
                    // Update progress tracking with failure
                    if let Some(tracker) = &self.progress_tracker {
                        tracker.update_chunk_failed(&session_id, chunk_id, e.to_string())
                            .map_err(|e| PublishingError::TrackingError(e))?;
                        
                        tracker.fail_transfer(&session_id, format!("Chunk {} failed: {}", chunk_id, e))
                            .map_err(|e| PublishingError::TrackingError(e))?;
                    }
                    
                    self.update_stats_failure().await;
                    return Err(e);
                }
            }
        }

        // Complete progress tracking
        if let Some(tracker) = &self.progress_tracker {
            tracker.complete_transfer(&session_id)
                .map_err(|e| PublishingError::TrackingError(e))?;
        }

        info!("Published {} chunks successfully for file: {}", published_packets.len(), file_name);
        Ok(published_packets)
    }

    /// Get progress information for a transfer session
    pub fn get_transfer_progress(&self, session_id: &TransferSessionId) -> Option<crate::progress_tracker::FileTransferProgress> {
        self.progress_tracker.as_ref()?.get_progress(session_id)
    }

    /// Get current progress metrics
    pub fn get_progress_metrics(&self) -> Option<crate::progress_tracker::ProgressMetrics> {
        self.progress_tracker.as_ref().map(|tracker| tracker.get_metrics())
    }

    /// Subscribe to progress events
    pub fn subscribe_progress_events(&self) -> Option<tokio::sync::broadcast::Receiver<crate::progress_tracker::ProgressEvent>> {
        self.progress_tracker.as_ref().map(|tracker| tracker.subscribe_events())
    }

    /// Get the publisher configuration
    pub fn get_config(&self) -> &PublisherConfig {
        &self.config
    }

    // Private helper methods

    /// Apply publisher configuration to a Data packet
    fn apply_publisher_config(&self, data: &mut Data, chunk: &FileChunk) -> Result<(), PublishingError> {
        // Ensure MetaInfo exists
        if data.meta_info.is_none() {
            data.meta_info = Some(MetaInfo::default());
        }

        let meta_info = data.meta_info.as_mut().unwrap();

        // Set content type
        meta_info.content_type = self.config.default_content_type;

        // Set freshness period
        if let Some(freshness) = self.config.default_freshness_period {
            meta_info.freshness_period = Some(freshness);
        }

        // Set final block ID for the last chunk
        if chunk.chunk_info.is_final {
            meta_info.final_block_id = Some(chunk.chunk_info.sequence.to_string().into_bytes());
        }

        // Include file metadata in the first chunk if configured
        if self.config.include_chunk_metadata && chunk.chunk_info.sequence == 0 {
            if let Some(file_metadata) = &chunk.chunk_info.file_metadata {
                match file_metadata.encode() {
                    Ok(metadata_bytes) => {
                        // Store metadata in other_fields with a custom type
                        meta_info.other_fields.insert(0xF0, metadata_bytes); // Custom type for file metadata
                    }
                    Err(e) => {
                        warn!("Failed to encode file metadata: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add digital signature to a Data packet
    fn add_signature(&self, data: &mut Data) -> Result<(), PublishingError> {
        if !self.config.enable_signatures {
            return Ok(());
        }

        let mut sig_info = SignatureInfo::new(self.config.signature_type);
        
        if let Some(key_locator) = &self.config.key_locator {
            sig_info = sig_info.with_key_locator(key_locator.clone());
        }

        data.signature_info = Some(sig_info);

        // In a real implementation, this would compute an actual signature
        // For demo purposes, we use a placeholder or the configured signature
        data.signature_value = self.signature_value.clone()
            .or_else(|| Some(b"demo_signature".to_vec()));

        Ok(())
    }

    /// Cache a published packet
    async fn cache_packet(&self, name: &str, packet: PublishedPacket) -> Result<(), PublishingError> {
        let mut cache = self.packet_cache.write()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire write lock: {}", e)))?;

        // Implement cache eviction if necessary
        if cache.len() >= self.config.max_cache_size {
            // Simple eviction: remove one random entry
            if let Some(key_to_remove) = cache.keys().next().cloned() {
                cache.remove(&key_to_remove);
                debug!("Evicted packet from cache: {}", key_to_remove);
            }
        }

        cache.insert(name.to_string(), packet);
        debug!("Cached packet: {}", name);
        Ok(())
    }

    /// Look up a packet in the cache
    async fn lookup_cached_packet(&self, name: &str) -> Result<Option<PublishedPacket>, PublishingError> {
        let cache = self.packet_cache.read()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire read lock: {}", e)))?;

        Ok(cache.get(name).cloned())
    }

    /// Update a packet in the cache
    async fn update_cache_with_packet(&self, name: &str, packet: PublishedPacket) -> Result<(), PublishingError> {
        let mut cache = self.packet_cache.write()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire write lock: {}", e)))?;

        cache.insert(name.to_string(), packet);
        Ok(())
    }

    /// Remove a packet from the cache
    async fn remove_from_cache(&self, name: &str) -> Result<(), PublishingError> {
        let mut cache = self.packet_cache.write()
            .map_err(|e| PublishingError::CacheError(format!("Failed to acquire write lock: {}", e)))?;

        cache.remove(name);
        Ok(())
    }

    // Statistics update methods

    async fn update_stats_publication(&self, packet_size: usize) {
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.record_publication(packet_size);
        }
    }

    async fn update_stats_failure(&self) {
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.record_failure();
        }
    }

    async fn update_stats_interest(&self) {
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.record_interest();
        }
    }

    async fn update_stats_cache_hit(&self) {
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.record_cache_result(true);
        }
    }

    async fn update_stats_cache_miss(&self) {
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.record_cache_result(false);
        }
    }
}

/// Utility functions for data packet publishing
pub mod utils {
    use super::*;

    /// Create a basic Data packet from raw content
    pub fn create_data_packet(
        name: Name,
        content: Vec<u8>,
        config: &PublisherConfig,
    ) -> Result<Data, PublishingError> {
        let mut data = Data::new(name, content);

        // Apply basic configuration
        let mut meta_info = MetaInfo::default();
        meta_info.content_type = config.default_content_type;
        
        if let Some(freshness) = config.default_freshness_period {
            meta_info.freshness_period = Some(freshness);
        }

        data.meta_info = Some(meta_info);

        Ok(data)
    }

    /// Extract file metadata from a Data packet's MetaInfo
    pub fn extract_file_metadata(data: &Data) -> Option<FileMetadata> {
        if let Some(meta_info) = &data.meta_info {
            if let Some(metadata_bytes) = meta_info.other_fields.get(&0xF0) {
                return FileMetadata::decode(metadata_bytes).ok();
            }
        }
        None
    }

    /// Check if a Data packet represents a final chunk
    pub fn is_final_chunk(data: &Data) -> bool {
        if let Some(meta_info) = &data.meta_info {
            meta_info.final_block_id.is_some()
        } else {
            false
        }
    }

    /// Extract chunk sequence number from packet name
    pub fn extract_sequence_number(name: &Name) -> Option<usize> {
        // Assuming naming convention: /path/to/file/segment/N
        if name.len() >= 2 {
            if let Some(segment_component) = name.get(name.len() - 2) {
                if segment_component == b"segment" {
                    if let Some(seq_component) = name.get(name.len() - 1) {
                        if let Ok(seq_str) = String::from_utf8(seq_component.clone()) {
                            return seq_str.parse().ok();
                        }
                    }
                }
            }
        }
        None
    }

    /// Validate that a Data packet follows expected chunking conventions
    pub fn validate_chunk_packet(data: &Data) -> Result<(), PublishingError> {
        // Check that name follows segment naming convention
        if extract_sequence_number(&data.name).is_none() {
            return Err(PublishingError::InvalidPacket(
                "Packet name does not follow chunk naming convention".to_string()
            ));
        }

        // Check that content is not empty (unless it's an intentional empty chunk)
        if data.content.is_empty() && !is_final_chunk(data) {
            return Err(PublishingError::InvalidPacket(
                "Non-final chunk has empty content".to_string()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_chunking::{FileChunker, ChunkingConfig, ChunkInfo};
    use std::io::Write;
    use tempfile::NamedTempFile;
    use std::time::Duration;

    fn create_test_file(size: usize) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let data = (0..size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        file
    }

    fn create_test_chunk(sequence: usize, is_final: bool) -> FileChunk {
        let base_name = Name::from_str("/test/file");
        let chunk_data = vec![42u8; 100]; // 100 bytes of test data
        
        let chunk_info = ChunkInfo {
            sequence,
            size: chunk_data.len(),
            offset: (sequence * 100) as u64,
            is_final,
            file_metadata: None,
        };

        FileChunk::new(&base_name, sequence, chunk_data, chunk_info)
    }

    #[tokio::test]
    async fn test_publisher_creation() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        let stats = publisher.get_stats().await;
        assert_eq!(stats.packets_published, 0);
        assert_eq!(stats.bytes_published, 0);
    }

    #[tokio::test]
    async fn test_publish_single_chunk() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        let chunk = create_test_chunk(0, false);
        let result = publisher.publish_chunk(chunk).await;
        
        assert!(result.is_ok());
        let published_packet = result.unwrap();
        assert!(!published_packet.encoded.is_empty());
        
        let stats = publisher.get_stats().await;
        assert_eq!(stats.packets_published, 1);
        assert!(stats.bytes_published > 0);
    }

    #[tokio::test]
    async fn test_publish_multiple_chunks() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        let chunks = vec![
            create_test_chunk(0, false),
            create_test_chunk(1, false),
            create_test_chunk(2, true), // Final chunk
        ];
        
        let result = publisher.publish_chunks(chunks).await;
        assert!(result.is_ok());
        
        let published_packets = result.unwrap();
        assert_eq!(published_packets.len(), 3);
        
        let stats = publisher.get_stats().await;
        assert_eq!(stats.packets_published, 3);
    }

    #[tokio::test]
    async fn test_handle_interest() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        // Publish a chunk first
        let chunk = create_test_chunk(0, false);
        let chunk_name = chunk.name.clone();
        publisher.publish_chunk(chunk).await.unwrap();
        
        // Create Interest for the published chunk
        let interest = Interest::new(chunk_name);
        
        // Handle the Interest
        let result = publisher.handle_interest(&interest).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(response.is_some());
        
        let stats = publisher.get_stats().await;
        assert_eq!(stats.interests_processed, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 0);
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        // Publish multiple chunks
        let chunks = vec![
            create_test_chunk(0, false),
            create_test_chunk(1, true),
        ];
        
        publisher.publish_chunks(chunks).await.unwrap();
        
        // Check cache info
        let (cache_size, max_size) = publisher.get_cache_info().await.unwrap();
        assert_eq!(cache_size, 2);
        assert!(max_size > 0);
        
        // List cached packets
        let cached_names = publisher.list_cached_packets().await.unwrap();
        assert_eq!(cached_names.len(), 2);
        
        // Clear cache
        publisher.clear_cache().await.unwrap();
        
        let (cache_size_after, _) = publisher.get_cache_info().await.unwrap();
        assert_eq!(cache_size_after, 0);
    }

    #[tokio::test]
    async fn test_signature_support() {
        let key_locator = KeyLocator::Name(Name::from_str("/test/key"));
        let config = PublisherConfig::default()
            .with_signatures(key_locator, 1);
        
        let publisher = DataPacketPublisher::new(config)
            .with_signature_value(b"test_signature".to_vec());
        
        let chunk = create_test_chunk(0, false);
        let result = publisher.publish_chunk(chunk).await;
        
        assert!(result.is_ok());
        let published_packet = result.unwrap();
        
        // Check that signature was added
        assert!(published_packet.data.signature_info.is_some());
        assert!(published_packet.data.signature_value.is_some());
        assert_eq!(published_packet.data.signature_value.unwrap(), b"test_signature");
    }

    #[tokio::test]
    async fn test_freshness_handling() {
        let mut config = PublisherConfig::default();
        config.default_freshness_period = Some(Duration::from_millis(10)); // Very short freshness
        
        let publisher = DataPacketPublisher::new(config);
        
        // Publish a chunk
        let chunk = create_test_chunk(0, false);
        let chunk_name = chunk.name.clone();
        publisher.publish_chunk(chunk).await.unwrap();
        
        // Wait for packet to become stale
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        // Try to handle Interest for stale packet
        let interest = Interest::new(chunk_name);
        let result = publisher.handle_interest(&interest).await.unwrap();
        
        // Should return None because packet is stale
        assert!(result.is_none());
        
        let stats = publisher.get_stats().await;
        assert_eq!(stats.cache_misses, 1);
    }

    #[tokio::test]
    async fn test_final_chunk_metadata() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        // Create final chunk
        let chunk = create_test_chunk(5, true);
        let result = publisher.publish_chunk(chunk).await.unwrap();
        
        // Check that final block ID was set
        assert!(result.data.meta_info.is_some());
        let meta_info = result.data.meta_info.unwrap();
        assert!(meta_info.final_block_id.is_some());
        assert_eq!(meta_info.final_block_id.unwrap(), b"5");
    }

    #[tokio::test]
    async fn test_utils_functions() {
        // Test sequence number extraction
        let name = Name::from_str("/test/file/segment/42");
        assert_eq!(utils::extract_sequence_number(&name), Some(42));
        
        // Test invalid name
        let invalid_name = Name::from_str("/test/file");
        assert_eq!(utils::extract_sequence_number(&invalid_name), None);
        
        // Test data packet creation
        let config = PublisherConfig::default();
        let data = utils::create_data_packet(
            Name::from_str("/test"),
            b"content".to_vec(),
            &config
        ).unwrap();
        
        assert_eq!(data.content, b"content");
        assert!(data.meta_info.is_some());
        
        // Test final chunk detection
        let mut data_with_final = data.clone();
        data_with_final.meta_info.as_mut().unwrap().final_block_id = Some(b"1".to_vec());
        assert!(utils::is_final_chunk(&data_with_final));
        assert!(!utils::is_final_chunk(&data));
        
        // Test chunk validation
        let valid_chunk_data = utils::create_data_packet(
            Name::from_str("/test/segment/0"),
            b"content".to_vec(),
            &config
        ).unwrap();
        assert!(utils::validate_chunk_packet(&valid_chunk_data).is_ok());
        
        let invalid_chunk_data = utils::create_data_packet(
            Name::from_str("/test/invalid"),
            b"content".to_vec(),
            &config
        ).unwrap();
        assert!(utils::validate_chunk_packet(&invalid_chunk_data).is_err());
    }

    #[tokio::test]
    async fn test_config_variants() {
        let file_transfer_config = PublisherConfig::for_file_transfer();
        assert_eq!(file_transfer_config.default_freshness_period, Some(Duration::from_secs(7200)));
        assert_eq!(file_transfer_config.max_cache_size, 2000);
        
        let streaming_config = PublisherConfig::for_streaming();
        assert_eq!(streaming_config.default_freshness_period, Some(Duration::from_secs(30)));
        assert!(!streaming_config.include_chunk_metadata);
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(config);
        
        // Test initial stats
        let stats = publisher.get_stats().await;
        assert_eq!(stats.packets_published, 0);
        assert_eq!(stats.cache_hit_ratio(), 0.0);
        
        // Publish some chunks
        let chunks = vec![
            create_test_chunk(0, false),
            create_test_chunk(1, true),
        ];
        publisher.publish_chunks(chunks).await.unwrap();
        
        // Handle some interests
        let interest1 = Interest::new(Name::from_str("/test/file/segment/0"));
        let interest2 = Interest::new(Name::from_str("/test/file/segment/1"));
        let interest3 = Interest::new(Name::from_str("/nonexistent/segment/0"));
        
        publisher.handle_interest(&interest1).await.unwrap();
        publisher.handle_interest(&interest2).await.unwrap();
        publisher.handle_interest(&interest3).await.unwrap();
        
        let final_stats = publisher.get_stats().await;
        assert_eq!(final_stats.packets_published, 2);
        assert_eq!(final_stats.interests_processed, 3);
        assert_eq!(final_stats.cache_hits, 2);
        assert_eq!(final_stats.cache_misses, 1);
        assert!(final_stats.cache_hit_ratio() > 0.5);
        assert!(final_stats.avg_packet_size > 0.0);
        assert!(final_stats.last_publication_time.is_some());
    }
}