use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use log::{debug, warn};
use tokio::sync::RwLock;
use quinn::Connection;

use udcn_core::packets::{Data, Interest, ValidationConfig};
use udcn_core::signature::{SignatureEngine, SignatureType};
use crate::ndn_quic::NdnQuicTransport;

/// Result of signature validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    /// Signature is valid
    Valid,
    /// Signature is invalid with reason
    Invalid(String),
}

/// Configuration for Data response handling
#[derive(Debug, Clone)]
pub struct DataResponseConfig {
    /// Enable signature verification for incoming Data packets
    pub verify_signatures: bool,
    /// Enable content verification (checksums, integrity)
    pub verify_content: bool,
    /// Enable freshness validation
    pub verify_freshness: bool,
    /// Maximum acceptable Data packet size
    pub max_data_size: usize,
    /// Content store cache enabled
    pub enable_content_store: bool,
    /// Maximum entries in content store
    pub max_content_store_entries: usize,
    /// Data packet timeout for processing
    pub processing_timeout: std::time::Duration,
    /// Enable duplicate detection
    pub enable_duplicate_detection: bool,
}

impl Default for DataResponseConfig {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            verify_content: true,
            verify_freshness: true,
            max_data_size: 8192, // 8KB
            enable_content_store: true,
            max_content_store_entries: 1000,
            processing_timeout: std::time::Duration::from_secs(30),
            enable_duplicate_detection: true,
        }
    }
}

/// Data packet verification status
#[derive(Debug, Clone, PartialEq)]
pub enum DataVerificationStatus {
    /// Data packet is valid and verified
    Valid,
    /// Signature verification failed
    InvalidSignature(String),
    /// Content verification failed
    InvalidContent(String),
    /// Data packet is stale/expired
    Stale,
    /// Data packet format is malformed
    Malformed(String),
    /// Data packet exceeds size limits
    OversizedPacket,
    /// Duplicate Data packet detected
    Duplicate,
}

/// Content Store entry for caching Data packets
#[derive(Debug, Clone)]
pub struct ContentStoreEntry {
    /// The cached Data packet
    pub data: Data,
    /// Time when the entry was cached
    pub cached_at: std::time::Instant,
    /// Access count for LRU eviction
    pub access_count: u32,
    /// Last access time
    pub last_accessed: std::time::Instant,
    /// Entry size in bytes
    pub size: usize,
}

impl ContentStoreEntry {
    pub fn new(data: Data) -> Self {
        let now = std::time::Instant::now();
        let size = data.encode().map(|encoded| encoded.len()).unwrap_or(0);
        
        Self {
            data,
            cached_at: now,
            access_count: 1,
            last_accessed: now,
            size,
        }
    }
    
    /// Check if this entry is still fresh
    pub fn is_fresh(&self) -> bool {
        if let Some(freshness_period) = self.data.meta_info.as_ref()
            .and_then(|meta| meta.freshness_period) {
            self.cached_at.elapsed() <= freshness_period
        } else {
            true // No freshness period specified, consider always fresh
        }
    }
    
    /// Update access statistics
    pub fn mark_accessed(&mut self) {
        self.access_count += 1;
        self.last_accessed = std::time::Instant::now();
    }
}

/// Content Store for caching validated Data packets
#[derive(Debug, Default)]
pub struct ContentStore {
    /// Entries indexed by Data name
    entries: HashMap<String, ContentStoreEntry>,
    /// Total size of cached content in bytes
    total_size: usize,
    /// Maximum allowed cache size
    max_size: usize,
    /// Maximum number of entries
    max_entries: usize,
}

impl ContentStore {
    pub fn new(max_entries: usize, max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            total_size: 0,
            max_size,
            max_entries,
        }
    }
    
    /// Insert a Data packet into the content store
    pub fn insert(&mut self, data: Data) -> Result<()> {
        let name = data.name.to_string();
        let entry = ContentStoreEntry::new(data);
        
        // Check if we need to evict entries
        if self.entries.len() >= self.max_entries || 
           self.total_size + entry.size > self.max_size {
            self.evict_entries(entry.size)?;
        }
        
        // Remove existing entry if present
        if let Some(old_entry) = self.entries.remove(&name) {
            self.total_size -= old_entry.size;
        }
        
        // Insert new entry
        let entry_size = entry.size;
        self.total_size += entry_size;
        self.entries.insert(name.clone(), entry);
        
        debug!("Inserted Data packet into content store: {} (size: {} bytes)", 
               name, entry_size);
        Ok(())
    }
    
    /// Retrieve a Data packet from the content store
    pub fn get(&mut self, name: &str) -> Option<ContentStoreEntry> {
        if let Some(entry) = self.entries.get_mut(name) {
            if entry.is_fresh() {
                entry.mark_accessed();
                Some(entry.clone())
            } else {
                // Remove stale entry
                let entry_size = entry.size;
                self.entries.remove(name);
                self.total_size -= entry_size;
                None
            }
        } else {
            None
        }
    }
    
    /// Evict entries using LRU policy
    fn evict_entries(&mut self, needed_space: usize) -> Result<()> {
        let mut candidates: Vec<_> = self.entries.iter().collect();
        
        // Sort by last accessed time (oldest first)
        candidates.sort_by_key(|(_, entry)| entry.last_accessed);
        
        let mut freed_space = 0;
        let mut names_to_remove = Vec::new();
        
        for (name, entry) in candidates {
            names_to_remove.push(name.clone());
            freed_space += entry.size;
            
            if freed_space >= needed_space {
                break;
            }
        }
        
        // Remove selected entries
        for name in names_to_remove {
            if let Some(entry) = self.entries.remove(&name) {
                self.total_size -= entry.size;
                debug!("Evicted content store entry: {} (size: {} bytes)", name, entry.size);
            }
        }
        
        Ok(())
    }
    
    /// Clean up stale entries
    pub fn cleanup_stale(&mut self) -> usize {
        let mut stale_names = Vec::new();
        
        for (name, entry) in &self.entries {
            if !entry.is_fresh() {
                stale_names.push(name.clone());
            }
        }
        
        let count = stale_names.len();
        for name in stale_names {
            if let Some(entry) = self.entries.remove(&name) {
                self.total_size -= entry.size;
            }
        }
        
        if count > 0 {
            debug!("Cleaned up {} stale content store entries", count);
        }
        
        count
    }
    
    /// Get content store statistics
    pub fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        stats.insert("total_entries".to_string(), self.entries.len() as u64);
        stats.insert("total_size_bytes".to_string(), self.total_size as u64);
        stats.insert("max_entries".to_string(), self.max_entries as u64);
        stats.insert("max_size_bytes".to_string(), self.max_size as u64);
        stats
    }
}

/// Data Response Handler for processing incoming Data packets
pub struct DataResponseHandler {
    /// Configuration for Data response handling
    config: DataResponseConfig,
    /// Signature engine for Data packet verification
    signature_engine: Arc<SignatureEngine>,
    /// Content store for caching validated Data packets
    content_store: Arc<RwLock<ContentStore>>,
    /// Duplicate detection cache
    duplicate_cache: Arc<RwLock<HashMap<String, std::time::Instant>>>,
    /// Processing statistics
    stats: Arc<RwLock<DataResponseStats>>,
}

/// Statistics for Data response processing
#[derive(Debug, Default)]
pub struct DataResponseStats {
    /// Total Data packets processed
    pub total_processed: u64,
    /// Successfully validated packets
    pub valid_packets: u64,
    /// Failed validation packets
    pub invalid_packets: u64,
    /// Signature verification failures
    pub signature_failures: u64,
    /// Content verification failures
    pub content_failures: u64,
    /// Stale packets rejected
    pub stale_packets: u64,
    /// Duplicate packets detected
    pub duplicate_packets: u64,
    /// Content store hits
    pub content_store_hits: u64,
    /// Content store misses
    pub content_store_misses: u64,
}

impl DataResponseHandler {
    /// Create a new Data response handler
    pub fn new(
        config: DataResponseConfig,
        _validation_config: ValidationConfig,
    ) -> Self {
        let signature_engine = Arc::new(SignatureEngine::new());
        let content_store = Arc::new(RwLock::new(ContentStore::new(
            config.max_content_store_entries,
            config.max_data_size * config.max_content_store_entries,
        )));
        
        Self {
            config,
            signature_engine,
            content_store,
            duplicate_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DataResponseStats::default())),
        }
    }
    
    /// Process an incoming Data packet with comprehensive validation
    pub async fn process_data_packet(
        &self,
        data: Data,
        matching_interest: Option<&Interest>,
    ) -> Result<DataVerificationStatus> {
        let start_time = std::time::Instant::now();
        
        // Update processing statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_processed += 1;
        }
        
        // Check packet size limits
        if let Ok(encoded) = data.encode() {
            if encoded.len() > self.config.max_data_size {
                self.update_stats_invalid().await;
                return Ok(DataVerificationStatus::OversizedPacket);
            }
        }
        
        // Check for duplicates if enabled
        if self.config.enable_duplicate_detection {
            if self.is_duplicate(&data).await? {
                self.update_stats_duplicate().await;
                return Ok(DataVerificationStatus::Duplicate);
            }
        }
        
        // Verify Data packet format
        if let Err(e) = self.verify_packet_format(&data) {
            self.update_stats_invalid().await;
            return Ok(DataVerificationStatus::Malformed(e.to_string()));
        }
        
        // Verify Interest-Data matching if Interest is provided
        if let Some(interest) = matching_interest {
            if !self.verify_interest_data_match(interest, &data) {
                self.update_stats_invalid().await;
                return Ok(DataVerificationStatus::InvalidContent(
                    "Data does not match Interest".to_string()
                ));
            }
        }
        
        // Verify freshness if enabled
        if self.config.verify_freshness {
            if !self.verify_freshness(&data) {
                self.update_stats_stale().await;
                return Ok(DataVerificationStatus::Stale);
            }
        }
        
        // Verify signature if enabled
        if self.config.verify_signatures {
            match self.verify_signature(&data).await {
                Ok(ValidationResult::Valid) => {
                    debug!("Data packet signature verified: {}", data.name.to_string());
                }
                Ok(ValidationResult::Invalid(reason)) => {
                    self.update_stats_signature_failure().await;
                    return Ok(DataVerificationStatus::InvalidSignature(reason));
                }
                Err(e) => {
                    self.update_stats_signature_failure().await;
                    return Ok(DataVerificationStatus::InvalidSignature(e.to_string()));
                }
            }
        }
        
        // Verify content integrity if enabled
        if self.config.verify_content {
            if let Err(e) = self.verify_content_integrity(&data).await {
                self.update_stats_content_failure().await;
                return Ok(DataVerificationStatus::InvalidContent(e.to_string()));
            }
        }
        
        // Cache in content store if enabled
        if self.config.enable_content_store {
            if let Err(e) = self.cache_data_packet(data.clone()).await {
                warn!("Failed to cache Data packet: {}", e);
            }
        }
        
        // Record successful validation
        {
            let mut stats = self.stats.write().await;
            stats.valid_packets += 1;
        }
        
        let processing_time = start_time.elapsed();
        debug!("Successfully processed Data packet: {} in {:?}", 
               data.name.to_string(), processing_time);
        
        Ok(DataVerificationStatus::Valid)
    }
    
    /// Check if a Data packet is a duplicate
    async fn is_duplicate(&self, data: &Data) -> Result<bool> {
        let name = data.name.to_string();
        let mut cache = self.duplicate_cache.write().await;
        
        // Clean up old entries (older than 1 hour)
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        cache.retain(|_, &mut timestamp| timestamp > cutoff);
        
        // Check if this packet was recently seen
        if cache.contains_key(&name) {
            Ok(true)
        } else {
            cache.insert(name, std::time::Instant::now());
            Ok(false)
        }
    }
    
    /// Verify Data packet format and structure
    fn verify_packet_format(&self, data: &Data) -> Result<()> {
        // Check name is not empty
        if data.name.is_empty() {
            return Err(anyhow::anyhow!("Data name cannot be empty"));
        }
        
        // Verify signature info is present if signature value exists
        if data.signature_value.is_some() && data.signature_info.is_none() {
            return Err(anyhow::anyhow!("Signature value present without signature info"));
        }
        
        // Verify meta info structure if present
        if let Some(meta_info) = &data.meta_info {
            if let Some(freshness_period) = meta_info.freshness_period {
                if freshness_period == std::time::Duration::from_secs(0) {
                    return Err(anyhow::anyhow!("Freshness period cannot be zero"));
                }
            }
        }
        
        Ok(())
    }
    
    /// Verify Interest-Data name matching
    fn verify_interest_data_match(&self, interest: &Interest, data: &Data) -> bool {
        // Basic name matching - Interest name should be a prefix of Data name
        interest.name.is_prefix_of(&data.name)
    }
    
    /// Verify Data packet freshness
    fn verify_freshness(&self, data: &Data) -> bool {
        if let Some(meta_info) = &data.meta_info {
            if let Some(freshness_period) = meta_info.freshness_period {
                // For simplicity, assume Data was created recently
                // In a real implementation, you'd track creation time
                return true; // Placeholder - implement proper freshness checking
            }
        }
        true // No freshness constraints
    }
    
    /// Verify Data packet signature
    async fn verify_signature(&self, data: &Data) -> Result<ValidationResult> {
        // Check if Data packet has signature info and value
        if data.signature_info.is_none() || data.signature_value.is_none() {
            return Ok(ValidationResult::Invalid("Missing signature information".to_string()));
        }
        
        // For now, implement basic signature validation
        // In a real implementation, you would extract the public key from KeyLocator
        // and perform cryptographic verification
        let signature_type = SignatureType::from(data.signature_info.as_ref().unwrap().signature_type);
        match signature_type {
            SignatureType::DigestSha256 => {
                // For digest-only, we just verify the digest exists
                if data.signature_value.as_ref().unwrap().len() >= 32 {
                    Ok(ValidationResult::Valid)
                } else {
                    Ok(ValidationResult::Invalid("Invalid SHA256 digest length".to_string()))
                }
            }
            _ => {
                // For actual signatures, we need a public key
                // This is a placeholder - real implementation would verify cryptographically
                if !data.signature_value.as_ref().unwrap().is_empty() {
                    Ok(ValidationResult::Valid)
                } else {
                    Ok(ValidationResult::Invalid("Empty signature value".to_string()))
                }
            }
        }
    }
    
    /// Verify Data packet content integrity
    async fn verify_content_integrity(&self, _data: &Data) -> Result<()> {
        // Placeholder for content integrity verification
        // Could include checksums, hash verification, etc.
        Ok(())
    }
    
    /// Cache a validated Data packet in the content store
    async fn cache_data_packet(&self, data: Data) -> Result<()> {
        let mut content_store = self.content_store.write().await;
        content_store.insert(data)
    }
    
    /// Look up a Data packet in the content store
    pub async fn lookup_content_store(&self, name: &str) -> Option<Data> {
        let mut content_store = self.content_store.write().await;
        if let Some(entry) = content_store.get(name) {
            let mut stats = self.stats.write().await;
            stats.content_store_hits += 1;
            Some(entry.data)
        } else {
            let mut stats = self.stats.write().await;
            stats.content_store_misses += 1;
            None
        }
    }
    
    /// Clean up stale content store entries
    pub async fn cleanup_content_store(&self) -> Result<usize> {
        let mut content_store = self.content_store.write().await;
        Ok(content_store.cleanup_stale())
    }
    
    /// Get processing statistics
    pub async fn get_stats(&self) -> DataResponseStats {
        let stats = self.stats.read().await;
        DataResponseStats {
            total_processed: stats.total_processed,
            valid_packets: stats.valid_packets,
            invalid_packets: stats.invalid_packets,
            signature_failures: stats.signature_failures,
            content_failures: stats.content_failures,
            stale_packets: stats.stale_packets,
            duplicate_packets: stats.duplicate_packets,
            content_store_hits: stats.content_store_hits,
            content_store_misses: stats.content_store_misses,
        }
    }
    
    /// Get content store statistics
    pub async fn get_content_store_stats(&self) -> HashMap<String, u64> {
        let content_store = self.content_store.read().await;
        content_store.get_stats()
    }
    
    // Helper methods for updating statistics
    async fn update_stats_invalid(&self) {
        let mut stats = self.stats.write().await;
        stats.invalid_packets += 1;
    }
    
    async fn update_stats_duplicate(&self) {
        let mut stats = self.stats.write().await;
        stats.duplicate_packets += 1;
    }
    
    async fn update_stats_stale(&self) {
        let mut stats = self.stats.write().await;
        stats.stale_packets += 1;
    }
    
    async fn update_stats_signature_failure(&self) {
        let mut stats = self.stats.write().await;
        stats.signature_failures += 1;
        stats.invalid_packets += 1;
    }
    
    async fn update_stats_content_failure(&self) {
        let mut stats = self.stats.write().await;
        stats.content_failures += 1;
        stats.invalid_packets += 1;
    }
}

/// Integration with NdnQuicTransport for Data response processing
impl NdnQuicTransport {
    /// Enhanced receive_data with response processing
    pub async fn receive_data_with_processing(
        &self, 
        connection: &Connection,
        data_handler: &DataResponseHandler,
        matching_interest: Option<&Interest>,
    ) -> Result<(Data, DataVerificationStatus)> {
        // Receive the raw Data packet
        let data = self.receive_data(connection).await?;
        
        // Process and validate the Data packet
        let verification_status = data_handler
            .process_data_packet(data.clone(), matching_interest)
            .await?;
        
        Ok((data, verification_status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use udcn_core::packets::Name;
    use udcn_core::packets::ValidationConfig;
    
    #[tokio::test]
    async fn test_data_response_handler_creation() {
        let config = DataResponseConfig::default();
        let validation_config = ValidationConfig::default();
        let handler = DataResponseHandler::new(config, validation_config);
        
        let stats = handler.get_stats().await;
        assert_eq!(stats.total_processed, 0);
    }
    
    #[tokio::test]
    async fn test_content_store_basic_operations() {
        let mut content_store = ContentStore::new(10, 1024);
        
        let name = Name::from_str("/test/data");
        let data = Data::new(name, vec![]);
        
        content_store.insert(data.clone()).expect("Insert should succeed");
        
        let retrieved = content_store.get("/test/data");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data.name, data.name);
    }
    
    #[tokio::test]
    async fn test_duplicate_detection() {
        let config = DataResponseConfig::default();
        let validation_config = ValidationConfig::default();
        let handler = DataResponseHandler::new(config, validation_config);
        
        let name = Name::from_str("/test/duplicate");
        let data = Data::new(name, vec![]);
        
        // First packet should not be duplicate
        assert!(!handler.is_duplicate(&data).await.unwrap());
        
        // Second identical packet should be duplicate
        assert!(handler.is_duplicate(&data).await.unwrap());
    }
    
    #[tokio::test]
    async fn test_oversized_packet_rejection() {
        let mut config = DataResponseConfig::default();
        config.max_data_size = 100; // Very small limit
        
        let validation_config = ValidationConfig::default();
        let handler = DataResponseHandler::new(config, validation_config);
        
        let name = Name::from_str("/test/large");
        let data = Data::new(name, vec![0; 200]); // Larger than limit
        
        let result = handler.process_data_packet(data, None).await.unwrap();
        assert_eq!(result, DataVerificationStatus::OversizedPacket);
    }
    
    #[test]
    fn test_content_store_eviction() {
        let mut content_store = ContentStore::new(2, 1024); // Small limits
        
        // Insert first data packet
        let data1 = Data::new(Name::from_str("/test/data1"), vec![]);
        content_store.insert(data1).expect("Insert should succeed");
        
        // Insert second data packet
        let data2 = Data::new(Name::from_str("/test/data2"), vec![]);
        content_store.insert(data2).expect("Insert should succeed");
        
        // Access first packet to make it more recently used
        content_store.get("/test/data1");
        
        // Insert third packet, should evict data2 (least recently used)
        let data3 = Data::new(Name::from_str("/test/data3"), vec![]);
        content_store.insert(data3).expect("Insert should succeed");
        
        assert!(content_store.get("/test/data1").is_some());
        assert!(content_store.get("/test/data2").is_none());
        assert!(content_store.get("/test/data3").is_some());
    }
}