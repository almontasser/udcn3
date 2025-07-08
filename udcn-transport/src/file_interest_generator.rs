use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};


use udcn_core::packets::{Interest, Name};

use crate::file_chunking::FileMetadata;
use crate::ndn_quic::NdnQuicTransport;

/// Configuration for file Interest generation
#[derive(Debug, Clone)]
pub struct FileInterestConfig {
    /// Maximum number of concurrent requests
    pub max_concurrent_requests: usize,
    /// Initial timeout for Interest packets
    pub initial_timeout: Duration,
    /// Maximum timeout for Interest packets
    pub max_timeout: Duration,
    /// Backoff multiplier for retry attempts
    pub backoff_multiplier: f64,
    /// Maximum number of retry attempts
    pub max_retries: usize,
    /// Request window size for pipeline fetching
    pub request_window_size: usize,
    /// Nonce generation range
    pub nonce_range: (u32, u32),
}

impl Default for FileInterestConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            initial_timeout: Duration::from_secs(2),
            max_timeout: Duration::from_secs(10),
            backoff_multiplier: 1.5,
            max_retries: 3,
            request_window_size: 5,
            nonce_range: (1, u32::MAX),
        }
    }
}

/// Status of a chunk request
#[derive(Debug, Clone, PartialEq)]
pub enum ChunkRequestStatus {
    /// Request is pending
    Pending,
    /// Request is in progress
    InProgress,
    /// Request completed successfully
    Completed,
    /// Request failed after retries
    Failed,
    /// Request timed out
    TimedOut,
}

/// Information about a chunk request
#[derive(Debug, Clone)]
pub struct ChunkRequest {
    /// Chunk sequence number
    pub sequence: usize,
    /// NDN name for this chunk
    pub name: Name,
    /// Current status
    pub status: ChunkRequestStatus,
    /// Number of attempts made
    pub attempts: usize,
    /// Time when request was created
    pub created_at: Instant,
    /// Time when request was last attempted
    pub last_attempt: Option<Instant>,
    /// Current timeout duration
    pub current_timeout: Duration,
    /// Associated Interest packet
    pub interest: Interest,
}

impl ChunkRequest {
    /// Create a new chunk request
    pub fn new(sequence: usize, base_name: &Name, config: &FileInterestConfig) -> Self {
        let name = Self::generate_chunk_name(base_name, sequence);
        let interest = Self::create_interest(&name, config);
        
        Self {
            sequence,
            name,
            status: ChunkRequestStatus::Pending,
            attempts: 0,
            created_at: Instant::now(),
            last_attempt: None,
            current_timeout: config.initial_timeout,
            interest,
        }
    }

    /// Generate NDN name for a specific chunk
    fn generate_chunk_name(base_name: &Name, sequence: usize) -> Name {
        let mut name = base_name.clone();
        name.components.push(b"chunk".to_vec());
        name.components.push(sequence.to_string().as_bytes().to_vec());
        name
    }

    /// Create Interest packet for a chunk
    fn create_interest(name: &Name, config: &FileInterestConfig) -> Interest {
        Interest {
            name: name.clone(),
            selectors: None,
            nonce: Some(fastrand::u32(config.nonce_range.0..config.nonce_range.1)),
            interest_lifetime: Some(config.initial_timeout),
            hop_limit: Some(64),
            application_parameters: None,
        }
    }

    /// Update Interest packet for retry
    pub fn update_for_retry(&mut self, config: &FileInterestConfig) {
        self.attempts += 1;
        self.last_attempt = Some(Instant::now());
        self.current_timeout = std::cmp::min(
            Duration::from_secs_f64(self.current_timeout.as_secs_f64() * config.backoff_multiplier),
            config.max_timeout,
        );
        
        // Generate new nonce for retry
        self.interest.nonce = Some(fastrand::u32(config.nonce_range.0..config.nonce_range.1));
        self.interest.interest_lifetime = Some(self.current_timeout);
    }

    /// Check if request should be retried
    pub fn should_retry(&self, config: &FileInterestConfig) -> bool {
        self.attempts < config.max_retries && 
        matches!(self.status, ChunkRequestStatus::Pending | ChunkRequestStatus::InProgress)
    }

    /// Check if request has expired
    pub fn is_expired(&self) -> bool {
        if let Some(last_attempt) = self.last_attempt {
            last_attempt.elapsed() > self.current_timeout
        } else {
            self.created_at.elapsed() > self.current_timeout
        }
    }
}

/// Statistics for Interest generation
#[derive(Debug, Clone, Default)]
pub struct InterestGenerationStats {
    /// Total number of requests generated
    pub total_requests: usize,
    /// Number of successful requests
    pub successful_requests: usize,
    /// Number of failed requests
    pub failed_requests: usize,
    /// Number of timed out requests
    pub timed_out_requests: usize,
    /// Number of retries performed
    pub total_retries: usize,
    /// Average response time
    pub avg_response_time: Duration,
    /// Current window size
    pub current_window_size: usize,
}

/// File Interest Generator for NDN file transfers
pub struct FileInterestGenerator {
    /// Configuration
    config: FileInterestConfig,
    /// Transport layer
    transport: Arc<NdnQuicTransport>,
    /// Pending chunk requests
    pending_requests: Arc<RwLock<HashMap<usize, ChunkRequest>>>,
    /// Statistics
    stats: Arc<RwLock<InterestGenerationStats>>,
}

impl FileInterestGenerator {
    /// Create a new FileInterestGenerator
    pub fn new(config: FileInterestConfig, transport: Arc<NdnQuicTransport>) -> Self {
        Self {
            config,
            transport,
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(InterestGenerationStats::default())),
        }
    }

    /// Generate Interest packets for file chunks
    pub async fn generate_interests_for_file(
        &self,
        base_name: &Name,
        file_metadata: &FileMetadata,
        _remote_addr: SocketAddr,
    ) -> Result<Vec<ChunkRequest>> {
        let total_chunks = file_metadata.total_chunks;
        let mut requests = Vec::with_capacity(total_chunks);

        debug!("Generating {} Interest packets for file: {}", total_chunks, base_name);

        // Generate chunk requests
        for sequence in 0..total_chunks {
            let request = ChunkRequest::new(sequence, base_name, &self.config);
            requests.push(request);
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += total_chunks;
        }

        info!("Generated {} Interest packets for file transfer", total_chunks);
        Ok(requests)
    }

    /// Generate Interest for a specific chunk
    pub async fn generate_chunk_interest(
        &self,
        base_name: &Name,
        sequence: usize,
    ) -> Result<ChunkRequest> {
        let request = ChunkRequest::new(sequence, base_name, &self.config);
        
        debug!("Generated Interest for chunk {}: {}", sequence, request.name);
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
        }

        Ok(request)
    }

    /// Send Interest packet with retry logic
    pub async fn send_interest_with_retry(
        &self,
        mut request: ChunkRequest,
        remote_addr: SocketAddr,
    ) -> Result<ChunkRequest> {
        let mut last_error = None;

        while request.should_retry(&self.config) {
            request.status = ChunkRequestStatus::InProgress;
            
            debug!("Sending Interest for chunk {} (attempt {})", 
                   request.sequence, request.attempts + 1);

            // Send Interest packet
            match timeout(
                request.current_timeout,
                self.transport.send_interest(&request.interest, remote_addr)
            ).await {
                Ok(Ok(())) => {
                    request.status = ChunkRequestStatus::Completed;
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().await;
                        stats.successful_requests += 1;
                    }

                    info!("Successfully sent Interest for chunk {}", request.sequence);
                    return Ok(request);
                }
                Ok(Err(e)) => {
                    warn!("Failed to send Interest for chunk {}: {}", request.sequence, e);
                    last_error = Some(e);
                }
                Err(_) => {
                    warn!("Interest for chunk {} timed out", request.sequence);
                    request.status = ChunkRequestStatus::TimedOut;
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().await;
                        stats.timed_out_requests += 1;
                    }
                }
            }

            // Prepare for retry
            if request.should_retry(&self.config) {
                request.update_for_retry(&self.config);
                
                // Update retry statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.total_retries += 1;
                }

                // Wait before retry
                sleep(Duration::from_millis(100)).await;
            }
        }

        // Mark as failed
        request.status = ChunkRequestStatus::Failed;
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.failed_requests += 1;
        }

        error!("Failed to send Interest for chunk {} after {} attempts", 
               request.sequence, request.attempts);
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Interest sending failed")))
    }

    /// Send multiple Interest packets concurrently
    pub async fn send_interests_concurrent(
        &self,
        requests: Vec<ChunkRequest>,
        remote_addr: SocketAddr,
    ) -> Result<Vec<ChunkRequest>> {
        let mut results = Vec::with_capacity(requests.len());
        let mut _handles: Vec<tokio::task::JoinHandle<Result<ChunkRequest>>> = Vec::new();

        // Create concurrent tasks with window size limit
        let chunks = requests.chunks(self.config.max_concurrent_requests);
        
        for chunk in chunks {
            let mut window_handles = Vec::new();
            
            for request in chunk {
                let request = request.clone();
                let generator = self.clone();
                
                let handle = tokio::spawn(async move {
                    generator.send_interest_with_retry(request, remote_addr).await
                });
                
                window_handles.push(handle);
            }
            
            // Wait for current window to complete
            for handle in window_handles {
                match handle.await {
                    Ok(Ok(request)) => results.push(request),
                    Ok(Err(e)) => {
                        error!("Interest sending failed: {}", e);
                        // Continue with other requests
                    }
                    Err(e) => {
                        error!("Task join error: {}", e);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> InterestGenerationStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = InterestGenerationStats::default();
    }

    /// Get pending requests
    pub async fn get_pending_requests(&self) -> HashMap<usize, ChunkRequest> {
        self.pending_requests.read().await.clone()
    }

    /// Add request to pending list
    pub async fn add_pending_request(&self, request: ChunkRequest) {
        let mut pending = self.pending_requests.write().await;
        pending.insert(request.sequence, request);
    }

    /// Remove request from pending list
    pub async fn remove_pending_request(&self, sequence: usize) -> Option<ChunkRequest> {
        let mut pending = self.pending_requests.write().await;
        pending.remove(&sequence)
    }

    /// Clean up expired requests
    pub async fn cleanup_expired_requests(&self) -> usize {
        let mut pending = self.pending_requests.write().await;
        let initial_count = pending.len();
        
        pending.retain(|_, request| !request.is_expired());
        
        let removed_count = initial_count - pending.len();
        if removed_count > 0 {
            debug!("Cleaned up {} expired requests", removed_count);
        }
        
        removed_count
    }
}

impl Clone for FileInterestGenerator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            transport: self.transport.clone(),
            pending_requests: self.pending_requests.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_chunk_name_generation() {
        let mut base_name = Name { components: Vec::new() };
        base_name.components.push(b"example".to_vec());
        base_name.components.push(b"file".to_vec());
        
        let chunk_name = ChunkRequest::generate_chunk_name(&base_name, 42);
        
        assert_eq!(chunk_name.components.len(), 4);
        assert_eq!(chunk_name.components[0], b"example".to_vec());
        assert_eq!(chunk_name.components[1], b"file".to_vec());
        assert_eq!(chunk_name.components[2], b"chunk".to_vec());
        assert_eq!(chunk_name.components[3], b"42".to_vec());
    }

    #[test]
    fn test_chunk_request_creation() {
        let config = FileInterestConfig::default();
        let mut base_name = Name { components: Vec::new() };
        base_name.components.push(b"test".to_vec());
        
        let request = ChunkRequest::new(5, &base_name, &config);
        
        assert_eq!(request.sequence, 5);
        assert_eq!(request.status, ChunkRequestStatus::Pending);
        assert_eq!(request.attempts, 0);
        assert!(request.interest.nonce.is_some());
        assert_eq!(request.interest.interest_lifetime, Some(config.initial_timeout));
    }

    #[test]
    fn test_retry_logic() {
        let config = FileInterestConfig::default();
        let mut base_name = Name { components: Vec::new() };
        base_name.components.push(b"test".to_vec());
        
        let mut request = ChunkRequest::new(0, &base_name, &config);
        
        // Should retry initially
        assert!(request.should_retry(&config));
        
        // After max retries, should not retry
        request.attempts = config.max_retries;
        assert!(!request.should_retry(&config));
        
        // Failed status should not retry
        request.attempts = 0;
        request.status = ChunkRequestStatus::Failed;
        assert!(!request.should_retry(&config));
    }

    #[test]
    fn test_backoff_calculation() {
        let config = FileInterestConfig::default();
        let mut base_name = Name { components: Vec::new() };
        base_name.components.push(b"test".to_vec());
        
        let mut request = ChunkRequest::new(0, &base_name, &config);
        let initial_timeout = request.current_timeout;
        
        request.update_for_retry(&config);
        
        assert!(request.current_timeout > initial_timeout);
        assert_eq!(request.attempts, 1);
        assert!(request.last_attempt.is_some());
    }
}