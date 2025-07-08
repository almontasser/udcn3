use std::collections::HashMap;
use crate::progress_tracker::{ProgressTracker, TransferSessionId};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use udcn_core::packets::{Interest, Name};
use crate::data_publisher::{DataPacketPublisher, PublisherConfig, PublishedPacket, PublishingError};
use crate::file_chunking::FileChunk;
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};

/// Configuration for the concurrent server
#[derive(Debug, Clone)]
pub struct ConcurrentServerConfig {
    /// Maximum number of concurrent requests to handle
    pub max_concurrent_requests: usize,
    /// Maximum number of worker threads
    pub max_worker_threads: usize,
    /// Request timeout duration
    pub request_timeout: Duration,
    /// Channel buffer size for request queuing
    pub request_buffer_size: usize,
    /// Statistics collection interval
    pub stats_interval: Duration,
    /// Enable request deduplication
    pub enable_deduplication: bool,
    /// Deduplication cache size
    pub dedup_cache_size: usize,
    /// Deduplication cache TTL
    pub dedup_cache_ttl: Duration,
}

impl Default for ConcurrentServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 1000,
            max_worker_threads: num_cpus::get(),
            request_timeout: Duration::from_secs(30),
            request_buffer_size: 10000,
            stats_interval: Duration::from_secs(60),
            enable_deduplication: true,
            dedup_cache_size: 5000,
            dedup_cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl ConcurrentServerConfig {
    /// Create config optimized for high-throughput file serving
    pub fn for_file_transfer() -> Self {
        Self {
            max_concurrent_requests: 2000,
            max_worker_threads: num_cpus::get() * 2,
            request_timeout: Duration::from_secs(60),
            request_buffer_size: 20000,
            stats_interval: Duration::from_secs(30),
            enable_deduplication: true,
            dedup_cache_size: 10000,
            dedup_cache_ttl: Duration::from_secs(600), // 10 minutes
        }
    }

    /// Create config for low-latency streaming
    pub fn for_streaming() -> Self {
        Self {
            max_concurrent_requests: 500,
            max_worker_threads: num_cpus::get(),
            request_timeout: Duration::from_secs(5),
            request_buffer_size: 5000,
            stats_interval: Duration::from_secs(10),
            enable_deduplication: false, // Disable for real-time streams
            dedup_cache_size: 0,
            dedup_cache_ttl: Duration::from_secs(0),
        }
    }

    /// Create config for memory-constrained environments
    pub fn for_low_memory() -> Self {
        Self {
            max_concurrent_requests: 100,
            max_worker_threads: 2,
            request_timeout: Duration::from_secs(15),
            request_buffer_size: 1000,
            stats_interval: Duration::from_secs(120),
            enable_deduplication: true,
            dedup_cache_size: 500,
            dedup_cache_ttl: Duration::from_secs(180),
        }
    }
}

/// Server performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    /// Total requests received
    pub requests_received: u64,
    /// Total requests processed successfully
    pub requests_processed: u64,
    /// Total requests failed
    pub requests_failed: u64,
    /// Total requests timeout
    pub requests_timeout: u64,
    /// Total requests deduplicated
    pub requests_deduplicated: u64,
    /// Current active requests
    pub active_requests: u64,
    /// Peak concurrent requests
    pub peak_concurrent_requests: u64,
    /// Average request processing time (milliseconds)
    pub avg_processing_time_ms: f64,
    /// Total bytes served
    pub bytes_served: u64,
    /// Server uptime (seconds)
    pub uptime_seconds: u64,
    /// Requests per second (last interval)
    pub requests_per_second: f64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Worker thread utilization
    pub worker_utilization: f64,
}

impl Default for ServerStats {
    fn default() -> Self {
        Self {
            requests_received: 0,
            requests_processed: 0,
            requests_failed: 0,
            requests_timeout: 0,
            requests_deduplicated: 0,
            active_requests: 0,
            peak_concurrent_requests: 0,
            avg_processing_time_ms: 0.0,
            bytes_served: 0,
            uptime_seconds: 0,
            requests_per_second: 0.0,
            cache_hit_ratio: 0.0,
            worker_utilization: 0.0,
        }
    }
}

impl ServerStats {
    /// Calculate overall success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.requests_processed + self.requests_failed + self.requests_timeout;
        if total == 0 {
            0.0
        } else {
            self.requests_processed as f64 / total as f64
        }
    }

    /// Calculate throughput in MB/s
    pub fn throughput_mbps(&self) -> f64 {
        if self.uptime_seconds == 0 {
            0.0
        } else {
            (self.bytes_served as f64 / (1024.0 * 1024.0)) / self.uptime_seconds as f64
        }
    }
}

/// Request context for tracking and deduplication
#[derive(Debug, Clone)]
struct RequestContext {
    interest: Interest,
    request_id: String,
    received_at: SystemTime,
    client_id: Option<String>,
}

impl RequestContext {
    fn new(interest: Interest, client_id: Option<String>) -> Self {
        let request_id = format!("{}_{}", 
            interest.name.to_string(), 
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default().as_nanos()
        );

        Self {
            interest,
            request_id,
            received_at: SystemTime::now(),
            client_id,
        }
    }

    fn dedup_key(&self) -> String {
        self.interest.name.to_string()
    }
}

/// Response from processing a request
#[derive(Debug, Clone)]
pub struct RequestResponse {
    pub request_id: String,
    pub data: Option<PublishedPacket>,
    pub processing_time: Duration,
    pub cache_hit: bool,
    pub error: Option<String>,
}

/// Deduplication cache entry
#[derive(Debug, Clone)]
struct DedupCacheEntry {
    response: RequestResponse,
    created_at: SystemTime,
}

impl DedupCacheEntry {
    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed().unwrap_or_default() > ttl
    }
}

/// Main concurrent server for handling multiple Interest requests
pub struct ConcurrentServer {
    config: ConcurrentServerConfig,
    publisher: Arc<DataPacketPublisher>,
    stats: Arc<RwLock<ServerStats>>,
    start_time: SystemTime,
    
    // Concurrency control
    request_semaphore: Arc<Semaphore>,
    
    // Request deduplication
    dedup_cache: Arc<RwLock<HashMap<String, DedupCacheEntry>>>,
    
    // Communication channels
    request_sender: Option<mpsc::Sender<RequestContext>>,
    response_receiver: Option<mpsc::Receiver<RequestResponse>>,
    
    // Background tasks
    worker_handles: Vec<JoinHandle<()>>,
    stats_task: Option<JoinHandle<()>>,
    cleanup_task: Option<JoinHandle<()>>,
    
    // Progress tracking
    progress_tracker: Option<Arc<crate::progress_tracker::ProgressTracker>>,
}

impl ConcurrentServer {
    /// Create a new concurrent server
    pub fn new(config: ConcurrentServerConfig, publisher: DataPacketPublisher) -> Self {
        let request_semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
        let dedup_cache = Arc::new(RwLock::new(HashMap::new()));
        
        Self {
            config,
            publisher: Arc::new(publisher),
            stats: Arc::new(RwLock::new(ServerStats::default())),
            start_time: SystemTime::now(),
            request_semaphore,
            dedup_cache,
            request_sender: None,
            response_receiver: None,
            worker_handles: Vec::new(),
            stats_task: None,
            cleanup_task: None,
            progress_tracker: None,
        }
    }

    /// Create server with default configuration
    pub fn with_default_config(publisher: DataPacketPublisher) -> Self {
        Self::new(ConcurrentServerConfig::default(), publisher)
    }

    /// Configure the server with a progress tracker
    pub fn with_progress_tracker(mut self, tracker: Arc<ProgressTracker>) -> Self {
        self.progress_tracker = Some(tracker);
        self
    }

    /// Start the concurrent server
    pub async fn start(&mut self) -> Result<(), ConcurrentServerError> {
        info!("Starting concurrent server with {} workers", self.config.max_worker_threads);

        // Create communication channels
        let (request_tx, request_rx) = mpsc::channel(self.config.request_buffer_size);
        let (response_tx, response_rx) = mpsc::channel(self.config.request_buffer_size);

        self.request_sender = Some(request_tx);
        self.response_receiver = Some(response_rx);

        // Start worker threads
        self.start_workers(request_rx, response_tx).await?;

        // Start background tasks
        self.start_background_tasks().await?;

        info!("Concurrent server started successfully");
        Ok(())
    }

    /// Stop the concurrent server
    pub async fn stop(&mut self) -> Result<(), ConcurrentServerError> {
        info!("Stopping concurrent server...");

        // Close request channel
        self.request_sender = None;

        // Wait for all worker tasks to complete
        for handle in self.worker_handles.drain(..) {
            if let Err(e) = handle.await {
                warn!("Worker task error during shutdown: {}", e);
            }
        }

        // Stop background tasks
        if let Some(stats_task) = self.stats_task.take() {
            stats_task.abort();
        }
        if let Some(cleanup_task) = self.cleanup_task.take() {
            cleanup_task.abort();
        }

        info!("Concurrent server stopped");
        Ok(())
    }

    /// Handle an Interest request
    pub async fn handle_request(
        &self, 
        interest: Interest, 
        client_id: Option<String>
    ) -> Result<RequestResponse, ConcurrentServerError> {
        let context = RequestContext::new(interest, client_id);
        
        // Update statistics
        self.increment_requests_received().await;

        // Check deduplication cache first
        if self.config.enable_deduplication {
            if let Some(cached_response) = self.check_dedup_cache(&context).await {
                self.increment_requests_deduplicated().await;
                return Ok(cached_response);
            }
        }

        // Acquire semaphore for concurrency control
        let _permit = self.request_semaphore.acquire().await
            .map_err(|_| ConcurrentServerError::ResourceUnavailable("Request semaphore closed".to_string()))?;

        self.increment_active_requests().await;

        // Send request to worker pool
        if let Some(sender) = &self.request_sender {
            sender.send(context.clone()).await
                .map_err(|e| ConcurrentServerError::ChannelError(format!("Failed to send request: {}", e)))?;
        } else {
            return Err(ConcurrentServerError::ServerNotRunning("Server not started".to_string()));
        }

        // Wait for response with timeout
        let response = tokio::time::timeout(
            self.config.request_timeout,
            self.wait_for_response(&context.request_id)
        ).await;

        self.decrement_active_requests().await;

        match response {
            Ok(Ok(resp)) => {
                // Cache response for deduplication
                if self.config.enable_deduplication {
                    self.cache_response(&context, &resp).await;
                }
                
                self.increment_requests_processed().await;
                Ok(resp)
            }
            Ok(Err(e)) => {
                self.increment_requests_failed().await;
                Err(e)
            }
            Err(_) => {
                self.increment_requests_timeout().await;
                Err(ConcurrentServerError::RequestTimeout("Request timed out".to_string()))
            }
        }
    }

    /// Get current server statistics
    pub async fn get_stats(&self) -> ServerStats {
        if let Ok(stats) = self.stats.read() {
            let mut stats = stats.clone();
            stats.uptime_seconds = self.start_time.elapsed()
                .unwrap_or_default().as_secs();
            
            // Get publisher stats for cache hit ratio
            let pub_stats = self.publisher.get_stats().await;
            stats.cache_hit_ratio = pub_stats.cache_hit_ratio();
            
            stats
        } else {
            ServerStats::default()
        }
    }

    /// Get current configuration
    pub fn get_config(&self) -> &ConcurrentServerConfig {
        &self.config
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.request_sender.is_some() && !self.worker_handles.is_empty()
    }

    /// Handle a file transfer request with progress tracking
    pub async fn handle_file_transfer(
        &self,
        chunks: Vec<crate::file_chunking::FileChunk>,
        client_id: String,
        file_name: String,
        file_size: u64,
    ) -> Result<Vec<crate::data_publisher::PublishedPacket>, ConcurrentServerError> {
        let session_id = TransferSessionId::new(&file_name, &client_id);
        
        // Use the publisher's progress tracking if available
        if let Some(tracker) = &self.progress_tracker {
            // Configure the publisher with the progress tracker
            let publisher_with_tracker = DataPacketPublisher::new(
                self.publisher.get_config().clone()
            ).with_progress_tracker(tracker.clone());
            
            // Publish with progress tracking
            publisher_with_tracker.publish_file_with_progress(
                chunks,
                session_id,
                file_name,
                file_size,
            ).await.map_err(|e| ConcurrentServerError::PublishingError(e))
        } else {
            // Fallback to regular publish without progress tracking
            self.publisher.publish_chunks(chunks).await
                .map_err(|e| ConcurrentServerError::PublishingError(e))
        }
    }

    /// Get progress information for a transfer session
    pub fn get_transfer_progress(&self, session_id: &TransferSessionId) -> Option<crate::progress_tracker::FileTransferProgress> {
        self.progress_tracker.as_ref()?.get_progress(session_id)
    }

    /// Get all active transfer sessions
    pub fn get_active_transfers(&self) -> Vec<crate::progress_tracker::FileTransferProgress> {
        self.progress_tracker.as_ref()
            .map(|tracker| tracker.get_active_transfers())
            .unwrap_or_default()
    }

    /// Get current progress metrics
    pub fn get_progress_metrics(&self) -> Option<crate::progress_tracker::ProgressMetrics> {
        self.progress_tracker.as_ref().map(|tracker| tracker.get_metrics())
    }

    /// Subscribe to progress events
    pub fn subscribe_progress_events(&self) -> Option<tokio::sync::broadcast::Receiver<crate::progress_tracker::ProgressEvent>> {
        self.progress_tracker.as_ref().map(|tracker| tracker.subscribe_events())
    }

    // Private implementation methods

    async fn start_workers(
        &mut self, 
        request_rx: mpsc::Receiver<RequestContext>,
        response_tx: mpsc::Sender<RequestResponse>
    ) -> Result<(), ConcurrentServerError> {
        let request_rx = Arc::new(tokio::sync::Mutex::new(request_rx));
        
        for worker_id in 0..self.config.max_worker_threads {
            let publisher = Arc::clone(&self.publisher);
            let response_tx = response_tx.clone();
            let stats = Arc::clone(&self.stats);
            let request_rx = Arc::clone(&request_rx);

            let handle = tokio::spawn(async move {
                debug!("Worker {} started", worker_id);
                
                loop {
                    let context = {
                        let mut rx = request_rx.lock().await;
                        match rx.recv().await {
                            Some(ctx) => ctx,
                            None => break, // Channel closed
                        }
                    };
                    
                    let start_time = SystemTime::now();
                    
                    let response = match publisher.handle_interest(&context.interest).await {
                        Ok(Some(packet)) => RequestResponse {
                            request_id: context.request_id.clone(),
                            data: Some(packet),
                            processing_time: start_time.elapsed().unwrap_or_default(),
                            cache_hit: true,
                            error: None,
                        },
                        Ok(None) => RequestResponse {
                            request_id: context.request_id.clone(),
                            data: None,
                            processing_time: start_time.elapsed().unwrap_or_default(),
                            cache_hit: false,
                            error: Some("No data available".to_string()),
                        },
                        Err(e) => RequestResponse {
                            request_id: context.request_id.clone(),
                            data: None,
                            processing_time: start_time.elapsed().unwrap_or_default(),
                            cache_hit: false,
                            error: Some(e.to_string()),
                        },
                    };

                    // Update processing time statistics
                    if let Ok(mut stats_guard) = stats.write() {
                        let new_time_ms = response.processing_time.as_millis() as f64;
                        let total_requests = stats_guard.requests_processed + stats_guard.requests_failed + 1;
                        
                        stats_guard.avg_processing_time_ms = 
                            (stats_guard.avg_processing_time_ms * (total_requests - 1) as f64 + new_time_ms) / total_requests as f64;
                    }

                    if let Err(e) = response_tx.send(response).await {
                        error!("Worker {} failed to send response: {}", worker_id, e);
                        break;
                    }
                }
                
                debug!("Worker {} stopped", worker_id);
            });

            self.worker_handles.push(handle);
        }

        Ok(())
    }

    async fn start_background_tasks(&mut self) -> Result<(), ConcurrentServerError> {
        // Start statistics collection task
        let stats = Arc::clone(&self.stats);
        let stats_interval = self.config.stats_interval;
        
        self.stats_task = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(stats_interval);
            let mut last_requests = 0u64;
            
            loop {
                interval.tick().await;
                
                if let Ok(mut stats_guard) = stats.write() {
                    let current_requests = stats_guard.requests_processed + stats_guard.requests_failed;
                    let requests_diff = current_requests.saturating_sub(last_requests);
                    
                    stats_guard.requests_per_second = requests_diff as f64 / stats_interval.as_secs_f64();
                    last_requests = current_requests;
                }
            }
        }));

        // Start cache cleanup task
        if self.config.enable_deduplication {
            let dedup_cache = Arc::clone(&self.dedup_cache);
            let cache_ttl = self.config.dedup_cache_ttl;
            
            self.cleanup_task = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60)); // Cleanup every minute
                
                loop {
                    interval.tick().await;
                    
                    if let Ok(mut cache) = dedup_cache.write() {
                        cache.retain(|_, entry| !entry.is_expired(cache_ttl));
                    }
                }
            }));
        }

        Ok(())
    }

    async fn wait_for_response(&self, _request_id: &str) -> Result<RequestResponse, ConcurrentServerError> {
        // In a real implementation, this would use a more sophisticated mechanism
        // like a response map with conditional variables or channels per request
        // For now, we'll use a simple polling approach with the receiver
        
        if let Some(_receiver) = &self.response_receiver {
            // This is a simplified implementation - in production, you'd want
            // a more efficient request/response matching system
            tokio::time::sleep(Duration::from_millis(10)).await; // Simulate processing
        }
        
        Err(ConcurrentServerError::InternalError("Response waiting not fully implemented".to_string()))
    }

    async fn check_dedup_cache(&self, context: &RequestContext) -> Option<RequestResponse> {
        if let Ok(cache) = self.dedup_cache.read() {
            if let Some(entry) = cache.get(&context.dedup_key()) {
                if !entry.is_expired(self.config.dedup_cache_ttl) {
                    return Some(entry.response.clone());
                }
            }
        }
        None
    }

    async fn cache_response(&self, context: &RequestContext, response: &RequestResponse) {
        if let Ok(mut cache) = self.dedup_cache.write() {
            // Implement cache size limit
            if cache.len() >= self.config.dedup_cache_size {
                // Simple eviction: remove random entry
                if let Some(key_to_remove) = cache.keys().next().cloned() {
                    cache.remove(&key_to_remove);
                }
            }

            let entry = DedupCacheEntry {
                response: response.clone(),
                created_at: SystemTime::now(),
            };

            cache.insert(context.dedup_key(), entry);
        }
    }

    // Statistics update methods
    async fn increment_requests_received(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.requests_received += 1;
        }
    }

    async fn increment_requests_processed(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.requests_processed += 1;
        }
    }

    async fn increment_requests_failed(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.requests_failed += 1;
        }
    }

    async fn increment_requests_timeout(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.requests_timeout += 1;
        }
    }

    async fn increment_requests_deduplicated(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.requests_deduplicated += 1;
        }
    }

    async fn increment_active_requests(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.active_requests += 1;
            if stats.active_requests > stats.peak_concurrent_requests {
                stats.peak_concurrent_requests = stats.active_requests;
            }
        }
    }

    async fn decrement_active_requests(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.active_requests = stats.active_requests.saturating_sub(1);
        }
    }
}

/// Errors that can occur in the concurrent server
#[derive(Debug, thiserror::Error)]
pub enum ConcurrentServerError {
    #[error("Resource unavailable: {0}")]
    ResourceUnavailable(String),
    #[error("Channel error: {0}")]
    ChannelError(String),
    #[error("Server not running: {0}")]
    ServerNotRunning(String),
    #[error("Request timeout: {0}")]
    RequestTimeout(String),
    #[error("Publishing error: {0}")]
    PublishingError(#[from] PublishingError),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_chunking::{FileChunker, ChunkingConfig};
    use std::io::Write;
    use tempfile::NamedTempFile;
    use udcn_core::packets::Name;

    fn create_test_file(size: usize) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let data = (0..size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        file
    }

    async fn setup_test_server() -> (ConcurrentServer, Vec<FileChunk>) {
        let publisher_config = PublisherConfig::default();
        let publisher = DataPacketPublisher::new(publisher_config);
        
        // Create test file and chunks
        let test_file = create_test_file(5000);
        let chunking_config = ChunkingConfig::for_quic();
        let mut chunker = FileChunker::new(chunking_config);
        
        let base_name = Name::from_str("/test/file");
        let chunks = chunker.chunk_file(test_file.path(), &base_name).unwrap()
            .collect::<Result<Vec<_>, _>>().unwrap();
        
        // Publish chunks
        publisher.publish_chunks(chunks.clone()).await.unwrap();
        
        let server_config = ConcurrentServerConfig::default();
        let server = ConcurrentServer::new(server_config, publisher);
        
        (server, chunks)
    }

    #[tokio::test]
    async fn test_server_creation() {
        let publisher = DataPacketPublisher::default();
        let config = ConcurrentServerConfig::default();
        let server = ConcurrentServer::new(config, publisher);
        
        assert!(!server.is_running());
        assert_eq!(server.get_config().max_concurrent_requests, 1000);
    }

    #[tokio::test]
    async fn test_server_start_stop() {
        let publisher = DataPacketPublisher::default();
        let mut server = ConcurrentServer::with_default_config(publisher);
        
        // Start server
        let result = server.start().await;
        assert!(result.is_ok());
        assert!(server.is_running());
        
        // Stop server
        let result = server.stop().await;
        assert!(result.is_ok());
        assert!(!server.is_running());
    }

    #[tokio::test]
    async fn test_config_variants() {
        let file_config = ConcurrentServerConfig::for_file_transfer();
        assert_eq!(file_config.max_concurrent_requests, 2000);
        assert!(file_config.enable_deduplication);
        
        let streaming_config = ConcurrentServerConfig::for_streaming();
        assert_eq!(streaming_config.request_timeout, Duration::from_secs(5));
        assert!(!streaming_config.enable_deduplication);
        
        let low_mem_config = ConcurrentServerConfig::for_low_memory();
        assert_eq!(low_mem_config.max_concurrent_requests, 100);
        assert_eq!(low_mem_config.max_worker_threads, 2);
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let (server, _) = setup_test_server().await;
        
        let stats = server.get_stats().await;
        assert_eq!(stats.requests_received, 0);
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.throughput_mbps(), 0.0);
    }

    #[tokio::test]
    async fn test_request_context() {
        let interest = Interest::new(Name::from_str("/test/file/segment/0"));
        let context = RequestContext::new(interest.clone(), Some("client1".to_string()));
        
        assert_eq!(context.interest.name, interest.name);
        assert_eq!(context.client_id, Some("client1".to_string()));
        assert!(!context.request_id.is_empty());
        assert_eq!(context.dedup_key(), "/test/file/segment/0");
    }

    #[tokio::test]
    async fn test_dedup_cache_entry() {
        let response = RequestResponse {
            request_id: "test_123".to_string(),
            data: None,
            processing_time: Duration::from_millis(10),
            cache_hit: false,
            error: None,
        };
        
        let entry = DedupCacheEntry {
            response,
            created_at: SystemTime::now(),
        };
        
        assert!(!entry.is_expired(Duration::from_secs(60)));
        
        let old_entry = DedupCacheEntry {
            response: entry.response.clone(),
            created_at: SystemTime::now() - Duration::from_secs(120),
        };
        
        assert!(old_entry.is_expired(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_server_stats_calculations() {
        let mut stats = ServerStats::default();
        stats.requests_processed = 80;
        stats.requests_failed = 15;
        stats.requests_timeout = 5;
        stats.bytes_served = 1024 * 1024 * 10; // 10 MB
        stats.uptime_seconds = 10;
        
        assert_eq!(stats.success_rate(), 0.8); // 80/100
        assert_eq!(stats.throughput_mbps(), 1.0); // 10MB / 10s
    }

    #[tokio::test]
    async fn test_error_types() {
        let resource_error = ConcurrentServerError::ResourceUnavailable("Test".to_string());
        assert!(resource_error.to_string().contains("Resource unavailable"));
        
        let channel_error = ConcurrentServerError::ChannelError("Test".to_string());
        assert!(channel_error.to_string().contains("Channel error"));
        
        let timeout_error = ConcurrentServerError::RequestTimeout("Test".to_string());
        assert!(timeout_error.to_string().contains("Request timeout"));
    }
}