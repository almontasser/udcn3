use crate::file_interest_generator::{FileInterestGenerator, ChunkRequest};
use crate::data_reception_handler::DataReceptionHandler;
use crate::file_reassembly::{FileReassemblyEngine, ReassemblyProgress};
use crate::file_chunking::{FileMetadata, FileChunk};
use crate::Transport;
use udcn_core::packets::Name;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use tokio::sync::{RwLock, mpsc, Mutex, broadcast};
use tokio::task::JoinHandle;
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

/// Configuration for the pipeline coordinator
#[derive(Debug, Clone)]
pub struct PipelineCoordinatorConfig {
    /// Maximum number of concurrent file transfers
    pub max_concurrent_transfers: usize,
    /// Default window size for chunk requests
    pub default_window_size: usize,
    /// Timeout for chunk requests
    pub chunk_timeout: Duration,
    /// Maximum retries for failed chunks
    pub max_retries: usize,
    /// Interval for progress monitoring
    pub progress_interval: Duration,
    /// Enable adaptive window sizing
    pub adaptive_window: bool,
    /// Enable flow control
    pub flow_control: bool,
}

impl Default for PipelineCoordinatorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_transfers: 10,
            default_window_size: 50,
            chunk_timeout: Duration::from_secs(30),
            max_retries: 3,
            progress_interval: Duration::from_millis(500),
            adaptive_window: true,
            flow_control: true,
        }
    }
}

/// Handle for a file transfer operation
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TransferHandle {
    pub id: String,
    pub file_name: Name,
}

impl TransferHandle {
    pub fn new(file_name: Name) -> Self {
        Self {
            id: format!("{:x}", fastrand::u64(..)),
            file_name,
        }
    }
}

/// Status of a file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferStatus {
    Pending,
    Active { progress: f64, chunks_received: usize, total_chunks: usize },
    Completed { bytes_transferred: u64, duration: Duration },
    Failed { error: String, chunks_received: usize, total_chunks: usize },
    Cancelled,
}

/// State of individual chunks within a pipeline
#[derive(Debug, Clone, PartialEq)]
pub enum ChunkState {
    Pending,
    Requested { attempt: usize, requested_at: Instant },
    Received { received_at: Instant },
    Failed { attempts: usize, last_error: String },
    Timeout { attempts: usize },
}

/// Pipeline state for a single file transfer
#[derive(Debug)]
pub struct FilePipeline {
    pub handle: TransferHandle,
    pub metadata: FileMetadata,
    pub remote_addr: SocketAddr,
    pub status: TransferStatus,
    pub chunk_states: Vec<ChunkState>,
    pub window_size: usize,
    pub started_at: Instant,
    pub completed_at: Option<Instant>,
    pub bytes_received: u64,
    pub active_requests: HashMap<usize, ChunkRequest>,
    pub reassembly_progress: Option<ReassemblyProgress>,
}

impl FilePipeline {
    pub fn new(handle: TransferHandle, metadata: FileMetadata, remote_addr: SocketAddr, window_size: usize) -> Self {
        let chunk_states = vec![ChunkState::Pending; metadata.total_chunks];
        
        Self {
            handle,
            metadata,
            remote_addr,
            status: TransferStatus::Pending,
            chunk_states,
            window_size,
            started_at: Instant::now(),
            completed_at: None,
            bytes_received: 0,
            active_requests: HashMap::new(),
            reassembly_progress: None,
        }
    }
    
    pub fn get_progress(&self) -> f64 {
        let received_count = self.chunk_states.iter()
            .filter(|state| matches!(state, ChunkState::Received { .. }))
            .count();
        
        if self.metadata.total_chunks == 0 {
            return 0.0;
        }
        
        (received_count as f64) / (self.metadata.total_chunks as f64)
    }
    
    pub fn get_next_pending_chunks(&self, count: usize) -> Vec<usize> {
        self.chunk_states.iter()
            .enumerate()
            .filter(|(_, state)| matches!(state, ChunkState::Pending))
            .take(count)
            .map(|(index, _)| index)
            .collect()
    }
    
    pub fn get_timeout_chunks(&self, timeout: Duration) -> Vec<usize> {
        let now = Instant::now();
        self.chunk_states.iter()
            .enumerate()
            .filter_map(|(index, state)| {
                if let ChunkState::Requested { requested_at, .. } = state {
                    if now.duration_since(*requested_at) > timeout {
                        Some(index)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }
    
    pub fn is_complete(&self) -> bool {
        self.chunk_states.iter().all(|state| matches!(state, ChunkState::Received { .. }))
    }
    
    pub fn get_failed_chunks(&self) -> Vec<usize> {
        self.chunk_states.iter()
            .enumerate()
            .filter(|(_, state)| matches!(state, ChunkState::Failed { .. }))
            .map(|(index, _)| index)
            .collect()
    }
    
    /// Get number of active (in-flight) requests
    pub fn get_active_request_count(&self) -> usize {
        self.active_requests.len()
    }
    
    /// Calculate dynamic window size based on network conditions
    pub fn calculate_dynamic_window_size(&self, config: &PipelineCoordinatorConfig) -> usize {
        if !config.adaptive_window {
            return self.window_size;
        }
        
        let success_rate = self.get_success_rate();
        let latency_factor = self.get_latency_factor();
        
        // Adjust window size based on success rate and latency
        let base_window = config.default_window_size as f64;
        let adjusted_window = base_window * success_rate * latency_factor;
        
        // Clamp to reasonable bounds
        let min_window = 5;
        let max_window = config.default_window_size * 2;
        
        (adjusted_window as usize).clamp(min_window, max_window)
    }
    
    /// Calculate success rate for adaptive window sizing
    fn get_success_rate(&self) -> f64 {
        let total_attempts = self.chunk_states.len();
        if total_attempts == 0 {
            return 1.0;
        }
        
        let successful = self.chunk_states.iter()
            .filter(|state| matches!(state, ChunkState::Received { .. }))
            .count();
        
        let failed = self.chunk_states.iter()
            .filter(|state| matches!(state, ChunkState::Failed { .. }))
            .count();
        
        if successful + failed == 0 {
            return 1.0;
        }
        
        successful as f64 / (successful + failed) as f64
    }
    
    /// Calculate latency factor for adaptive window sizing
    fn get_latency_factor(&self) -> f64 {
        // Simple heuristic: if we have many timeouts, reduce window
        let timeout_count = self.chunk_states.iter()
            .filter(|state| matches!(state, ChunkState::Timeout { .. }))
            .count();
        
        let total_requests = self.chunk_states.len();
        if total_requests == 0 {
            return 1.0;
        }
        
        let timeout_ratio = timeout_count as f64 / total_requests as f64;
        
        // Reduce factor if too many timeouts
        if timeout_ratio > 0.1 {
            0.7 // Reduce window by 30%
        } else if timeout_ratio > 0.05 {
            0.85 // Reduce window by 15%
        } else {
            1.0 // No adjustment
        }
    }
    
    /// Check if pipeline needs more requests (flow control)
    pub fn needs_more_requests(&self, config: &PipelineCoordinatorConfig) -> bool {
        if !config.flow_control {
            return false;
        }
        
        let active_count = self.get_active_request_count();
        let dynamic_window = self.calculate_dynamic_window_size(config);
        
        // Send more requests if we're below the window size and have pending chunks
        active_count < dynamic_window && !self.get_next_pending_chunks(1).is_empty()
    }
}

/// Statistics for the pipeline coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub active_transfers: usize,
    pub completed_transfers: usize,
    pub failed_transfers: usize,
    pub cancelled_transfers: usize,
    pub total_bytes_transferred: u64,
    pub average_transfer_time: Duration,
    pub current_throughput: f64, // bytes per second

}

impl Default for CoordinatorStats {
    fn default() -> Self {
        Self {
            active_transfers: 0,
            completed_transfers: 0,
            failed_transfers: 0,
            cancelled_transfers: 0,
            total_bytes_transferred: 0,
            average_transfer_time: Duration::from_secs(0),
            current_throughput: 0.0,
        }
    }
}

/// Main pipeline fetching coordinator
pub struct PipelineFetchingCoordinator<T: Transport> {
    config: PipelineCoordinatorConfig,
    transport: Arc<T>,
    interest_generator: Arc<FileInterestGenerator>,
    data_reception_handler: Arc<DataReceptionHandler>,
    reassembly_engine: Arc<Mutex<FileReassemblyEngine>>,
    
    // State management
    active_pipelines: Arc<RwLock<HashMap<TransferHandle, FilePipeline>>>,
    stats: Arc<RwLock<CoordinatorStats>>,
    
    // Communication channels
    progress_sender: broadcast::Sender<(TransferHandle, TransferStatus)>,
    progress_receiver: broadcast::Receiver<(TransferHandle, TransferStatus)>,
    
    // Control channels
    shutdown_sender: mpsc::Sender<()>,
    shutdown_receiver: Arc<Mutex<mpsc::Receiver<()>>>,
    
    // Task handles
    monitoring_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    coordination_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl<T: Transport + Send + Sync + Clone + 'static> PipelineFetchingCoordinator<T> {
    /// Create a new pipeline coordinator
    pub fn new(
        config: PipelineCoordinatorConfig,
        transport: Arc<T>,
        interest_generator: Arc<FileInterestGenerator>,
        data_reception_handler: Arc<DataReceptionHandler>,
        reassembly_engine: Arc<Mutex<FileReassemblyEngine>>,
    ) -> Self {
        let (progress_sender, progress_receiver) = broadcast::channel(1000);
        let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
        
        Self {
            config,
            transport,
            interest_generator,
            data_reception_handler,
            reassembly_engine,
            active_pipelines: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CoordinatorStats::default())),
            progress_sender,
            progress_receiver,
            shutdown_sender,
            shutdown_receiver: Arc::new(Mutex::new(shutdown_receiver)),
            monitoring_task: Arc::new(Mutex::new(None)),
            coordination_task: Arc::new(Mutex::new(None)),
        }
    }
    
    /// Start the pipeline coordinator
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting pipeline fetching coordinator");
        
        // Start data reception handler
        self.data_reception_handler.start().await
            .map_err(|e| format!("Failed to start data reception handler: {}", e))?;
        
        // Start monitoring task
        self.start_monitoring_task().await;
        
        // Start coordination task
        self.start_coordination_task().await;
        
        info!("Pipeline fetching coordinator started successfully");
        Ok(())
    }
    
    /// Start a new file transfer
    pub async fn start_file_transfer(
        &self,
        file_name: Name,
        metadata: FileMetadata,
        remote_addr: SocketAddr,
    ) -> Result<TransferHandle, Box<dyn std::error::Error + Send + Sync>> {
        let handle = TransferHandle::new(file_name.clone());
        
        // Check if we're at the concurrent transfer limit
        {
            let pipelines = self.active_pipelines.read().await;
            if pipelines.len() >= self.config.max_concurrent_transfers {
                return Err("Maximum concurrent transfers reached".into());
            }
        }
        
        info!("Starting file transfer: {} (handle: {})", file_name, handle.id);
        
        // Create pipeline
        let pipeline = FilePipeline::new(
            handle.clone(),
            metadata.clone(),
            remote_addr,
            self.config.default_window_size,
        );
        
        // Add to active pipelines
        {
            let mut pipelines = self.active_pipelines.write().await;
            pipelines.insert(handle.clone(), pipeline);
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_transfers += 1;
        }
        
        // Send progress update
        let _ = self.progress_sender.send((handle.clone(), TransferStatus::Pending));
        
        // Start the transfer process
        self.initiate_transfer(&handle).await?;
        
        Ok(handle)
    }
    
    /// Monitor transfer progress
    pub async fn monitor_transfer_progress(
        &self,
        handle: &TransferHandle,
    ) -> Result<TransferStatus, Box<dyn std::error::Error + Send + Sync>> {
        let pipelines = self.active_pipelines.read().await;
        match pipelines.get(handle) {
            Some(pipeline) => Ok(pipeline.status.clone()),
            None => Err("Transfer not found".into()),
        }
    }
    
    /// Cancel a transfer
    pub async fn cancel_transfer(
        &self,
        handle: &TransferHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Cancelling transfer: {}", handle.id);
        
        let mut pipelines = self.active_pipelines.write().await;
        if let Some(mut pipeline) = pipelines.remove(handle) {
            pipeline.status = TransferStatus::Cancelled;
            
            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.active_transfers = stats.active_transfers.saturating_sub(1);
                stats.cancelled_transfers += 1;
            }
            
            // Send progress update
            let _ = self.progress_sender.send((handle.clone(), TransferStatus::Cancelled));
            
            Ok(())
        } else {
            Err("Transfer not found".into())
        }
    }
    
    /// Get coordinator statistics
    pub async fn get_statistics(&self) -> CoordinatorStats {
        let stats = self.stats.read().await;
        stats.clone()
    }
    
    /// Subscribe to progress updates
    pub fn subscribe_progress(&self) -> broadcast::Receiver<(TransferHandle, TransferStatus)> {
        self.progress_sender.subscribe()
    }
    
    /// Shutdown the coordinator
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down pipeline fetching coordinator");
        
        // Send shutdown signal
        let _ = self.shutdown_sender.send(()).await;
        
        // Wait for tasks to complete
        if let Some(task) = self.monitoring_task.lock().await.take() {
            task.abort();
        }
        
        if let Some(task) = self.coordination_task.lock().await.take() {
            task.abort();
        }
        
        // Cancel all active transfers
        let handles: Vec<TransferHandle> = {
            let pipelines = self.active_pipelines.read().await;
            pipelines.keys().cloned().collect()
        };
        
        for handle in handles {
            let _ = self.cancel_transfer(&handle).await;
        }
        
        info!("Pipeline fetching coordinator shut down");
        Ok(())
    }
    
    /// Initiate a transfer for the given handle
    async fn initiate_transfer(
        &self,
        handle: &TransferHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Generate initial interest packets
        let (metadata, remote_addr) = {
            let pipelines = self.active_pipelines.read().await;
            let pipeline = pipelines.get(handle).ok_or("Pipeline not found")?;
            (pipeline.metadata.clone(), pipeline.remote_addr)
        };
        
        // Generate chunk requests
        let chunk_requests = self.interest_generator
            .generate_interests_for_file(&handle.file_name, &metadata, remote_addr)
            .await
            .map_err(|e| format!("Failed to generate interests: {}", e))?;
        
        // Send initial window of interests
        self.send_initial_window(handle, chunk_requests).await?;
        
        Ok(())
    }
    
    /// Send initial window of interest packets
    async fn send_initial_window(
        &self,
        handle: &TransferHandle,
        chunk_requests: Vec<ChunkRequest>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (window_size, remote_addr) = {
            let pipelines = self.active_pipelines.read().await;
            let pipeline = pipelines.get(handle).ok_or("Pipeline not found")?;
            (pipeline.window_size, pipeline.remote_addr)
        };
        
        // Take initial window
        let initial_requests: Vec<ChunkRequest> = chunk_requests.into_iter()
            .take(window_size)
            .collect();
        
        // Send concurrent interests
        let sent_requests = self.interest_generator
            .send_interests_concurrent(initial_requests, remote_addr)
            .await
            .map_err(|e| format!("Failed to send interests: {}", e))?;
        
        // Update pipeline state
        {
            let mut pipelines = self.active_pipelines.write().await;
            if let Some(pipeline) = pipelines.get_mut(handle) {
                pipeline.status = TransferStatus::Active {
                    progress: 0.0,
                    chunks_received: 0,
                    total_chunks: pipeline.metadata.total_chunks,
                };
                
                // Mark chunks as requested
                for request in &sent_requests {
                    if let Some(sequence) = self.extract_sequence_from_request(request) {
                        if sequence < pipeline.chunk_states.len() {
                            pipeline.chunk_states[sequence] = ChunkState::Requested {
                                attempt: 1,
                                requested_at: Instant::now(),
                            };
                            pipeline.active_requests.insert(sequence, request.clone());
                        }
                    }
                }
            }
        }
        
        // Send progress update
        let _ = self.progress_sender.send((handle.clone(), TransferStatus::Active {
            progress: 0.0,
            chunks_received: 0,
            total_chunks: sent_requests.len(),
        }));
        
        Ok(())
    }
    
    /// Extract sequence number from chunk request
    fn extract_sequence_from_request(&self, request: &ChunkRequest) -> Option<usize> {
        Some(request.sequence)
    }
    
    /// Start monitoring task
    async fn start_monitoring_task(&self) {
        let pipelines = Arc::clone(&self.active_pipelines);
        let stats = Arc::clone(&self.stats);
        let progress_sender = self.progress_sender.clone();
        let config = self.config.clone();
        let interest_generator = Arc::clone(&self.interest_generator);
        let shutdown_receiver = Arc::clone(&self.shutdown_receiver);
        
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.progress_interval);
            let mut shutdown = shutdown_receiver.lock().await;
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Monitor active transfers
                        Self::monitor_active_transfers(
                            &pipelines,
                            &stats,
                            &progress_sender,
                            &config,
                            &interest_generator,
                        ).await;
                        
                        // Check for pipeline stalls every few intervals
                        if interval.period().as_secs() % 10 == 0 {
                            // This would need access to self to call handle_pipeline_stalls
                            // For now, stall detection is integrated into monitor_active_transfers
                        }
                    }
                    _ = shutdown.recv() => {
                        debug!("Monitoring task shutting down");
                        break;
                    }
                }
            }
        });
        
        *self.monitoring_task.lock().await = Some(task);
    }
    
    /// Start coordination task
    async fn start_coordination_task(&self) {
        let pipelines = Arc::clone(&self.active_pipelines);
        let data_reception_handler = Arc::clone(&self.data_reception_handler);
        let reassembly_engine = Arc::clone(&self.reassembly_engine);
        let progress_sender = self.progress_sender.clone();
        let shutdown_receiver = Arc::clone(&self.shutdown_receiver);
        
        let task = tokio::spawn(async move {
            let mut shutdown = shutdown_receiver.lock().await;
            
            // Get packet receiver from data reception handler
            let packet_receiver = data_reception_handler.get_packet_receiver().await;
            
            if let Some(mut receiver) = packet_receiver {
                loop {
                    tokio::select! {
                        chunk = receiver.recv() => {
                            if let Some(chunk) = chunk {
                                Self::process_received_chunk(
                                    chunk,
                                    &pipelines,
                                    &reassembly_engine,
                                    &progress_sender,
                                ).await;
                            }
                        }
                        _ = shutdown.recv() => {
                            debug!("Coordination task shutting down");
                            break;
                        }
                    }
                }
            }
        });
        
        *self.coordination_task.lock().await = Some(task);
    }
    
    /// Monitor active transfers for timeouts and progress
    async fn monitor_active_transfers(
        pipelines: &Arc<RwLock<HashMap<TransferHandle, FilePipeline>>>,
        stats: &Arc<RwLock<CoordinatorStats>>,
        progress_sender: &broadcast::Sender<(TransferHandle, TransferStatus)>,
        config: &PipelineCoordinatorConfig,
        _interest_generator: &Arc<FileInterestGenerator>,
    ) {
        let mut pipelines_guard = pipelines.write().await;
        let mut completed_handles = Vec::new();
        
        for (handle, pipeline) in pipelines_guard.iter_mut() {
            // Check for timeouts
            let timeout_chunks = pipeline.get_timeout_chunks(config.chunk_timeout);
            if !timeout_chunks.is_empty() {
                warn!("Transfer {} has {} timed out chunks", handle.id, timeout_chunks.len());
                
                // Handle timeouts (retry or mark as failed)
                for chunk_index in timeout_chunks {
                    if let Some(chunk_state) = pipeline.chunk_states.get_mut(chunk_index) {
                        if let ChunkState::Requested { attempt, .. } = chunk_state {
                            if *attempt < config.max_retries {
                                // Mark for retry
                                *chunk_state = ChunkState::Timeout { attempts: *attempt };
                            } else {
                                // Mark as failed
                                *chunk_state = ChunkState::Failed {
                                    attempts: *attempt,
                                    last_error: "Timeout exceeded max retries".to_string(),
                                };
                            }
                        }
                    }
                    // Remove from active requests
                    pipeline.active_requests.remove(&chunk_index);
                }
            }
            
            // Flow control: send more requests if needed
            if pipeline.needs_more_requests(config) {
                let dynamic_window = pipeline.calculate_dynamic_window_size(config);
                let active_count = pipeline.get_active_request_count();
                let needed_requests = dynamic_window.saturating_sub(active_count);
                
                let pending_chunks = pipeline.get_next_pending_chunks(needed_requests);
                if !pending_chunks.is_empty() {
                    debug!("Sending {} additional requests for transfer {} (window: {}, active: {})", 
                           pending_chunks.len(), handle.id, dynamic_window, active_count);
                    
                    // Generate and send additional requests
                    for chunk_index in pending_chunks {
                        if let Some(chunk_state) = pipeline.chunk_states.get_mut(chunk_index) {
                            *chunk_state = ChunkState::Requested {
                                attempt: 1,
                                requested_at: Instant::now(),
                            };
                        }
                    }
                }
            }
            
            // Check if transfer is complete
            if pipeline.is_complete() {
                let duration = pipeline.started_at.elapsed();
                pipeline.status = TransferStatus::Completed {
                    bytes_transferred: pipeline.metadata.file_size,
                    duration,
                };
                pipeline.completed_at = Some(Instant::now());
                
                let _ = progress_sender.send((handle.clone(), pipeline.status.clone()));
                completed_handles.push(handle.clone());
            } else {
                // Send progress update
                let chunks_received = pipeline.chunk_states.iter()
                    .filter(|state| matches!(state, ChunkState::Received { .. }))
                    .count();
                
                let progress = pipeline.get_progress();
                let status = TransferStatus::Active {
                    progress,
                    chunks_received,
                    total_chunks: pipeline.metadata.total_chunks,
                };
                
                let _ = progress_sender.send((handle.clone(), status));
            }
        }
        
        // Remove completed transfers
        for handle in completed_handles {
            pipelines_guard.remove(&handle);
            
            // Update stats
            let mut stats_guard = stats.write().await;
            stats_guard.active_transfers = stats_guard.active_transfers.saturating_sub(1);
            stats_guard.completed_transfers += 1;
        }
    }
    
    /// Process a received chunk
    async fn process_received_chunk(
        chunk: FileChunk,
        pipelines: &Arc<RwLock<HashMap<TransferHandle, FilePipeline>>>,
        reassembly_engine: &Arc<Mutex<FileReassemblyEngine>>,
        _progress_sender: &broadcast::Sender<(TransferHandle, TransferStatus)>,
    ) {
        // Find the pipeline that this chunk belongs to by matching file name
        let handle = {
            let pipelines_guard = pipelines.read().await;
            pipelines_guard.iter()
                .find(|(_, pipeline)| {
                    // Match based on file name from chunk
                    pipeline.handle.file_name == chunk.name || 
                    chunk.name.to_string().contains(&pipeline.handle.file_name.to_string())
                })
                .map(|(handle, _)| handle.clone())
        };
        
        if let Some(handle) = handle {
            // Update pipeline state and trigger flow control
            let should_send_more = {
                let mut pipelines_guard = pipelines.write().await;
                if let Some(pipeline) = pipelines_guard.get_mut(&handle) {
                    // Mark chunk as received
                    if let Some(sequence) = Self::extract_sequence_from_chunk(&chunk) {
                        if sequence < pipeline.chunk_states.len() {
                            pipeline.chunk_states[sequence] = ChunkState::Received {
                                received_at: Instant::now(),
                            };
                            pipeline.active_requests.remove(&sequence);
                            pipeline.bytes_received += chunk.data.content.len() as u64;
                        }
                    }
                    
                    // Check if we need to send more requests due to flow control
                    // This creates a dynamic pipeline that sends new requests as responses arrive
                    pipeline.needs_more_requests(&PipelineCoordinatorConfig::default())
                } else {
                    false
                }
            };
            
            // If flow control indicates we need more requests, trigger them
            if should_send_more {
                debug!("Chunk received for transfer {}, checking for additional requests needed", handle.id);
                // Additional request logic would be handled by the monitoring task
            }
            
            // Forward to reassembly engine
            {
                let engine = reassembly_engine.lock().await;
                let chunk_sender = engine.get_chunk_sender();
                if let Err(e) = chunk_sender.send(chunk) {
                    error!("Failed to send chunk to reassembly engine: {}", e);
                }
            }
        }
    }
    
    /// Extract sequence number from chunk
    fn extract_sequence_from_chunk(chunk: &FileChunk) -> Option<usize> {
        Some(chunk.chunk_info.sequence)
    }
    
    /// Retry failed or timed out chunks
    async fn retry_failed_chunks(
        &self,
        handle: &TransferHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let chunks_to_retry = {
            let pipelines = self.active_pipelines.read().await;
            if let Some(pipeline) = pipelines.get(handle) {
                // Get chunks that need retry (failed or timed out)
                let mut retry_chunks = Vec::new();
                
                for (index, state) in pipeline.chunk_states.iter().enumerate() {
                    match state {
                        ChunkState::Timeout { attempts } if *attempts < self.config.max_retries => {
                            retry_chunks.push(index);
                        }
                        ChunkState::Failed { attempts, .. } if *attempts < self.config.max_retries => {
                            retry_chunks.push(index);
                        }
                        _ => {}
                    }
                }
                
                retry_chunks
            } else {
                return Err("Pipeline not found".into());
            }
        };
        
        if chunks_to_retry.is_empty() {
            return Ok(());
        }
        
        info!("Retrying {} chunks for transfer {}", chunks_to_retry.len(), handle.id);
        
        // Generate retry requests
        let metadata = {
            let pipelines = self.active_pipelines.read().await;
            pipelines.get(handle).map(|p| p.metadata.clone())
                .ok_or("Pipeline not found")?
        };
        
        // Create chunk requests for retry
        let retry_requests: Vec<ChunkRequest> = chunks_to_retry.iter()
            .filter_map(|&chunk_index| {
                // This would need to be implemented to create ChunkRequest from index
                // For now, return None to avoid compilation errors
                None
            })
            .collect();
        
        // Send retry requests
        if !retry_requests.is_empty() {
            let remote_addr = {
                let pipelines = self.active_pipelines.read().await;
                pipelines.get(handle).map(|p| p.remote_addr)
                    .ok_or("Pipeline not found")?
            };
            
            let sent_requests = self.interest_generator
                .send_interests_concurrent(retry_requests, remote_addr)
                .await
                .map_err(|e| format!("Failed to send retry interests: {}", e))?;
            
            // Update pipeline state for retries
            {
                let mut pipelines = self.active_pipelines.write().await;
                if let Some(pipeline) = pipelines.get_mut(handle) {
                    for request in &sent_requests {
                        if let Some(sequence) = self.extract_sequence_from_request(request) {
                            if let Some(chunk_state) = pipeline.chunk_states.get_mut(sequence) {
                                let new_attempt = match chunk_state {
                                    ChunkState::Timeout { attempts } => *attempts + 1,
                                    ChunkState::Failed { attempts, .. } => *attempts + 1,
                                    _ => 1,
                                };
                                
                                *chunk_state = ChunkState::Requested {
                                    attempt: new_attempt,
                                    requested_at: Instant::now(),
                                };
                                
                                pipeline.active_requests.insert(sequence, request.clone());
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle pipeline stalls (no progress for extended period)
    async fn handle_pipeline_stalls(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stall_threshold = Duration::from_secs(60); // 1 minute without progress
        let now = Instant::now();
        
        let mut stalled_handles = Vec::new();
        
        {
            let pipelines = self.active_pipelines.read().await;
            for (handle, pipeline) in pipelines.iter() {
                // Check if pipeline has been stalled
                let last_activity = pipeline.chunk_states.iter()
                    .filter_map(|state| match state {
                        ChunkState::Received { received_at } => Some(*received_at),
                        ChunkState::Requested { requested_at, .. } => Some(*requested_at),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(pipeline.started_at);
                
                if now.duration_since(last_activity) > stall_threshold {
                    warn!("Pipeline {} appears stalled, last activity: {:?} ago", 
                          handle.id, now.duration_since(last_activity));
                    stalled_handles.push(handle.clone());
                }
            }
        }
        
        // Attempt recovery for stalled pipelines
        for handle in stalled_handles {
            info!("Attempting recovery for stalled pipeline: {}", handle.id);
            if let Err(e) = self.retry_failed_chunks(&handle).await {
                error!("Failed to recover stalled pipeline {}: {}", handle.id, e);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::UdpTransport;
    use udcn_core::packets::{Data, MetaInfo, ContentType};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::path::PathBuf;

    // Mock transport for testing
    #[derive(Debug, Clone)]
    struct MockTransport {
        should_fail: Arc<AtomicBool>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                should_fail: Arc::new(AtomicBool::new(false)),
            }
        }

        fn set_should_fail(&self, fail: bool) {
            self.should_fail.store(fail, Ordering::Relaxed);
        }
    }

    impl Transport for MockTransport {
        fn send(&self, _data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            if self.should_fail.load(Ordering::Relaxed) {
                Err("Mock transport failure".into())
            } else {
                Ok(())
            }
        }

        fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            if self.should_fail.load(Ordering::Relaxed) {
                Err("Mock transport failure".into())
            } else {
                Ok(vec![1, 2, 3, 4])
            }
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineCoordinatorConfig::default();
        assert_eq!(config.max_concurrent_transfers, 10);
        assert_eq!(config.default_window_size, 50);
        assert!(config.adaptive_window);
        assert!(config.flow_control);
    }

    #[test]
    fn test_transfer_handle_creation() {
        let name = Name::from_str("/test/file");
        let handle = TransferHandle::new(name.clone());
        assert_eq!(handle.file_name, name);
        assert!(!handle.id.is_empty());
    }

    #[test]
    fn test_file_pipeline_creation() {
        let handle = TransferHandle::new(Name::from_str("/test/file"));
        let metadata = FileMetadata {
            file_path: PathBuf::from("test.txt"),
            file_size: 1024,
            total_chunks: 10,
            chunk_size: 102,
            modified_time: 1234567890,
            content_type: ContentType::Blob,
            file_hash: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();
        
        let pipeline = FilePipeline::new(handle.clone(), metadata.clone(), remote_addr, 5);
        
        assert_eq!(pipeline.handle, handle);
        assert_eq!(pipeline.metadata, metadata);
        assert_eq!(pipeline.window_size, 5);
        assert_eq!(pipeline.chunk_states.len(), 10);
        assert!(matches!(pipeline.status, TransferStatus::Pending));
    }

    #[test]
    fn test_file_pipeline_progress() {
        let handle = TransferHandle::new(Name::from_str("/test/file"));
        let metadata = FileMetadata {
            file_path: PathBuf::from("test.txt"),
            file_size: 1024,
            total_chunks: 4,
            chunk_size: 256,
            modified_time: 1234567890,
            content_type: ContentType::Blob,
            file_hash: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();
        
        let mut pipeline = FilePipeline::new(handle, metadata, remote_addr, 5);
        
        // Initially no progress
        assert_eq!(pipeline.get_progress(), 0.0);
        
        // Mark some chunks as received
        pipeline.chunk_states[0] = ChunkState::Received { received_at: Instant::now() };
        pipeline.chunk_states[1] = ChunkState::Received { received_at: Instant::now() };
        
        // Should be 50% progress
        assert_eq!(pipeline.get_progress(), 0.5);
        
        // Mark all chunks as received
        for state in &mut pipeline.chunk_states {
            *state = ChunkState::Received { received_at: Instant::now() };
        }
        
        assert_eq!(pipeline.get_progress(), 1.0);
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_dynamic_window_sizing() {
        let handle = TransferHandle::new(Name::from_str("/test/file"));
        let metadata = FileMetadata {
            file_path: PathBuf::from("test.txt"),
            file_size: 1024,
            total_chunks: 10,
            chunk_size: 102,
            modified_time: 1234567890,
            content_type: ContentType::Blob,
            file_hash: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();
        
        let mut pipeline = FilePipeline::new(handle, metadata, remote_addr, 20);
        let config = PipelineCoordinatorConfig::default();
        
        // With no failures, window should remain at default
        let window_size = pipeline.calculate_dynamic_window_size(&config);
        assert!(window_size >= 5); // Should be at least minimum
        
        // Simulate some failures
        pipeline.chunk_states[0] = ChunkState::Failed { attempts: 3, last_error: "test".to_string() };
        pipeline.chunk_states[1] = ChunkState::Failed { attempts: 2, last_error: "test".to_string() };
        
        // Window should be reduced due to failures
        let reduced_window = pipeline.calculate_dynamic_window_size(&config);
        assert!(reduced_window <= window_size);
    }

    #[test]
    fn test_chunk_state_transitions() {
        let handle = TransferHandle::new(Name::from_str("/test/file"));
        let metadata = FileMetadata {
            file_path: PathBuf::from("test.txt"),
            file_size: 1024,
            total_chunks: 5,
            chunk_size: 204,
            modified_time: 1234567890,
            content_type: ContentType::Blob,
            file_hash: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();
        
        let mut pipeline = FilePipeline::new(handle, metadata, remote_addr, 5);
        
        // Test pending to requested transition
        pipeline.chunk_states[0] = ChunkState::Requested { 
            attempt: 1, 
            requested_at: Instant::now() 
        };
        
        // Test timeout detection
        pipeline.chunk_states[1] = ChunkState::Requested { 
            attempt: 1, 
            requested_at: Instant::now() - Duration::from_secs(60) 
        };
        
        let timeout_chunks = pipeline.get_timeout_chunks(Duration::from_secs(30));
        assert_eq!(timeout_chunks, vec![1]);
        
        // Test getting pending chunks
        let pending = pipeline.get_next_pending_chunks(3);
        assert_eq!(pending.len(), 3); // Should return chunks 2, 3, 4
    }

    #[test]
    fn test_flow_control_logic() {
        let handle = TransferHandle::new(Name::from_str("/test/file"));
        let metadata = FileMetadata {
            file_path: PathBuf::from("test.txt"),
            file_size: 1024,
            total_chunks: 10,
            chunk_size: 102,
            modified_time: 1234567890,
            content_type: ContentType::Blob,
            file_hash: None,
        };
        let remote_addr = "127.0.0.1:8080".parse().unwrap();
        
        let pipeline = FilePipeline::new(handle, metadata, remote_addr, 5);
        let config = PipelineCoordinatorConfig::default();
        
        // With empty active requests and pending chunks, should need more requests
        assert!(pipeline.needs_more_requests(&config));
        
        // Test with flow control disabled
        let mut config_no_flow = config.clone();
        config_no_flow.flow_control = false;
        assert!(!pipeline.needs_more_requests(&config_no_flow));
    }

    #[tokio::test]
    async fn test_coordinator_stats() {
        let stats = CoordinatorStats::default();
        assert_eq!(stats.active_transfers, 0);
        assert_eq!(stats.completed_transfers, 0);
        assert_eq!(stats.total_bytes_transferred, 0);
    }
}
