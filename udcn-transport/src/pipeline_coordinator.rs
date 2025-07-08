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
    
    /// Extract sequence number from chunk request (implementation depends on ChunkRequest structure)
    fn extract_sequence_from_request(&self, _request: &ChunkRequest) -> Option<usize> {
        // This would need to be implemented based on the actual ChunkRequest structure
        // For now, returning None as placeholder
        None
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
        // Find the pipeline that this chunk belongs to
        let handle = {
            let pipelines_guard = pipelines.read().await;
            pipelines_guard.iter()
                .find(|(_, _pipeline)| {
                    // This would need to match based on file name or other identifier
                    // For now, just taking the first active pipeline
                    true
                })
                .map(|(handle, _)| handle.clone())
        };
        
        if let Some(handle) = handle {
            // Update pipeline state
            {
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
                }
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
    
    /// Extract sequence number from chunk (implementation depends on FileChunk structure)
    fn extract_sequence_from_chunk(_chunk: &FileChunk) -> Option<usize> {
        // This would need to be implemented based on the actual FileChunk structure
        // For now, returning None as placeholder
        None
    }
}