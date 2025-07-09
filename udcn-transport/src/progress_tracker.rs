use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use std::fs;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use log::{debug, info, warn, error};

/// Configuration for progress tracking
#[derive(Debug, Clone)]
pub struct ProgressTrackerConfig {
    /// Maximum number of concurrent transfers to track
    pub max_concurrent_transfers: usize,
    /// Progress reporting interval
    pub reporting_interval: Duration,
    /// Whether to enable detailed chunk-level tracking
    pub enable_chunk_tracking: bool,
    /// Maximum number of progress events to buffer
    pub max_event_buffer: usize,
}

impl Default for ProgressTrackerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_transfers: 1000,
            reporting_interval: Duration::from_secs(1),
            enable_chunk_tracking: true,
            max_event_buffer: 10000,
        }
    }
}

/// Unique identifier for a file transfer session
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferSessionId(pub String);

impl TransferSessionId {
    pub fn new(file_name: &str, client_id: &str) -> Self {
        Self(format!("{}_{}", file_name, client_id))
    }
}

/// Current state of a file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferState {
    /// Transfer is being initialized
    Initializing,
    /// Transfer is actively sending chunks
    Active,
    /// Transfer is paused
    Paused,
    /// Transfer was interrupted (network/system failure)
    Interrupted,
    /// Transfer completed successfully
    Completed,
    /// Transfer failed with error
    Failed { error: String },
    /// Transfer was cancelled
    Cancelled,
}

/// Progress event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgressEvent {
    /// Transfer session started
    TransferStarted {
        session_id: TransferSessionId,
        file_name: String,
        file_size: u64,
        total_chunks: u32,
        timestamp: u64,
    },
    /// Chunk was successfully sent
    ChunkSent {
        session_id: TransferSessionId,
        chunk_id: u32,
        chunk_size: u64,
        timestamp: u64,
    },
    /// Chunk send failed
    ChunkFailed {
        session_id: TransferSessionId,
        chunk_id: u32,
        error: String,
        timestamp: u64,
    },
    /// Transfer state changed
    StateChanged {
        session_id: TransferSessionId,
        old_state: TransferState,
        new_state: TransferState,
        timestamp: u64,
    },
    /// Transfer completed
    TransferCompleted {
        session_id: TransferSessionId,
        bytes_sent: u64,
        duration: Duration,
        timestamp: u64,
    },
    /// Transfer failed
    TransferFailed {
        session_id: TransferSessionId,
        error: String,
        bytes_sent: u64,
        timestamp: u64,
    },
    /// Chunk integrity verification started
    IntegrityVerificationStarted {
        session_id: TransferSessionId,
        chunk_id: u32,
        timestamp: u64,
    },
    /// Chunk integrity verification passed
    IntegrityVerificationPassed {
        session_id: TransferSessionId,
        chunk_id: u32,
        timestamp: u64,
    },
    /// Chunk integrity verification failed
    IntegrityVerificationFailed {
        session_id: TransferSessionId,
        chunk_id: u32,
        error: String,
        timestamp: u64,
    },
    /// Chunk corruption detected
    ChunkCorrupted {
        session_id: TransferSessionId,
        chunk_id: u32,
        timestamp: u64,
    },
    /// Chunk recovery started
    RecoveryStarted {
        session_id: TransferSessionId,
        chunk_id: u32,
        attempt: u32,
        timestamp: u64,
    },
    /// Chunk recovery succeeded
    RecoverySucceeded {
        session_id: TransferSessionId,
        chunk_id: u32,
        attempt: u32,
        timestamp: u64,
    },
    /// Chunk recovery failed
    RecoveryFailed {
        session_id: TransferSessionId,
        chunk_id: u32,
        attempt: u32,
        error: String,
        timestamp: u64,
    },
}

impl ProgressEvent {
    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn transfer_started(
        session_id: TransferSessionId,
        file_name: String,
        file_size: u64,
        total_chunks: u32,
    ) -> Self {
        Self::TransferStarted {
            session_id,
            file_name,
            file_size,
            total_chunks,
            timestamp: Self::timestamp(),
        }
    }

    pub fn chunk_sent(session_id: TransferSessionId, chunk_id: u32, chunk_size: u64) -> Self {
        Self::ChunkSent {
            session_id,
            chunk_id,
            chunk_size,
            timestamp: Self::timestamp(),
        }
    }

    pub fn chunk_failed(session_id: TransferSessionId, chunk_id: u32, error: String) -> Self {
        Self::ChunkFailed {
            session_id,
            chunk_id,
            error,
            timestamp: Self::timestamp(),
        }
    }

    pub fn state_changed(
        session_id: TransferSessionId,
        old_state: TransferState,
        new_state: TransferState,
    ) -> Self {
        Self::StateChanged {
            session_id,
            old_state,
            new_state,
            timestamp: Self::timestamp(),
        }
    }

    pub fn transfer_completed(
        session_id: TransferSessionId,
        bytes_sent: u64,
        duration: Duration,
    ) -> Self {
        Self::TransferCompleted {
            session_id,
            bytes_sent,
            duration,
            timestamp: Self::timestamp(),
        }
    }

    pub fn transfer_failed(session_id: TransferSessionId, error: String, bytes_sent: u64) -> Self {
        Self::TransferFailed {
            session_id,
            error,
            bytes_sent,
            timestamp: Self::timestamp(),
        }
    }
}

/// Progress information for a single file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferProgress {
    /// Unique session identifier
    pub session_id: TransferSessionId,
    /// Original file name
    pub file_name: String,
    /// Total file size in bytes
    pub file_size: u64,
    /// Current transfer state
    pub state: TransferState,
    /// Number of chunks sent successfully
    pub chunks_sent: u32,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Transfer start time (not serialized for internal use)
    #[serde(skip, default = "Instant::now")]
    pub start_time: Instant,
    /// Last activity time (not serialized for internal use)
    #[serde(skip, default = "Instant::now")]
    pub last_activity: Instant,
    /// Current transfer rate (bytes per second)
    pub current_rate: f64,
    /// Average transfer rate (bytes per second)
    pub average_rate: f64,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Number of failed chunks
    pub failed_chunks: u32,
    /// Number of retried chunks
    pub retried_chunks: u32,
    /// Client identifier
    pub client_id: Option<String>,
    /// Path to checkpoint file for resume capability
    pub checkpoint_path: Option<String>,
    /// Last checkpoint save time
    #[serde(skip, default = "Instant::now")]
    pub last_checkpoint_time: Instant,
    /// Checkpoint save interval in seconds
    pub checkpoint_interval: u64,
    /// Integrity verification status
    pub integrity_verified: bool,
    /// Number of chunks verified for integrity
    pub chunks_verified: u32,
    /// Number of corrupted chunks detected
    pub corrupted_chunks: u32,
    /// Number of chunks recovered
    pub recovered_chunks: u32,
}

/// Checkpoint data for resuming interrupted transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCheckpoint {
    /// Session identifier
    pub session_id: TransferSessionId,
    /// File name
    pub file_name: String,
    /// File size
    pub file_size: u64,
    /// Total chunks
    pub total_chunks: u32,
    /// Chunks successfully sent
    pub chunks_sent: u32,
    /// Bytes successfully sent
    pub bytes_sent: u64,
    /// Failed chunks to retry
    pub failed_chunks: u32,
    /// Retried chunks count
    pub retried_chunks: u32,
    /// Client identifier
    pub client_id: Option<String>,
    /// Checkpoint creation timestamp
    pub checkpoint_time: std::time::SystemTime,
    /// File hash for integrity verification
    pub file_hash: Option<String>,
    /// Chunk completion bitmap (bit per chunk)
    pub chunk_bitmap: Vec<u8>,
}

impl TransferCheckpoint {
    /// Create a new checkpoint from current progress
    pub fn from_progress(progress: &FileTransferProgress) -> Self {
        let chunk_bitmap = Self::create_chunk_bitmap(progress.total_chunks, progress.chunks_sent);
        
        Self {
            session_id: progress.session_id.clone(),
            file_name: progress.file_name.clone(),
            file_size: progress.file_size,
            total_chunks: progress.total_chunks,
            chunks_sent: progress.chunks_sent,
            bytes_sent: progress.bytes_sent,
            failed_chunks: progress.failed_chunks,
            retried_chunks: progress.retried_chunks,
            client_id: progress.client_id.clone(),
            checkpoint_time: std::time::SystemTime::now(),
            file_hash: None, // Will be set separately
            chunk_bitmap,
        }
    }
    
    /// Create a bitmap representing completed chunks
    fn create_chunk_bitmap(total_chunks: u32, chunks_sent: u32) -> Vec<u8> {
        let bitmap_size = ((total_chunks + 7) / 8) as usize;
        let mut bitmap = vec![0u8; bitmap_size];
        
        // Set bits for completed chunks (simplified - assumes sequential completion)
        for chunk_idx in 0..chunks_sent {
            let byte_idx = (chunk_idx / 8) as usize;
            let bit_idx = chunk_idx % 8;
            if byte_idx < bitmap.len() {
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
        
        bitmap
    }
    
    /// Check if a specific chunk is marked as completed
    pub fn is_chunk_completed(&self, chunk_idx: u32) -> bool {
        let byte_idx = (chunk_idx / 8) as usize;
        let bit_idx = chunk_idx % 8;
        
        if byte_idx >= self.chunk_bitmap.len() {
            return false;
        }
        
        (self.chunk_bitmap[byte_idx] & (1 << bit_idx)) != 0
    }
    
    /// Mark a chunk as completed in the bitmap
    pub fn mark_chunk_completed(&mut self, chunk_idx: u32) {
        let byte_idx = (chunk_idx / 8) as usize;
        let bit_idx = chunk_idx % 8;
        
        if byte_idx < self.chunk_bitmap.len() {
            self.chunk_bitmap[byte_idx] |= 1 << bit_idx;
        }
    }
    
    /// Get the next chunk that needs to be sent
    pub fn get_next_chunk_to_send(&self) -> Option<u32> {
        for chunk_idx in 0..self.total_chunks {
            if !self.is_chunk_completed(chunk_idx) {
                return Some(chunk_idx);
            }
        }
        None
    }
    
    /// Validate checkpoint integrity
    pub fn validate(&self) -> Result<(), String> {
        if self.chunks_sent > self.total_chunks {
            return Err("Chunks sent exceeds total chunks".to_string());
        }
        
        if self.bytes_sent > self.file_size {
            return Err("Bytes sent exceeds file size".to_string());
        }
        
        let expected_bitmap_size = ((self.total_chunks + 7) / 8) as usize;
        if self.chunk_bitmap.len() != expected_bitmap_size {
            return Err("Chunk bitmap size mismatch".to_string());
        }
        
        Ok(())
    }
}

impl FileTransferProgress {
    pub fn new(
        session_id: TransferSessionId,
        file_name: String,
        file_size: u64,
        total_chunks: u32,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            file_name,
            file_size,
            state: TransferState::Initializing,
            chunks_sent: 0,
            total_chunks,
            bytes_sent: 0,
            start_time: now,
            last_activity: now,
            current_rate: 0.0,
            average_rate: 0.0,
            eta: None,
            failed_chunks: 0,
            retried_chunks: 0,
            client_id: None,
            checkpoint_path: None,
            last_checkpoint_time: now,
            checkpoint_interval: 30, // Default 30 seconds
            integrity_verified: false,
            chunks_verified: 0,
            corrupted_chunks: 0,
            recovered_chunks: 0,
        }
    }

    /// Update progress with a sent chunk
    pub fn update_chunk_sent(&mut self, chunk_size: u64) {
        self.chunks_sent += 1;
        self.bytes_sent += chunk_size;
        self.last_activity = Instant::now();
        self.update_rates();
        self.update_eta();
    }

    /// Update progress with a failed chunk
    pub fn update_chunk_failed(&mut self) {
        self.failed_chunks += 1;
        self.last_activity = Instant::now();
    }

    /// Update progress with a retried chunk
    pub fn update_chunk_retried(&mut self) {
        self.retried_chunks += 1;
        self.last_activity = Instant::now();
    }

    /// Update transfer rates with enhanced calculation
    fn update_rates(&mut self) {
        let elapsed = self.start_time.elapsed();
        if elapsed.as_secs() > 0 {
            self.average_rate = self.bytes_sent as f64 / elapsed.as_secs_f64();
        }

        // For current rate, use exponential moving average for better accuracy
        let recent_elapsed = self.last_activity.elapsed();
        if recent_elapsed.as_secs() <= 1 {
            // Recently active - calculate instantaneous rate
            let new_rate = if recent_elapsed.as_secs_f64() > 0.0 {
                // Estimate based on recent activity (simplified)
                self.average_rate
            } else {
                self.average_rate
            };
            
            // Apply exponential smoothing (alpha = 0.3 for responsiveness)
            self.current_rate = 0.3 * new_rate + 0.7 * self.current_rate;
        } else {
            // No recent activity - decay current rate
            self.current_rate *= 0.9;
        }
    }

    /// Update estimated time remaining with enhanced prediction
    fn update_eta(&mut self) {
        let effective_rate = if self.current_rate > 0.0 {
            // Use weighted average of current and average rates
            0.7 * self.current_rate + 0.3 * self.average_rate
        } else {
            self.average_rate
        };

        if effective_rate > 0.0 {
            let remaining_bytes = self.file_size - self.bytes_sent;
            let eta_seconds = remaining_bytes as f64 / effective_rate;
            
            // Add buffer for potential slowdowns (10% extra time)
            let buffered_eta = eta_seconds * 1.1;
            self.eta = Some(Duration::from_secs_f64(buffered_eta));
        } else {
            self.eta = None;
        }
    }

    /// Get progress percentage (0.0 to 1.0)
    pub fn progress_percentage(&self) -> f64 {
        if self.file_size > 0 {
            self.bytes_sent as f64 / self.file_size as f64
        } else {
            0.0
        }
    }

    /// Get chunk-based progress percentage (0.0 to 1.0)
    pub fn chunk_progress_percentage(&self) -> f64 {
        if self.total_chunks > 0 {
            self.chunks_sent as f64 / self.total_chunks as f64
        } else {
            0.0
        }
    }

    /// Get comprehensive progress information
    pub fn get_progress_info(&self) -> ProgressInfo {
        ProgressInfo {
            session_id: self.session_id.clone(),
            file_name: self.file_name.clone(),
            file_size: self.file_size,
            bytes_sent: self.bytes_sent,
            chunks_sent: self.chunks_sent,
            total_chunks: self.total_chunks,
            state: self.state.clone(),
            byte_percentage: self.progress_percentage(),
            chunk_percentage: self.chunk_progress_percentage(),
            current_rate_bps: self.current_rate,
            average_rate_bps: self.average_rate,
            eta: self.eta,
            failed_chunks: self.failed_chunks,
            retried_chunks: self.retried_chunks,
            elapsed_time: self.start_time.elapsed(),
            is_stalled: self.is_stalled(),
            efficiency_ratio: self.get_efficiency_ratio(),
        }
    }

    /// Check if transfer appears stalled (no activity for >30 seconds)
    pub fn is_stalled(&self) -> bool {
        matches!(self.state, TransferState::Active) && 
        self.last_activity.elapsed() > Duration::from_secs(30)
    }

    /// Get transfer efficiency ratio (successful vs total attempts)
    pub fn get_efficiency_ratio(&self) -> f64 {
        let total_attempts = self.chunks_sent + self.failed_chunks;
        if total_attempts > 0 {
            self.chunks_sent as f64 / total_attempts as f64
        } else {
            1.0
        }
    }

    /// Get estimated completion time
    pub fn estimated_completion_time(&self) -> Option<std::time::SystemTime> {
        self.eta.map(|eta| std::time::SystemTime::now() + eta)
    }

    /// Get human-readable progress summary
    pub fn progress_summary(&self) -> String {
        let byte_percent = (self.progress_percentage() * 100.0).round();
        let chunk_percent = (self.chunk_progress_percentage() * 100.0).round();
        
        let rate_str = if self.current_rate > 1_000_000.0 {
            format!("{:.1} MB/s", self.current_rate / 1_000_000.0)
        } else if self.current_rate > 1_000.0 {
            format!("{:.1} KB/s", self.current_rate / 1_000.0)
        } else {
            format!("{:.0} B/s", self.current_rate)
        };

        let eta_str = match self.eta {
            Some(eta) => {
                let total_seconds = eta.as_secs();
                if total_seconds > 3600 {
                    format!("{}h {}m", total_seconds / 3600, (total_seconds % 3600) / 60)
                } else if total_seconds > 60 {
                    format!("{}m {}s", total_seconds / 60, total_seconds % 60)
                } else {
                    format!("{}s", total_seconds)
                }
            }
            None => "unknown".to_string(),
        };

        format!(
            "{:.0}% ({:.0}% chunks) | {} | ETA: {} | {}/{} chunks | {} failures",
            byte_percent,
            chunk_percent,
            rate_str,
            eta_str,
            self.chunks_sent,
            self.total_chunks,
            self.failed_chunks
        )
    }

    /// Check if transfer is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, TransferState::Completed)
    }

    /// Check if transfer has failed
    pub fn is_failed(&self) -> bool {
        matches!(self.state, TransferState::Failed { .. })
    }

    /// Check if transfer is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, TransferState::Active | TransferState::Initializing)
    }
}

/// Aggregated progress metrics for all transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressMetrics {
    /// Total number of active transfers
    pub active_transfers: usize,
    /// Total number of completed transfers
    pub completed_transfers: u64,
    /// Total number of failed transfers
    pub failed_transfers: u64,
    /// Total bytes sent across all transfers
    pub total_bytes_sent: u64,
    /// Overall transfer rate (bytes per second)
    pub overall_rate: f64,
    /// Average transfer completion time
    pub avg_completion_time: Duration,
    /// Total number of chunks sent
    pub total_chunks_sent: u64,
    /// Total number of failed chunks
    pub total_failed_chunks: u64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Current memory usage for tracking
    pub memory_usage_bytes: u64,
    /// Timestamp of last update
    pub last_update: u64,
}

/// Health status information for transfer monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferHealthStatus {
    /// Total number of transfers being tracked
    pub total_transfers: usize,
    /// Number of active transfers
    pub active_transfers: usize,
    /// Number of failed transfers
    pub failed_transfers: usize,
    /// Number of stalled transfers (active but no recent activity)
    pub stalled_transfers: usize,
    /// Overall failure rate (0.0 to 1.0)
    pub failure_rate: f64,
    /// Memory usage for tracking in MB
    pub memory_usage_mb: f64,
    /// Overall transfer rate in KB/s
    pub overall_rate_kbps: f64,
}

/// Comprehensive progress information for a transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressInfo {
    /// Session identifier
    pub session_id: TransferSessionId,
    /// File name
    pub file_name: String,
    /// Total file size
    pub file_size: u64,
    /// Bytes sent so far
    pub bytes_sent: u64,
    /// Chunks sent successfully
    pub chunks_sent: u32,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Current transfer state
    pub state: TransferState,
    /// Progress as percentage of bytes (0.0 to 1.0)
    pub byte_percentage: f64,
    /// Progress as percentage of chunks (0.0 to 1.0)
    pub chunk_percentage: f64,
    /// Current transfer rate in bytes per second
    pub current_rate_bps: f64,
    /// Average transfer rate in bytes per second
    pub average_rate_bps: f64,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Number of failed chunks
    pub failed_chunks: u32,
    /// Number of retried chunks
    pub retried_chunks: u32,
    /// Total elapsed time
    pub elapsed_time: Duration,
    /// Whether transfer appears stalled
    pub is_stalled: bool,
    /// Transfer efficiency ratio (0.0 to 1.0)
    pub efficiency_ratio: f64,
}

impl Default for ProgressMetrics {
    fn default() -> Self {
        Self {
            active_transfers: 0,
            completed_transfers: 0,
            failed_transfers: 0,
            total_bytes_sent: 0,
            overall_rate: 0.0,
            avg_completion_time: Duration::default(),
            total_chunks_sent: 0,
            total_failed_chunks: 0,
            cache_hit_ratio: 0.0,
            memory_usage_bytes: 0,
            last_update: ProgressEvent::timestamp(),
        }
    }
}

/// Main progress tracking system
pub struct ProgressTracker {
    config: ProgressTrackerConfig,
    transfers: Arc<RwLock<HashMap<TransferSessionId, FileTransferProgress>>>,
    metrics: Arc<Mutex<ProgressMetrics>>,
    event_sender: broadcast::Sender<ProgressEvent>,
    _event_receiver: broadcast::Receiver<ProgressEvent>,
}

impl ProgressTracker {
    pub fn new(config: ProgressTrackerConfig) -> Self {
        let (event_sender, event_receiver) = broadcast::channel(config.max_event_buffer);
        
        Self {
            config,
            transfers: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(ProgressMetrics::default())),
            event_sender,
            _event_receiver: event_receiver,
        }
    }

    /// Save a checkpoint for a transfer session
    pub fn save_checkpoint(&self, session_id: &TransferSessionId, checkpoint_dir: &str) -> Result<String, String> {
        let transfers = self.transfers.read().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get(session_id) {
            let checkpoint = TransferCheckpoint::from_progress(progress);
            let checkpoint_path = format!("{}/checkpoint_{}.json", checkpoint_dir, session_id.0);
            
            // Create directory if it doesn't exist
            if let Some(parent) = PathBuf::from(&checkpoint_path).parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    error!("Failed to create checkpoint directory: {}", e);
                    format!("Failed to create checkpoint directory: {}", e)
                })?;
            }
            
            // Serialize and save checkpoint
            let checkpoint_json = serde_json::to_string_pretty(&checkpoint).map_err(|e| {
                error!("Failed to serialize checkpoint: {}", e);
                format!("Failed to serialize checkpoint: {}", e)
            })?;
            
            fs::write(&checkpoint_path, checkpoint_json).map_err(|e| {
                error!("Failed to write checkpoint file: {}", e);
                format!("Failed to write checkpoint file: {}", e)
            })?;
            
            // Update progress with checkpoint path
            drop(transfers);
            let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
            if let Some(progress) = transfers.get_mut(session_id) {
                progress.checkpoint_path = Some(checkpoint_path.clone());
                progress.last_checkpoint_time = Instant::now();
            }
            
            info!("Checkpoint saved for session {} at: {}", session_id.0, checkpoint_path);
            Ok(checkpoint_path)
        } else {
            error!("Cannot save checkpoint for unknown session: {}", session_id.0);
            Err("Transfer session not found".to_string())
        }
    }
    
    /// Load a checkpoint and restore transfer progress
    pub fn load_checkpoint(&self, checkpoint_path: &str) -> Result<TransferSessionId, String> {
        // Read checkpoint file
        let checkpoint_data = fs::read_to_string(checkpoint_path).map_err(|e| {
            error!("Failed to read checkpoint file: {}", e);
            format!("Failed to read checkpoint file: {}", e)
        })?;
        
        // Deserialize checkpoint
        let checkpoint: TransferCheckpoint = serde_json::from_str(&checkpoint_data).map_err(|e| {
            error!("Failed to deserialize checkpoint: {}", e);
            format!("Failed to deserialize checkpoint: {}", e)
        })?;
        
        // Validate checkpoint
        checkpoint.validate().map_err(|e| {
            error!("Invalid checkpoint: {}", e);
            format!("Invalid checkpoint: {}", e)
        })?;
        
        // Create progress from checkpoint
        let mut progress = FileTransferProgress::new(
            checkpoint.session_id.clone(),
            checkpoint.file_name.clone(),
            checkpoint.file_size,
            checkpoint.total_chunks,
        );
        
        // Restore progress state
        progress.state = TransferState::Interrupted;
        progress.chunks_sent = checkpoint.chunks_sent;
        progress.bytes_sent = checkpoint.bytes_sent;
        progress.failed_chunks = checkpoint.failed_chunks;
        progress.retried_chunks = checkpoint.retried_chunks;
        progress.client_id = checkpoint.client_id.clone();
        progress.checkpoint_path = Some(checkpoint_path.to_string());
        
        // Add to transfers
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        transfers.insert(checkpoint.session_id.clone(), progress);
        
        info!(
            "Checkpoint loaded for session {} | Progress: {:.1}% | Chunks: {}/{}",
            checkpoint.session_id.0,
            (checkpoint.bytes_sent as f64 / checkpoint.file_size as f64) * 100.0,
            checkpoint.chunks_sent,
            checkpoint.total_chunks
        );
        
        self.update_metrics();
        Ok(checkpoint.session_id)
    }
    
    /// Resume a transfer from an interrupted state
    pub fn resume_from_checkpoint(&self, session_id: &TransferSessionId) -> Result<TransferCheckpoint, String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get_mut(session_id) {
            match progress.state {
                TransferState::Interrupted | TransferState::Paused => {
                    // Load checkpoint if available
                    if let Some(checkpoint_path) = &progress.checkpoint_path {
                        let checkpoint_data = fs::read_to_string(checkpoint_path).map_err(|e| {
                            error!("Failed to read checkpoint file: {}", e);
                            format!("Failed to read checkpoint file: {}", e)
                        })?;
                        
                        let checkpoint: TransferCheckpoint = serde_json::from_str(&checkpoint_data).map_err(|e| {
                            error!("Failed to deserialize checkpoint: {}", e);
                            format!("Failed to deserialize checkpoint: {}", e)
                        })?;
                        
                        checkpoint.validate().map_err(|e| {
                            error!("Invalid checkpoint: {}", e);
                            format!("Invalid checkpoint: {}", e)
                        })?;
                        
                        // Resume from checkpoint
                        progress.state = TransferState::Active;
                        progress.chunks_sent = checkpoint.chunks_sent;
                        progress.bytes_sent = checkpoint.bytes_sent;
                        progress.failed_chunks = checkpoint.failed_chunks;
                        progress.retried_chunks = checkpoint.retried_chunks;
                        
                        info!(
                            "Resumed transfer from checkpoint: {} | Progress: {:.1}% | Next chunk: {}",
                            session_id.0,
                            (checkpoint.bytes_sent as f64 / checkpoint.file_size as f64) * 100.0,
                            checkpoint.get_next_chunk_to_send().unwrap_or(0)
                        );
                        
                        // Send state change event
                        let event = ProgressEvent::state_changed(
                            session_id.clone(),
                            TransferState::Interrupted,
                            TransferState::Active,
                        );
                        let _ = self.event_sender.send(event);
                        
                        self.update_metrics();
                        Ok(checkpoint)
                    } else {
                        // No checkpoint available, resume from current state
                        progress.state = TransferState::Active;
                        
                        info!("Resumed transfer without checkpoint: {}", session_id.0);
                        
                        // Create basic checkpoint from current progress
                        let checkpoint = TransferCheckpoint::from_progress(progress);
                        
                        // Send state change event
                        let event = ProgressEvent::state_changed(
                            session_id.clone(),
                            TransferState::Interrupted,
                            TransferState::Active,
                        );
                        let _ = self.event_sender.send(event);
                        
                        self.update_metrics();
                        Ok(checkpoint)
                    }
                }
                _ => {
                    warn!("Cannot resume session {} - transfer is not interrupted or paused", session_id.0);
                    Err("Transfer is not interrupted or paused".to_string())
                }
            }
        } else {
            error!("Cannot resume unknown session: {}", session_id.0);
            Err("Transfer session not found".to_string())
        }
    }
    
    /// Automatically save checkpoints for active transfers
    pub fn auto_save_checkpoints(&self, checkpoint_dir: &str) -> Result<usize, String> {
        let mut saved_count = 0;
        
        // Collect session IDs that need checkpoints
        let sessions_to_save: Vec<TransferSessionId> = {
            let transfers = self.transfers.read().map_err(|e| e.to_string())?;
            transfers.iter()
                .filter_map(|(session_id, progress)| {
                    if progress.is_active() {
                        let elapsed_since_checkpoint = progress.last_checkpoint_time.elapsed();
                        if elapsed_since_checkpoint.as_secs() >= progress.checkpoint_interval {
                            Some(session_id.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        };
        
        // Save checkpoints for collected sessions
        for session_id in sessions_to_save {
            if let Ok(_) = self.save_checkpoint(&session_id, checkpoint_dir) {
                saved_count += 1;
            }
        }
        
        if saved_count > 0 {
            debug!("Auto-saved {} checkpoints", saved_count);
        }
        
        Ok(saved_count)
    }
    
    /// Clean up checkpoint files for completed/failed transfers
    pub fn cleanup_checkpoints(&self, checkpoint_dir: &str) -> Result<usize, String> {
        let transfers = self.transfers.read().map_err(|e| e.to_string())?;
        let mut cleaned_count = 0;
        
        for progress in transfers.values() {
            if (progress.is_complete() || progress.is_failed()) && progress.checkpoint_path.is_some() {
                let checkpoint_path = progress.checkpoint_path.as_ref().unwrap();
                
                if let Err(e) = fs::remove_file(checkpoint_path) {
                    warn!("Failed to remove checkpoint file {}: {}", checkpoint_path, e);
                } else {
                    debug!("Cleaned up checkpoint file: {}", checkpoint_path);
                    cleaned_count += 1;
                }
            }
        }
        
        if cleaned_count > 0 {
            info!("Cleaned up {} checkpoint files", cleaned_count);
        }
        
        Ok(cleaned_count)
    }

    /// Start tracking a new file transfer
    pub fn start_transfer(
        &self,
        session_id: TransferSessionId,
        file_name: String,
        file_size: u64,
        total_chunks: u32,
    ) -> Result<(), String> {
        let event = {
            let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
            
            if transfers.len() >= self.config.max_concurrent_transfers {
                warn!("Maximum concurrent transfers reached: {}", self.config.max_concurrent_transfers);
                return Err("Maximum concurrent transfers reached".to_string());
            }

            let progress = FileTransferProgress::new(
                session_id.clone(),
                file_name.clone(),
                file_size,
                total_chunks,
            );

            transfers.insert(session_id.clone(), progress);
            
            // Log transfer start
            info!(
                "Started transfer session: {} | File: {} | Size: {} bytes | Chunks: {}",
                session_id.0, file_name, file_size, total_chunks
            );
            
            debug!(
                "Transfer session {} initialized with {} concurrent transfers active",
                session_id.0, transfers.len()
            );
            
            // Create event
            ProgressEvent::transfer_started(session_id, file_name, file_size, total_chunks)
        }; // Release write lock here
        
        // Send event after releasing lock
        let _ = self.event_sender.send(event);

        // Update metrics after releasing lock
        self.update_metrics();

        Ok(())
    }

    /// Update progress for a chunk sent
    pub fn update_chunk_sent(
        &self,
        session_id: &TransferSessionId,
        chunk_id: u32,
        chunk_size: u64,
    ) -> Result<(), String> {
        let (event, update_needed) = {
            let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
            
            if let Some(progress) = transfers.get_mut(session_id) {
                progress.update_chunk_sent(chunk_size);
                
                // Log chunk progress
                debug!(
                    "Chunk sent: {} | Session: {} | Chunk: {} | Size: {} bytes | Progress: {:.1}%",
                    session_id.0, session_id.0, chunk_id, chunk_size, progress.progress_percentage() * 100.0
                );
                
                // Log milestone progress
                let progress_pct = progress.progress_percentage();
                if progress_pct >= 0.25 && progress_pct < 0.26 {
                    info!("Transfer {} reached 25% completion", session_id.0);
                } else if progress_pct >= 0.5 && progress_pct < 0.51 {
                    info!("Transfer {} reached 50% completion", session_id.0);
                } else if progress_pct >= 0.75 && progress_pct < 0.76 {
                    info!("Transfer {} reached 75% completion", session_id.0);
                }
                
                // Create event
                let event = ProgressEvent::chunk_sent(session_id.clone(), chunk_id, chunk_size);
                (Some(event), true)
            } else {
                error!("Attempted to update chunk for unknown session: {}", session_id.0);
                (None, false)
            }
        }; // Release write lock here
        
        // Send event after releasing lock
        if let Some(event) = event {
            let _ = self.event_sender.send(event);
        }
        
        // Update metrics after releasing lock
        if update_needed {
            self.update_metrics();
            Ok(())
        } else {
            Err("Transfer session not found".to_string())
        }
    }

    /// Update progress for a chunk failure
    pub fn update_chunk_failed(
        &self,
        session_id: &TransferSessionId,
        chunk_id: u32,
        error: String,
    ) -> Result<(), String> {
        let (event, update_needed) = {
            let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
            
            if let Some(progress) = transfers.get_mut(session_id) {
                progress.update_chunk_failed();
                
                // Log chunk failure
                warn!(
                    "Chunk failed: {} | Session: {} | Chunk: {} | Error: {} | Failed chunks: {}",
                    session_id.0, session_id.0, chunk_id, error, progress.failed_chunks
                );
                
                // Log warning if failure rate is high
                let failure_rate = progress.failed_chunks as f64 / (progress.chunks_sent + progress.failed_chunks) as f64;
                if failure_rate > 0.1 && progress.failed_chunks > 5 {
                    warn!(
                        "High failure rate detected for session {}: {:.1}% ({} failures)",
                        session_id.0, failure_rate * 100.0, progress.failed_chunks
                    );
                }
                
                // Create event
                let event = ProgressEvent::chunk_failed(session_id.clone(), chunk_id, error);
                (Some(event), true)
            } else {
                error!("Attempted to update chunk failure for unknown session: {}", session_id.0);
                (None, false)
            }
        }; // Release write lock here
        
        // Send event after releasing lock
        if let Some(event) = event {
            let _ = self.event_sender.send(event);
        }
        
        // Update metrics after releasing lock
        if update_needed {
            self.update_metrics();
            Ok(())
        } else {
            Err("Transfer session not found".to_string())
        }
    }

    /// Update transfer state
    pub fn update_state(
        &self,
        session_id: &TransferSessionId,
        new_state: TransferState,
    ) -> Result<(), String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get_mut(session_id) {
            let old_state = progress.state.clone();
            progress.state = new_state.clone();
            
            // Send event
            let event = ProgressEvent::state_changed(session_id.clone(), old_state, new_state);
            let _ = self.event_sender.send(event);
            
            // Update metrics
            self.update_metrics();
            
            Ok(())
        } else {
            Err("Transfer session not found".to_string())
        }
    }

    /// Complete a transfer
    pub fn complete_transfer(&self, session_id: &TransferSessionId) -> Result<(), String> {
        let (event_data, update_needed) = {
            let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
            
            if let Some(progress) = transfers.get_mut(session_id) {
                progress.state = TransferState::Completed;
                let duration = progress.start_time.elapsed();
                
                // Log transfer completion with detailed statistics
                info!(
                    "Transfer completed: {} | Duration: {:.2}s | Bytes: {} | Chunks: {}/{} | Rate: {:.2} KB/s | Failures: {}",
                    session_id.0,
                    duration.as_secs_f64(),
                    progress.bytes_sent,
                    progress.chunks_sent,
                    progress.total_chunks,
                    progress.average_rate / 1024.0,
                    progress.failed_chunks
                );
                
                // Log performance metrics
                if progress.failed_chunks > 0 {
                    let failure_rate = progress.failed_chunks as f64 / progress.total_chunks as f64;
                    debug!(
                        "Transfer {} completed with {:.1}% failure rate ({} retries)",
                        session_id.0, failure_rate * 100.0, progress.retried_chunks
                    );
                }
                
                // Create event data
                let event = ProgressEvent::transfer_completed(
                    session_id.clone(),
                    progress.bytes_sent,
                    duration,
                );
                
                (Some(event), true)
            } else {
                error!("Attempted to complete unknown transfer session: {}", session_id.0);
                (None, false)
            }
        }; // Release write lock here
        
        // Send event after releasing lock
        if let Some(event) = event_data {
            let _ = self.event_sender.send(event);
        }
        
        // Update metrics after releasing lock
        if update_needed {
            self.update_metrics();
            Ok(())
        } else {
            Err("Transfer session not found".to_string())
        }
    }

    /// Fail a transfer
    pub fn fail_transfer(&self, session_id: &TransferSessionId, error: String) -> Result<(), String> {
        let (event, update_needed) = {
            let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
            
            if let Some(progress) = transfers.get_mut(session_id) {
                progress.state = TransferState::Failed { error: error.clone() };
                let duration = progress.start_time.elapsed();
                
                // Log transfer failure with context
                error!(
                    "Transfer failed: {} | Error: {} | Duration: {:.2}s | Progress: {:.1}% | Bytes sent: {} | Chunks: {}/{} | Failures: {}",
                    session_id.0,
                    error,
                    duration.as_secs_f64(),
                    progress.progress_percentage() * 100.0,
                    progress.bytes_sent,
                    progress.chunks_sent,
                    progress.total_chunks,
                    progress.failed_chunks
                );
                
                // Log additional context for debugging
                debug!(
                    "Transfer {} failed after {} chunk failures and {} retries",
                    session_id.0, progress.failed_chunks, progress.retried_chunks
                );
                
                // Create event
                let event = ProgressEvent::transfer_failed(
                    session_id.clone(),
                    error,
                    progress.bytes_sent,
                );
                (Some(event), true)
            } else {
                error!("Attempted to fail unknown transfer session: {}", session_id.0);
                (None, false)
            }
        }; // Release write lock here
        
        // Send event after releasing lock
        if let Some(event) = event {
            let _ = self.event_sender.send(event);
        }
        
        // Update metrics after releasing lock
        if update_needed {
            self.update_metrics();
            Ok(())
        } else {
            Err("Transfer session not found".to_string())
        }
    }

    /// Get progress for a specific transfer
    pub fn get_progress(&self, session_id: &TransferSessionId) -> Option<FileTransferProgress> {
        let transfers = self.transfers.read().ok()?;
        transfers.get(session_id).cloned()
    }

    /// Get all active transfers
    pub fn get_active_transfers(&self) -> Vec<FileTransferProgress> {
        let transfers = self.transfers.read().unwrap_or_else(|e| e.into_inner());
        transfers
            .values()
            .filter(|p| p.is_active())
            .cloned()
            .collect()
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> ProgressMetrics {
        self.metrics.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Subscribe to progress events
    pub fn subscribe_events(&self) -> broadcast::Receiver<ProgressEvent> {
        self.event_sender.subscribe()
    }

    /// Clean up completed and failed transfers
    pub fn cleanup_transfers(&self) -> usize {
        let mut transfers = self.transfers.write().unwrap_or_else(|e| e.into_inner());
        let initial_count = transfers.len();
        
        // Collect statistics before cleanup
        let completed_count = transfers.values().filter(|p| p.is_complete()).count();
        let failed_count = transfers.values().filter(|p| p.is_failed()).count();
        
        transfers.retain(|_, progress| {
            !progress.is_complete() && !progress.is_failed()
        });
        
        let removed = initial_count - transfers.len();
        if removed > 0 {
            info!(
                "Cleaned up {} finished transfers | Completed: {} | Failed: {} | Active remaining: {}",
                removed, completed_count, failed_count, transfers.len()
            );
            
            debug!(
                "Transfer cleanup: {} sessions removed, {} active sessions remaining",
                removed, transfers.len()
            );
            
            self.update_metrics();
        }
        
        removed
    }

    /// Retry failed chunks for a transfer session
    pub fn retry_failed_chunks(&self, session_id: &TransferSessionId) -> Result<u32, String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get_mut(session_id) {
            if progress.is_failed() {
                // Reset state to active for retry
                progress.state = TransferState::Active;
                let failed_chunks = progress.failed_chunks;
                progress.failed_chunks = 0;
                progress.retried_chunks += failed_chunks;
                
                info!(
                    "Retrying failed chunks for session {} | Failed chunks: {} | Total retries: {}",
                    session_id.0, failed_chunks, progress.retried_chunks
                );
                
                // Send state change event
                let event = ProgressEvent::state_changed(
                    session_id.clone(),
                    TransferState::Failed { error: "Retry initiated".to_string() },
                    TransferState::Active,
                );
                let _ = self.event_sender.send(event);
                
                self.update_metrics();
                Ok(failed_chunks)
            } else {
                warn!("Cannot retry chunks for session {} - transfer is not in failed state", session_id.0);
                Err("Transfer is not in failed state".to_string())
            }
        } else {
            error!("Cannot retry chunks for unknown session: {}", session_id.0);
            Err("Transfer session not found".to_string())
        }
    }

    /// Pause an active transfer
    pub fn pause_transfer(&self, session_id: &TransferSessionId) -> Result<(), String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get_mut(session_id) {
            if progress.is_active() {
                let old_state = progress.state.clone();
                progress.state = TransferState::Paused;
                
                info!("Paused transfer session: {}", session_id.0);
                
                // Send state change event
                let event = ProgressEvent::state_changed(
                    session_id.clone(),
                    old_state,
                    TransferState::Paused,
                );
                let _ = self.event_sender.send(event);
                
                self.update_metrics();
                Ok(())
            } else {
                warn!("Cannot pause session {} - transfer is not active", session_id.0);
                Err("Transfer is not active".to_string())
            }
        } else {
            error!("Cannot pause unknown session: {}", session_id.0);
            Err("Transfer session not found".to_string())
        }
    }

    /// Resume a paused or interrupted transfer
    pub fn resume_transfer(&self, session_id: &TransferSessionId) -> Result<(), String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get_mut(session_id) {
            match progress.state {
                TransferState::Paused => {
                    progress.state = TransferState::Active;
                    
                    info!("Resumed paused transfer session: {}", session_id.0);
                    
                    // Send state change event
                    let event = ProgressEvent::state_changed(
                        session_id.clone(),
                        TransferState::Paused,
                        TransferState::Active,
                    );
                    let _ = self.event_sender.send(event);
                    
                    self.update_metrics();
                    Ok(())
                }
                TransferState::Interrupted => {
                    progress.state = TransferState::Active;
                    
                    info!("Resumed interrupted transfer session: {}", session_id.0);
                    
                    // Send state change event
                    let event = ProgressEvent::state_changed(
                        session_id.clone(),
                        TransferState::Interrupted,
                        TransferState::Active,
                    );
                    let _ = self.event_sender.send(event);
                    
                    self.update_metrics();
                    Ok(())
                }
                _ => {
                    warn!("Cannot resume session {} - transfer is not paused or interrupted", session_id.0);
                    Err("Transfer is not paused or interrupted".to_string())
                }
            }
        } else {
            error!("Cannot resume unknown session: {}", session_id.0);
            Err("Transfer session not found".to_string())
        }
    }

    /// Cancel a transfer session
    pub fn cancel_transfer(&self, session_id: &TransferSessionId) -> Result<(), String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        
        if let Some(progress) = transfers.get_mut(session_id) {
            if !progress.is_complete() {
                let old_state = progress.state.clone();
                progress.state = TransferState::Cancelled;
                
                info!(
                    "Cancelled transfer session: {} | Progress: {:.1}% | Chunks sent: {}/{}",
                    session_id.0,
                    progress.progress_percentage() * 100.0,
                    progress.chunks_sent,
                    progress.total_chunks
                );
                
                // Send state change event
                let event = ProgressEvent::state_changed(
                    session_id.clone(),
                    old_state,
                    TransferState::Cancelled,
                );
                let _ = self.event_sender.send(event);
                
                self.update_metrics();
                Ok(())
            } else {
                warn!("Cannot cancel session {} - transfer is already complete", session_id.0);
                Err("Transfer is already complete".to_string())
            }
        } else {
            error!("Cannot cancel unknown session: {}", session_id.0);
            Err("Transfer session not found".to_string())
        }
    }

    /// Get health status of all transfers
    pub fn get_health_status(&self) -> Result<TransferHealthStatus, String> {
        let transfers = self.transfers.read().map_err(|e| e.to_string())?;
        let metrics = self.metrics.lock().map_err(|e| e.to_string())?;
        
        let total_transfers = transfers.len();
        let active_transfers = transfers.values().filter(|p| p.is_active()).count();
        let failed_transfers = transfers.values().filter(|p| p.is_failed()).count();
        let stalled_transfers = transfers.values().filter(|p| {
            p.is_active() && p.last_activity.elapsed().as_secs() > 60 // 1 minute stall threshold
        }).count();
        
        // Calculate overall failure rate
        let total_chunks = metrics.total_chunks_sent + metrics.total_failed_chunks;
        let failure_rate = if total_chunks > 0 {
            metrics.total_failed_chunks as f64 / total_chunks as f64
        } else {
            0.0
        };
        
        let status = TransferHealthStatus {
            total_transfers,
            active_transfers,
            failed_transfers,
            stalled_transfers,
            failure_rate,
            memory_usage_mb: metrics.memory_usage_bytes as f64 / (1024.0 * 1024.0),
            overall_rate_kbps: metrics.overall_rate / 1024.0,
        };
        
        // Log health warnings
        if failure_rate > 0.1 {
            warn!("High failure rate detected: {:.1}%", failure_rate * 100.0);
        }
        
        if stalled_transfers > 0 {
            warn!("Detected {} stalled transfers", stalled_transfers);
        }
        
        debug!("Health status: {:#?}", status);
        Ok(status)
    }

    /// Automatically recover stalled transfers
    pub fn auto_recover_stalled(&self) -> Result<usize, String> {
        let mut transfers = self.transfers.write().map_err(|e| e.to_string())?;
        let mut recovered = 0;
        
        let stall_threshold = Duration::from_secs(120); // 2 minutes
        let session_ids: Vec<TransferSessionId> = transfers.keys().cloned().collect();
        
        for session_id in session_ids {
            if let Some(progress) = transfers.get_mut(&session_id) {
                if progress.is_active() && progress.last_activity.elapsed() > stall_threshold {
                    // Mark as failed for automatic retry
                    progress.state = TransferState::Failed {
                        error: "Transfer stalled - automatic recovery".to_string()
                    };
                    
                    warn!(
                        "Auto-recovering stalled transfer: {} | Stalled for: {:.1}s",
                        session_id.0,
                        progress.last_activity.elapsed().as_secs_f64()
                    );
                    
                    recovered += 1;
                }
            }
        }
        
        if recovered > 0 {
            info!("Auto-recovered {} stalled transfers", recovered);
            self.update_metrics();
        }
        
        Ok(recovered)
    }

    /// Update aggregated metrics
    fn update_metrics(&self) {
        let transfers = self.transfers.read().unwrap_or_else(|e| e.into_inner());
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        
        let active_count = transfers.values().filter(|p| p.is_active()).count();
        let completed_count = transfers.values().filter(|p| p.is_complete()).count();
        let failed_count = transfers.values().filter(|p| p.is_failed()).count();
        
        let prev_completed = metrics.completed_transfers;
        let prev_failed = metrics.failed_transfers;
        
        metrics.active_transfers = active_count;
        metrics.completed_transfers = completed_count as u64;
        metrics.failed_transfers = failed_count as u64;
        
        metrics.total_bytes_sent = transfers.values().map(|p| p.bytes_sent).sum();
        metrics.total_chunks_sent = transfers.values().map(|p| p.chunks_sent as u64).sum();
        metrics.total_failed_chunks = transfers.values().map(|p| p.failed_chunks as u64).sum();
        
        // Calculate overall rate
        let total_duration: Duration = transfers.values()
            .map(|p| p.start_time.elapsed())
            .sum();
        if total_duration.as_secs() > 0 {
            metrics.overall_rate = metrics.total_bytes_sent as f64 / total_duration.as_secs_f64();
        }
        
        metrics.last_update = ProgressEvent::timestamp();
        
        // Estimate memory usage
        metrics.memory_usage_bytes = (transfers.len() * std::mem::size_of::<FileTransferProgress>()) as u64;
        
        // Log metrics updates periodically or on significant changes
        if metrics.completed_transfers != prev_completed || metrics.failed_transfers != prev_failed {
            debug!(
                "Metrics updated | Active: {} | Completed: {} | Failed: {} | Total bytes: {} | Overall rate: {:.2} KB/s",
                metrics.active_transfers,
                metrics.completed_transfers,
                metrics.failed_transfers,
                metrics.total_bytes_sent,
                metrics.overall_rate / 1024.0
            );
        }
        
        // Log warnings for concerning metrics
        if metrics.total_failed_chunks > 0 {
            let failure_rate = metrics.total_failed_chunks as f64 / (metrics.total_chunks_sent + metrics.total_failed_chunks) as f64;
            if failure_rate > 0.05 { // 5% failure rate threshold
                warn!(
                    "High overall failure rate detected: {:.1}% ({} failed chunks out of {})",
                    failure_rate * 100.0,
                    metrics.total_failed_chunks,
                    metrics.total_chunks_sent + metrics.total_failed_chunks
                );
            }
        }
        
        // Log memory usage warnings
        if metrics.memory_usage_bytes > 100 * 1024 * 1024 { // 100MB threshold
            warn!(
                "High memory usage for progress tracking: {:.1} MB ({} active transfers)",
                metrics.memory_usage_bytes as f64 / (1024.0 * 1024.0),
                metrics.active_transfers
            );
        }
    }

    /// Subscribe to specific progress events with filtering
    pub fn subscribe_filtered_events<F>(&self, filter: F) -> broadcast::Receiver<ProgressEvent>
    where
        F: Fn(&ProgressEvent) -> bool + Send + Sync + 'static,
    {
        // For now, return regular subscription - filtering would need async wrapper
        self.event_sender.subscribe()
    }

    /// Get progress updates for multiple sessions
    pub fn get_bulk_progress(&self, session_ids: &[TransferSessionId]) -> Vec<Option<ProgressInfo>> {
        let transfers = self.transfers.read().unwrap_or_else(|e| e.into_inner());
        session_ids.iter()
            .map(|id| transfers.get(id).map(|p| p.get_progress_info()))
            .collect()
    }

    /// Get progress summary for all active transfers
    pub fn get_all_progress_info(&self) -> Vec<ProgressInfo> {
        let transfers = self.transfers.read().unwrap_or_else(|e| e.into_inner());
        transfers.values()
            .filter(|p| p.is_active())
            .map(|p| p.get_progress_info())
            .collect()
    }

    /// Generate a comprehensive progress report
    pub fn generate_progress_report(&self) -> String {
        let transfers = self.transfers.read().unwrap_or_else(|e| e.into_inner());
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        
        let mut report = String::new();
        report.push_str("=== UDCN Transport Progress Report ===\n\n");
        
        // Overall metrics
        report.push_str(&format!("Overall Metrics:\n"));
        report.push_str(&format!("  Active Transfers: {}\n", metrics.active_transfers));
        report.push_str(&format!("  Completed: {} | Failed: {}\n", metrics.completed_transfers, metrics.failed_transfers));
        report.push_str(&format!("  Total Bytes Sent: {:.2} MB\n", metrics.total_bytes_sent as f64 / 1_000_000.0));
        report.push_str(&format!("  Overall Rate: {:.2} KB/s\n", metrics.overall_rate / 1000.0));
        report.push_str(&format!("  Memory Usage: {:.1} MB\n\n", metrics.memory_usage_bytes as f64 / (1024.0 * 1024.0)));
        
        // Active transfers
        if !transfers.is_empty() {
            report.push_str("Active Transfers:\n");
            for (i, progress) in transfers.values().filter(|p| p.is_active()).enumerate() {
                report.push_str(&format!("  {}. {}\n", i + 1, progress.progress_summary()));
            }
            report.push('\n');
        }
        
        // Stalled transfers
        let stalled: Vec<_> = transfers.values()
            .filter(|p| p.is_stalled())
            .collect();
        if !stalled.is_empty() {
            report.push_str("⚠️  Stalled Transfers:\n");
            for progress in stalled {
                let stall_duration = progress.last_activity.elapsed().as_secs();
                report.push_str(&format!("  {} (stalled for {}s)\n", 
                    progress.session_id.0, stall_duration));
            }
            report.push('\n');
        }
        
        // Health warnings
        let total_chunks = metrics.total_chunks_sent + metrics.total_failed_chunks;
        if total_chunks > 0 {
            let failure_rate = metrics.total_failed_chunks as f64 / total_chunks as f64;
            if failure_rate > 0.05 {
                report.push_str(&format!("⚠️  High failure rate: {:.1}%\n", failure_rate * 100.0));
            }
        }
        
        report
    }

    /// Create a simple progress bar visualization
    pub fn create_progress_bar(&self, session_id: &TransferSessionId, width: usize) -> Option<String> {
        let transfers = self.transfers.read().ok()?;
        let progress = transfers.get(session_id)?;
        
        let percentage = progress.progress_percentage();
        let filled = (percentage * width as f64) as usize;
        let empty = width.saturating_sub(filled);
        
        let bar = format!("[{}{}] {:.1}%", 
            "█".repeat(filled),
            "░".repeat(empty),
            percentage * 100.0
        );
        
        Some(bar)
    }

    /// Create detailed transfer status for CLI display
    pub fn format_transfer_status(&self, session_id: &TransferSessionId) -> Option<String> {
        let transfers = self.transfers.read().ok()?;
        let progress = transfers.get(session_id)?;
        
        let progress_bar = self.create_progress_bar(session_id, 30).unwrap_or_default();
        let info = progress.get_progress_info();
        
        let mut status = String::new();
        status.push_str(&format!("File: {}\n", info.file_name));
        status.push_str(&format!("Status: {:?}\n", info.state));
        status.push_str(&format!("Progress: {}\n", progress_bar));
        status.push_str(&format!("Rate: {:.1} KB/s (avg: {:.1} KB/s)\n", 
            info.current_rate_bps / 1000.0, 
            info.average_rate_bps / 1000.0));
        
        if let Some(eta) = info.eta {
            let seconds = eta.as_secs();
            if seconds > 3600 {
                status.push_str(&format!("ETA: {}h {}m\n", seconds / 3600, (seconds % 3600) / 60));
            } else if seconds > 60 {
                status.push_str(&format!("ETA: {}m {}s\n", seconds / 60, seconds % 60));
            } else {
                status.push_str(&format!("ETA: {}s\n", seconds));
            }
        }
        
        status.push_str(&format!("Chunks: {}/{} ({:.1}%)\n", 
            info.chunks_sent, 
            info.total_chunks, 
            info.chunk_percentage * 100.0));
        
        if info.failed_chunks > 0 {
            status.push_str(&format!("Failures: {} (efficiency: {:.1}%)\n", 
                info.failed_chunks, 
                info.efficiency_ratio * 100.0));
        }
        
        if info.is_stalled {
            status.push_str("⚠️  Transfer appears stalled\n");
        }
        
        Some(status)
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new(ProgressTrackerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_progress_tracker_basic() {
        let tracker = ProgressTracker::default();
        let session_id = TransferSessionId::new("test_file.txt", "client1");
        
        // Start transfer
        assert!(tracker.start_transfer(
            session_id.clone(),
            "test_file.txt".to_string(),
            1000,
            10
        ).is_ok());
        
        // Update progress
        assert!(tracker.update_chunk_sent(&session_id, 1, 100).is_ok());
        
        // Check progress
        let progress = tracker.get_progress(&session_id).unwrap();
        assert_eq!(progress.chunks_sent, 1);
        assert_eq!(progress.bytes_sent, 100);
        assert_eq!(progress.progress_percentage(), 0.1);
        
        // Complete transfer
        assert!(tracker.complete_transfer(&session_id).is_ok());
        
        let progress = tracker.get_progress(&session_id).unwrap();
        assert!(progress.is_complete());
    }

    #[test]
    fn test_progress_events() {
        let tracker = Arc::new(ProgressTracker::default());
        let mut receiver = tracker.subscribe_events();
        let session_id = TransferSessionId::new("test_file.txt", "client1");
        
        // Start transfer in background
        let tracker_clone = Arc::clone(&tracker);
        let session_id_clone = session_id.clone();
        thread::spawn(move || {
            tracker_clone.start_transfer(
                session_id_clone,
                "test_file.txt".to_string(),
                1000,
                10
            ).unwrap();
        });
        
        // Receive event
        let event = receiver.blocking_recv().unwrap();
        match event {
            ProgressEvent::TransferStarted { session_id: id, file_name, .. } => {
                assert_eq!(id, session_id);
                assert_eq!(file_name, "test_file.txt");
            }
            actual_event => {
                assert!(
                    false,
                    "Expected TransferStarted event, but got: {:?}",
                    actual_event
                );
            }
        }
    }

    #[test]
    fn test_metrics_update() {
        let tracker = ProgressTracker::default();
        let session_id = TransferSessionId::new("test_file.txt", "client1");
        
        tracker.start_transfer(
            session_id.clone(),
            "test_file.txt".to_string(),
            1000,
            10
        ).unwrap();
        
        let metrics = tracker.get_metrics();
        assert_eq!(metrics.active_transfers, 1);
        assert_eq!(metrics.completed_transfers, 0);
        
        tracker.complete_transfer(&session_id).unwrap();
        
        let metrics = tracker.get_metrics();
        assert_eq!(metrics.active_transfers, 0);
        assert_eq!(metrics.completed_transfers, 1);
    }

    #[test]
    fn test_enhanced_progress_calculations() {
        let tracker = ProgressTracker::default();
        let session_id = TransferSessionId::new("calc_test.txt", "client1");
        
        // Start transfer
        tracker.start_transfer(
            session_id.clone(),
            "calc_test.txt".to_string(),
            1000,
            10
        ).unwrap();
        
        // Simulate some progress
        tracker.update_chunk_sent(&session_id, 0, 100).unwrap();
        tracker.update_chunk_sent(&session_id, 1, 100).unwrap();
        
        let progress = tracker.get_progress(&session_id).unwrap();
        
        // Test enhanced methods
        assert_eq!(progress.chunk_progress_percentage(), 0.2); // 2/10 chunks
        assert_eq!(progress.progress_percentage(), 0.2); // 200/1000 bytes
        assert_eq!(progress.get_efficiency_ratio(), 1.0); // No failures
        assert!(!progress.is_stalled()); // Recently active
        
        // Test progress info
        let info = progress.get_progress_info();
        assert_eq!(info.chunks_sent, 2);
        assert_eq!(info.bytes_sent, 200);
        assert_eq!(info.byte_percentage, 0.2);
        assert_eq!(info.chunk_percentage, 0.2);
        assert!(!info.is_stalled);
    }

    #[test]
    fn test_progress_visualization() {
        let tracker = ProgressTracker::default();
        let session_id = TransferSessionId::new("viz_test.txt", "client1");
        
        // Start transfer
        tracker.start_transfer(
            session_id.clone(),
            "viz_test.txt".to_string(),
            1000,
            10
        ).unwrap();
        
        // Simulate 50% progress
        for i in 0..5 {
            tracker.update_chunk_sent(&session_id, i, 100).unwrap();
        }
        
        // Test progress bar
        let progress_bar = tracker.create_progress_bar(&session_id, 20).unwrap();
        assert!(progress_bar.contains("50.0%"));
        assert!(progress_bar.contains("█")); // Should have filled blocks
        assert!(progress_bar.contains("░")); // Should have empty blocks
        
        // Test formatted status
        let status = tracker.format_transfer_status(&session_id).unwrap();
        assert!(status.contains("viz_test.txt"));
        assert!(status.contains("50.0%"));
        assert!(status.contains("Chunks: 5/10"));
    }

    #[test]
    fn test_progress_report_generation() {
        let tracker = ProgressTracker::default();
        let session_id1 = TransferSessionId::new("report_test1.txt", "client1");
        let session_id2 = TransferSessionId::new("report_test2.txt", "client2");
        
        // Start multiple transfers
        tracker.start_transfer(
            session_id1.clone(),
            "report_test1.txt".to_string(),
            1000,
            10
        ).unwrap();
        
        tracker.start_transfer(
            session_id2.clone(),
            "report_test2.txt".to_string(),
            2000,
            20
        ).unwrap();
        
        // Add some progress
        tracker.update_chunk_sent(&session_id1, 0, 100).unwrap();
        tracker.update_chunk_sent(&session_id2, 0, 200).unwrap();
        
        // Generate report
        let report = tracker.generate_progress_report();
        assert!(report.contains("=== UDCN Transport Progress Report ==="));
        assert!(report.contains("Active Transfers: 2"));
        // Check that the report contains some percentage progress
        assert!(report.contains("%"));
        // Check that it contains chunk information
        assert!(report.contains("chunks"));
    }

    #[test]
    fn test_bulk_progress_operations() {
        let tracker = ProgressTracker::default();
        let session_ids: Vec<_> = (0..3)
            .map(|i| TransferSessionId::new(&format!("bulk_test_{}.txt", i), "client1"))
            .collect();
        
        // Start multiple transfers
        for (i, session_id) in session_ids.iter().enumerate() {
            tracker.start_transfer(
                session_id.clone(),
                format!("bulk_test_{}.txt", i),
                (i + 1) as u64 * 1000,
                (i + 1) as u32 * 10
            ).unwrap();
            
            // Add different amounts of progress
            for j in 0..=i {
                tracker.update_chunk_sent(session_id, j as u32, 100).unwrap();
            }
        }
        
        // Test bulk progress retrieval
        let progress_infos = tracker.get_bulk_progress(&session_ids);
        assert_eq!(progress_infos.len(), 3);
        assert!(progress_infos.iter().all(|p| p.is_some()));
        
        // Test all progress info
        let all_progress = tracker.get_all_progress_info();
        assert_eq!(all_progress.len(), 3);
        
        // Verify different progress levels (order may vary due to HashMap)
        let mut chunk_counts: Vec<_> = all_progress.iter().map(|p| p.chunks_sent).collect();
        chunk_counts.sort();
        assert_eq!(chunk_counts, vec![1, 2, 3]);
    }
}