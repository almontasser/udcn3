use anyhow::{anyhow, Result};
use std::collections::{HashMap, BTreeMap};
use std::fs::File;
use std::io::{Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::file_chunking::{ChunkInfo, FileChunk, FileMetadata};
use crate::file_integrity::{FileIntegrityEngine, IntegrityConfig};
use udcn_core::packets::Name;

/// Configuration for file reassembly
#[derive(Debug, Clone)]
pub struct ReassemblyConfig {
    /// Maximum number of concurrent file reassemblies
    pub max_concurrent_files: usize,
    /// Timeout for reassembly operations
    pub reassembly_timeout: Duration,
    /// Maximum memory usage for buffering chunks (in bytes)
    pub max_buffer_memory: usize,
    /// Whether to enable duplicate chunk detection
    pub enable_duplicate_detection: bool,
    /// Directory to store temporary reassembly files
    pub temp_directory: PathBuf,
    /// Whether to verify file integrity after reassembly
    pub verify_integrity: bool,
    /// Maximum number of out-of-order chunks to buffer
    pub max_out_of_order_chunks: usize,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_concurrent_files: 10,
            reassembly_timeout: Duration::from_secs(300), // 5 minutes
            max_buffer_memory: 50 * 1024 * 1024, // 50MB
            enable_duplicate_detection: true,
            temp_directory: std::env::temp_dir(),
            verify_integrity: true,
            max_out_of_order_chunks: 100,
        }
    }
}

/// Status of file reassembly
#[derive(Debug, Clone, PartialEq)]
pub enum ReassemblyStatus {
    /// Reassembly is in progress
    InProgress,
    /// Reassembly completed successfully
    Completed,
    /// Reassembly failed with error
    Failed(String),
    /// Reassembly timed out
    TimedOut,
    /// Reassembly was cancelled
    Cancelled,
}

/// Progress information for file reassembly
#[derive(Debug, Clone)]
pub struct ReassemblyProgress {
    /// File being reassembled
    pub file_name: String,
    /// Total expected chunks
    pub total_chunks: usize,
    /// Chunks received so far
    pub received_chunks: usize,
    /// Chunks successfully processed
    pub processed_chunks: usize,
    /// Duplicate chunks detected
    pub duplicate_chunks: usize,
    /// Out-of-order chunks buffered
    pub out_of_order_chunks: usize,
    /// Current status
    pub status: ReassemblyStatus,
    /// Time when reassembly started
    pub started_at: Instant,
    /// Current reassembly speed (chunks per second)
    pub reassembly_speed: f64,
    /// Estimated time remaining
    pub estimated_remaining: Option<Duration>,
}

/// Statistics for the reassembly engine
#[derive(Debug, Clone, Default)]
pub struct ReassemblyStats {
    /// Total files reassembled
    pub total_files: usize,
    /// Successfully completed files
    pub completed_files: usize,
    /// Failed reassemblies
    pub failed_files: usize,
    /// Total chunks processed
    pub total_chunks_processed: usize,
    /// Duplicate chunks detected
    pub duplicate_chunks_detected: usize,
    /// Out-of-order chunks handled
    pub out_of_order_chunks_handled: usize,
    /// Average reassembly time
    pub avg_reassembly_time: Duration,
    /// Total bytes reassembled
    pub total_bytes_reassembled: u64,
}

/// Individual file reassembly state
#[derive(Debug)]
struct FileReassemblyState {
    /// File metadata
    metadata: FileMetadata,
    /// Temporary file for reassembly
    temp_file: File,
    /// Temporary file path
    temp_path: PathBuf,
    /// Final output path
    output_path: PathBuf,
    /// Chunks received so far (sequence -> chunk_info)
    received_chunks: BTreeMap<usize, ChunkInfo>,
    /// Duplicate detection cache
    duplicate_cache: HashMap<usize, Instant>,
    /// Out-of-order chunks buffer
    out_of_order_buffer: HashMap<usize, Vec<u8>>,
    /// Next expected chunk sequence
    next_expected_sequence: usize,
    /// Total chunks written to file
    written_chunks: usize,
    /// Progress information
    progress: ReassemblyProgress,
    /// Channel for progress updates
    progress_sender: Option<mpsc::UnboundedSender<ReassemblyProgress>>,
}

impl FileReassemblyState {
    fn new(
        metadata: FileMetadata,
        output_path: PathBuf,
        temp_dir: &Path,
        progress_sender: Option<mpsc::UnboundedSender<ReassemblyProgress>>,
    ) -> Result<Self> {
        // Create unique temporary file name
        let temp_filename = format!(
            "reassembly_{}_{}.tmp",
            metadata.file_path.file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            std::process::id()
        );
        let temp_path = temp_dir.join(temp_filename);
        
        // Create temporary file
        let temp_file = File::create(&temp_path)?;
        
        let progress = ReassemblyProgress {
            file_name: output_path.display().to_string(),
            total_chunks: metadata.total_chunks,
            received_chunks: 0,
            processed_chunks: 0,
            duplicate_chunks: 0,
            out_of_order_chunks: 0,
            status: ReassemblyStatus::InProgress,
            started_at: Instant::now(),
            reassembly_speed: 0.0,
            estimated_remaining: None,
        };

        Ok(Self {
            metadata,
            temp_file,
            temp_path,
            output_path,
            received_chunks: BTreeMap::new(),
            duplicate_cache: HashMap::new(),
            out_of_order_buffer: HashMap::new(),
            next_expected_sequence: 0,
            written_chunks: 0,
            progress,
            progress_sender,
        })
    }

    /// Process a received chunk
    fn process_chunk(&mut self, chunk: &FileChunk, config: &ReassemblyConfig) -> Result<bool> {
        let sequence = chunk.chunk_info.sequence;
        
        // Check for duplicates
        if config.enable_duplicate_detection {
            if self.duplicate_cache.contains_key(&sequence) {
                debug!("Duplicate chunk detected: sequence {}", sequence);
                self.progress.duplicate_chunks += 1;
                self.send_progress_update();
                return Ok(false);
            }
            self.duplicate_cache.insert(sequence, Instant::now());
        }

        // Update received chunks
        self.received_chunks.insert(sequence, chunk.chunk_info.clone());
        self.progress.received_chunks += 1;

        // Check if this is the next expected chunk
        if sequence == self.next_expected_sequence {
            // Write this chunk and any subsequent buffered chunks
            self.write_chunk_data(&chunk.data.content)?;
            self.next_expected_sequence += 1;
            self.written_chunks += 1;
            self.progress.processed_chunks += 1;

            // Process any buffered out-of-order chunks
            while let Some(buffered_data) = self.out_of_order_buffer.remove(&self.next_expected_sequence) {
                self.write_chunk_data(&buffered_data)?;
                self.next_expected_sequence += 1;
                self.written_chunks += 1;
                self.progress.processed_chunks += 1;
                self.progress.out_of_order_chunks -= 1;
            }
        } else if sequence > self.next_expected_sequence {
            // Buffer out-of-order chunk
            if self.out_of_order_buffer.len() < config.max_out_of_order_chunks {
                self.out_of_order_buffer.insert(sequence, chunk.data.content.clone());
                self.progress.out_of_order_chunks += 1;
                debug!("Buffered out-of-order chunk: sequence {}", sequence);
            } else {
                warn!("Out-of-order buffer full, dropping chunk: sequence {}", sequence);
                return Ok(false);
            }
        } else {
            // Old chunk, might be a duplicate or retransmission
            debug!("Received old chunk: sequence {} (expected: {})", sequence, self.next_expected_sequence);
            return Ok(false);
        }

        // Update progress statistics
        self.update_progress_stats();
        self.send_progress_update();

        // Check if reassembly is complete
        Ok(self.is_complete())
    }

    /// Write chunk data to the temporary file
    fn write_chunk_data(&mut self, data: &[u8]) -> Result<()> {
        let expected_offset = (self.next_expected_sequence * self.metadata.chunk_size) as u64;
        self.temp_file.seek(SeekFrom::Start(expected_offset))?;
        self.temp_file.write_all(data)?;
        self.temp_file.flush()?;
        Ok(())
    }

    /// Check if reassembly is complete
    fn is_complete(&self) -> bool {
        self.written_chunks == self.metadata.total_chunks
    }

    /// Update progress statistics
    fn update_progress_stats(&mut self) {
        let elapsed = self.progress.started_at.elapsed();
        if !elapsed.is_zero() {
            self.progress.reassembly_speed = self.progress.processed_chunks as f64 / elapsed.as_secs_f64();
            
            if self.progress.reassembly_speed > 0.0 {
                let remaining_chunks = self.metadata.total_chunks - self.progress.processed_chunks;
                let remaining_seconds = remaining_chunks as f64 / self.progress.reassembly_speed;
                self.progress.estimated_remaining = Some(Duration::from_secs_f64(remaining_seconds));
            }
        }
    }

    /// Send progress update to subscribers
    fn send_progress_update(&self) {
        if let Some(sender) = &self.progress_sender {
            let _ = sender.send(self.progress.clone());
        }
    }

    /// Finalize reassembly by moving temp file to final location
    async fn finalize(&mut self, config: &ReassemblyConfig, integrity_engine: &Option<FileIntegrityEngine>) -> Result<()> {
        // Close temp file
        drop(std::mem::replace(&mut self.temp_file, File::create("/dev/null")?));

        // Ensure output directory exists
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Move temp file to final location
        std::fs::rename(&self.temp_path, &self.output_path)?;

        // Perform integrity verification if enabled
        if config.verify_integrity {
            if let Some(integrity_engine) = integrity_engine {
                match integrity_engine.verify_file(self.output_path.clone(), &self.metadata).await {
                    Ok(result) => {
                        info!("File integrity verification completed: {:?} - Status: {:?}", 
                              self.output_path, result.status);
                        
                        // If verification failed, mark reassembly as failed
                        if result.status != crate::file_integrity::IntegrityStatus::Verified {
                            self.progress.status = ReassemblyStatus::Failed(
                                result.error_message.unwrap_or_else(|| "Integrity verification failed".to_string())
                            );
                            self.send_progress_update();
                            return Err(anyhow!("File integrity verification failed"));
                        }
                    }
                    Err(e) => {
                        error!("Integrity verification error: {}", e);
                        self.progress.status = ReassemblyStatus::Failed(format!("Integrity verification error: {}", e));
                        self.send_progress_update();
                        return Err(anyhow!("Integrity verification failed: {}", e));
                    }
                }
            }
        }

        // Update progress
        self.progress.status = ReassemblyStatus::Completed;
        self.send_progress_update();

        info!("File reassembly completed: {:?}", self.output_path);
        Ok(())
    }

    /// Cleanup temporary files
    fn cleanup(&mut self) {
        if self.temp_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.temp_path) {
                warn!("Failed to cleanup temp file {:?}: {}", self.temp_path, e);
            }
        }
    }
}

impl Drop for FileReassemblyState {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// File Reassembly Engine
pub struct FileReassemblyEngine {
    config: ReassemblyConfig,
    /// Active reassembly operations (file_name -> state)
    active_reassemblies: Arc<RwLock<HashMap<String, Mutex<FileReassemblyState>>>>,
    /// Statistics
    stats: Arc<RwLock<ReassemblyStats>>,
    /// Progress update sender
    progress_sender: mpsc::UnboundedSender<ReassemblyProgress>,
    /// Progress update receiver
    progress_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<ReassemblyProgress>>>>,
    /// Chunk input channel
    chunk_sender: mpsc::UnboundedSender<FileChunk>,
    /// Chunk input receiver
    chunk_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<FileChunk>>>>,
    /// Integrity verification engine
    integrity_engine: Option<FileIntegrityEngine>,
}

impl FileReassemblyEngine {
    /// Create a new file reassembly engine
    pub fn new(config: ReassemblyConfig) -> Self {
        let (progress_sender, progress_receiver) = mpsc::unbounded_channel();
        let (chunk_sender, chunk_receiver) = mpsc::unbounded_channel();
        
        // Initialize integrity engine if verification is enabled
        let integrity_engine = if config.verify_integrity {
            Some(FileIntegrityEngine::new(IntegrityConfig::default()))
        } else {
            None
        };

        Self {
            config,
            active_reassemblies: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ReassemblyStats::default())),
            progress_sender,
            progress_receiver: Arc::new(RwLock::new(Some(progress_receiver))),
            chunk_sender,
            chunk_receiver: Arc::new(RwLock::new(Some(chunk_receiver))),
            integrity_engine,
        }
    }

    /// Start the reassembly engine
    pub async fn start(&self) -> Result<()> {
        info!("Starting file reassembly engine");

        // Start chunk processing task
        self.start_chunk_processing().await;

        // Start cleanup task
        self.start_cleanup_task().await;

        Ok(())
    }

    /// Get chunk input sender for integration with data reception handler
    pub fn get_chunk_sender(&self) -> mpsc::UnboundedSender<FileChunk> {
        self.chunk_sender.clone()
    }

    /// Get progress update receiver
    pub async fn get_progress_receiver(&self) -> Option<mpsc::UnboundedReceiver<ReassemblyProgress>> {
        self.progress_receiver.write().await.take()
    }

    /// Process a file chunk
    pub async fn process_chunk(&self, chunk: FileChunk, output_path: PathBuf) -> Result<()> {
        let file_name = self.extract_file_name(&chunk.name)?;
        
        // Check if we have an active reassembly for this file
        let mut reassemblies = self.active_reassemblies.write().await;
        
        if !reassemblies.contains_key(&file_name) {
            // Start new reassembly if we have the metadata (first chunk)
            if let Some(metadata) = &chunk.chunk_info.file_metadata {
                let state = FileReassemblyState::new(
                    metadata.clone(),
                    output_path,
                    &self.config.temp_directory,
                    Some(self.progress_sender.clone()),
                )?;
                reassemblies.insert(file_name.clone(), Mutex::new(state));
                
                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.total_files += 1;
                }
            } else {
                return Err(anyhow!("Cannot start reassembly without metadata (first chunk)"));
            }
        }

        // Process chunk
        if let Some(state_mutex) = reassemblies.get(&file_name) {
            let mut state = state_mutex.lock().await;
            let is_complete = state.process_chunk(&chunk, &self.config)?;
            
            if is_complete {
                // Finalize reassembly
                state.finalize(&self.config, &self.integrity_engine).await?;
                
                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.completed_files += 1;
                    stats.total_chunks_processed += state.progress.processed_chunks;
                    stats.duplicate_chunks_detected += state.progress.duplicate_chunks;
                    stats.out_of_order_chunks_handled += state.progress.out_of_order_chunks;
                    stats.total_bytes_reassembled += state.metadata.file_size;
                    
                    // Update average reassembly time
                    let reassembly_time = state.progress.started_at.elapsed();
                    if stats.completed_files == 1 {
                        stats.avg_reassembly_time = reassembly_time;
                    } else {
                        let total_time = stats.avg_reassembly_time * (stats.completed_files - 1) as u32;
                        stats.avg_reassembly_time = (total_time + reassembly_time) / stats.completed_files as u32;
                    }
                }
                
                // Remove from active reassemblies
                drop(state);
                reassemblies.remove(&file_name);
            }
        }

        Ok(())
    }

    /// Extract file name from chunk name
    fn extract_file_name(&self, chunk_name: &Name) -> Result<String> {
        // Expected format: /file/path/segment/<sequence>
        let name_str = chunk_name.to_string();
        let parts: Vec<&str> = name_str.split('/').collect();
        
        if parts.len() < 3 {
            return Err(anyhow!("Invalid chunk name format: {}", name_str));
        }
        
        // Remove last two components (segment and sequence)
        let file_parts = &parts[..parts.len() - 2];
        Ok(file_parts.join("/"))
    }

    /// Start chunk processing task
    async fn start_chunk_processing(&self) {
        let engine = self.clone();
        let mut receiver = self.chunk_receiver.write().await.take()
            .expect("Chunk receiver should be available");
        
        tokio::spawn(async move {
            while let Some(chunk) = receiver.recv().await {
                // Extract output path from chunk name
                let output_path = match engine.extract_output_path(&chunk.name) {
                    Ok(path) => path,
                    Err(e) => {
                        error!("Failed to extract output path from chunk: {}", e);
                        continue;
                    }
                };

                // Process chunk with timeout
                let result = timeout(
                    engine.config.reassembly_timeout,
                    engine.process_chunk(chunk, output_path)
                ).await;

                if let Err(_) = result {
                    error!("Chunk processing timed out");
                }
            }
        });
    }

    /// Extract output path from chunk name
    fn extract_output_path(&self, chunk_name: &Name) -> Result<PathBuf> {
        let file_name = self.extract_file_name(chunk_name)?;
        // Convert NDN name to file path
        let path_str = file_name.trim_start_matches('/').replace('/', &std::path::MAIN_SEPARATOR.to_string());
        Ok(PathBuf::from(path_str))
    }

    /// Start cleanup task for expired reassemblies
    async fn start_cleanup_task(&self) {
        let reassemblies = self.active_reassemblies.clone();
        let stats = self.stats.clone();
        let timeout_duration = self.config.reassembly_timeout;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                let mut expired_files = Vec::new();
                
                // Find expired reassemblies
                {
                    let reassemblies_guard = reassemblies.read().await;
                    for (file_name, state_mutex) in reassemblies_guard.iter() {
                        let state = state_mutex.lock().await;
                        if state.progress.started_at.elapsed() > timeout_duration {
                            expired_files.push(file_name.clone());
                        }
                    }
                }
                
                // Remove expired reassemblies
                if !expired_files.is_empty() {
                    let expired_count = expired_files.len();
                    let mut reassemblies_guard = reassemblies.write().await;
                    for file_name in expired_files {
                        if let Some(state_mutex) = reassemblies_guard.remove(&file_name) {
                            let mut state = state_mutex.lock().await;
                            state.progress.status = ReassemblyStatus::TimedOut;
                            state.send_progress_update();
                            warn!("Reassembly timed out for file: {}", file_name);
                        }
                    }
                    
                    // Update stats
                    {
                        let mut stats_guard = stats.write().await;
                        stats_guard.failed_files += expired_count;
                    }
                }
            }
        });
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ReassemblyStats {
        self.stats.read().await.clone()
    }

    /// Get active reassemblies
    pub async fn get_active_reassemblies(&self) -> Vec<String> {
        let reassemblies = self.active_reassemblies.read().await;
        reassemblies.keys().cloned().collect()
    }

    /// Cancel reassembly for a specific file
    pub async fn cancel_reassembly(&self, file_name: &str) -> Result<()> {
        let mut reassemblies = self.active_reassemblies.write().await;
        if let Some(state_mutex) = reassemblies.remove(file_name) {
            let mut state = state_mutex.lock().await;
            state.progress.status = ReassemblyStatus::Cancelled;
            state.send_progress_update();
            info!("Cancelled reassembly for file: {}", file_name);
        }
        Ok(())
    }

    /// Cancel all active reassemblies
    pub async fn cancel_all_reassemblies(&self) -> Result<()> {
        let mut reassemblies = self.active_reassemblies.write().await;
        for (file_name, state_mutex) in reassemblies.drain() {
            let mut state = state_mutex.lock().await;
            state.progress.status = ReassemblyStatus::Cancelled;
            state.send_progress_update();
            info!("Cancelled reassembly for file: {}", file_name);
        }
        Ok(())
    }
}

impl Clone for FileReassemblyEngine {
    fn clone(&self) -> Self {
        let (progress_sender, progress_receiver) = mpsc::unbounded_channel();
        let (chunk_sender, chunk_receiver) = mpsc::unbounded_channel();

        Self {
            config: self.config.clone(),
            active_reassemblies: self.active_reassemblies.clone(),
            stats: self.stats.clone(),
            progress_sender,
            progress_receiver: Arc::new(RwLock::new(Some(progress_receiver))),
            chunk_sender,
            chunk_receiver: Arc::new(RwLock::new(Some(chunk_receiver))),
            integrity_engine: self.integrity_engine.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_chunking::FileMetadata;
    use std::io::Write;
    use tempfile::TempDir;
    use udcn_core::packets::{Data, Name};

    #[tokio::test]
    async fn test_file_reassembly_engine_creation() {
        let config = ReassemblyConfig::default();
        let engine = FileReassemblyEngine::new(config);
        
        assert!(engine.start().await.is_ok());
    }

    #[tokio::test]
    async fn test_chunk_processing() {
        let temp_dir = TempDir::new().unwrap();
        let config = ReassemblyConfig {
            temp_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let engine = FileReassemblyEngine::new(config);
        engine.start().await.unwrap();

        // Create test metadata
        let metadata = FileMetadata {
            file_path: PathBuf::from("/test/file.txt"),
            file_size: 100,
            total_chunks: 2,
            chunk_size: 50,
            modified_time: 0,
            content_type: udcn_core::packets::ContentType::Blob,
            file_hash: None,
        };

        // Create first chunk with metadata
        let chunk1 = FileChunk {
            name: Name::from_str("/test/file.txt/segment/0"),
            data: Data::new(Name::from_str("/test/file.txt/segment/0"), vec![1; 50]),
            chunk_info: ChunkInfo {
                sequence: 0,
                size: 50,
                offset: 0,
                is_final: false,
                file_metadata: Some(metadata),
                chunk_hash: None,
                hash_algorithm: None,
            },
        };

        let output_path = temp_dir.path().join("output.txt");
        assert!(engine.process_chunk(chunk1, output_path.clone()).await.is_ok());

        // Check that reassembly is active
        let active = engine.get_active_reassemblies().await;
        assert_eq!(active.len(), 1);
    }

    #[tokio::test]
    async fn test_file_name_extraction() {
        let config = ReassemblyConfig::default();
        let engine = FileReassemblyEngine::new(config);
        
        let chunk_name = Name::from_str("/test/file.txt/segment/0");
        let file_name = engine.extract_file_name(&chunk_name).unwrap();
        assert_eq!(file_name, "/test/file.txt");
    }

    #[tokio::test]
    async fn test_output_path_extraction() {
        let config = ReassemblyConfig::default();
        let engine = FileReassemblyEngine::new(config);
        
        let chunk_name = Name::from_str("/test/file.txt/segment/0");
        let output_path = engine.extract_output_path(&chunk_name).unwrap();
        assert_eq!(output_path, PathBuf::from("test/file.txt"));
    }
}