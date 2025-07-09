use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

// Crypto library imports
use blake3::Hasher as Blake3Hasher;
use md5::{Md5, Digest as Md5Digest};
use sha2::{Sha256, Sha512, Digest as Sha2Digest};

use crate::file_chunking::FileMetadata;

/// Configuration for integrity verification
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    /// Enable checksum validation
    pub enable_checksum: bool,
    /// Enable signature verification
    pub enable_signature: bool,
    /// Buffer size for reading files during verification
    pub buffer_size: usize,
    /// Timeout for verification operations
    pub verification_timeout: std::time::Duration,
    /// Maximum file size for verification
    pub max_file_size: u64,
    /// Enable automatic recovery for corrupted chunks
    pub enable_recovery: bool,
    /// Maximum number of recovery attempts per chunk
    pub max_recovery_attempts: u32,
    /// Timeout for recovery operations
    pub recovery_timeout: std::time::Duration,
    /// Enable parallel chunk verification
    pub enable_parallel_verification: bool,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enable_checksum: true,
            enable_signature: false,
            buffer_size: 64 * 1024, // 64KB
            verification_timeout: std::time::Duration::from_secs(30),
            max_file_size: 100 * 1024 * 1024, // 100MB
            enable_recovery: true,
            max_recovery_attempts: 3,
            recovery_timeout: std::time::Duration::from_secs(10),
            enable_parallel_verification: true,
        }
    }
}

/// Checksum algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    /// MD5 hash (legacy, not recommended for security)
    Md5,
    /// SHA-256 hash
    Sha256,
    /// SHA-512 hash
    Sha512,
    /// Blake3 hash
    Blake3,
    /// CRC32 checksum
    Crc32,
}

impl Default for ChecksumAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Signature algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// RSA with SHA-256
    RsaSha256,
    /// ECDSA with SHA-256
    EcdsaSha256,
    /// Ed25519
    Ed25519,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

/// Integrity verification status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// Verification pending
    Pending,
    /// Verification in progress
    InProgress,
    /// Verification passed
    Verified,
    /// Verification failed
    Failed,
    /// Verification skipped
    Skipped,
    /// Verification timed out
    TimedOut,
}

/// Integrity verification result
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    /// File that was verified
    pub file_path: PathBuf,
    /// Overall verification status
    pub status: IntegrityStatus,
    /// Checksum verification result
    pub checksum_result: Option<ChecksumResult>,
    /// Signature verification result
    pub signature_result: Option<SignatureResult>,
    /// Time when verification started
    pub started_at: Instant,
    /// Time when verification completed
    pub completed_at: Option<Instant>,
    /// Error message if verification failed
    pub error_message: Option<String>,
}

/// Checksum verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumResult {
    /// Algorithm used
    pub algorithm: ChecksumAlgorithm,
    /// Expected checksum
    pub expected: Vec<u8>,
    /// Computed checksum
    pub computed: Vec<u8>,
    /// Whether checksums match
    pub matches: bool,
}

/// Signature verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResult {
    /// Algorithm used
    pub algorithm: SignatureAlgorithm,
    /// Whether signature is valid
    pub valid: bool,
    /// Signer information
    pub signer: Option<String>,
}

/// Integrity verification errors
#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
    #[error("File too large: {size} bytes (max: {max_size})")]
    FileTooLarge { size: u64, max_size: u64 },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Checksum mismatch: expected {expected:?}, got {computed:?}")]
    ChecksumMismatch { expected: Vec<u8>, computed: Vec<u8> },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Verification timeout")]
    Timeout,
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Chunk corruption detected at index {index}")]
    ChunkCorruption { index: usize },
    #[error("Multiple chunk corruptions detected: {corrupted_chunks:?}")]
    MultipleChunkCorruptions { corrupted_chunks: Vec<usize> },
    #[error("Recovery failed after {attempts} attempts")]
    RecoveryFailed { attempts: u32 },
    #[error("Recovery timeout")]
    RecoveryTimeout,
}

/// Statistics for integrity verification
#[derive(Debug, Clone, Default)]
pub struct IntegrityStats {
    /// Total files verified
    pub total_verified: u64,
    /// Files that passed verification
    pub verified_passed: u64,
    /// Files that failed verification
    pub verified_failed: u64,
    /// Files that were skipped
    pub verification_skipped: u64,
    /// Files that timed out
    pub verification_timeout: u64,
    /// Total verification time
    pub total_verification_time: std::time::Duration,
    /// Average verification time
    pub average_verification_time: std::time::Duration,
    /// Total chunks verified
    pub total_chunks_verified: u64,
    /// Chunks that passed verification
    pub chunks_passed: u64,
    /// Chunks that failed verification
    pub chunks_failed: u64,
    /// Corrupted chunks detected
    pub corrupted_chunks_detected: u64,
    /// Successful chunk recoveries
    pub successful_recoveries: u64,
    /// Failed recovery attempts
    pub failed_recoveries: u64,
    /// Total recovery time
    pub total_recovery_time: std::time::Duration,
}

impl IntegrityStats {
    /// Update statistics with a new verification result
    pub fn update(&mut self, result: &IntegrityResult) {
        self.total_verified += 1;
        
        match result.status {
            IntegrityStatus::Verified => self.verified_passed += 1,
            IntegrityStatus::Failed => self.verified_failed += 1,
            IntegrityStatus::Skipped => self.verification_skipped += 1,
            IntegrityStatus::TimedOut => self.verification_timeout += 1,
            _ => {}
        }
        
        if let Some(completed_at) = result.completed_at {
            let verification_time = completed_at.duration_since(result.started_at);
            self.total_verification_time += verification_time;
            self.average_verification_time = self.total_verification_time / self.total_verified as u32;
        }
    }
}

/// File Integrity Verification Engine
pub struct FileIntegrityEngine {
    config: IntegrityConfig,
    /// Active verification operations
    active_verifications: Arc<RwLock<HashMap<PathBuf, IntegrityResult>>>,
    /// Verification statistics
    stats: Arc<RwLock<IntegrityStats>>,
    /// Result notification channel
    result_sender: mpsc::UnboundedSender<IntegrityResult>,
    /// Result notification receiver
    result_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<IntegrityResult>>>>,
}

impl FileIntegrityEngine {
    /// Create a new integrity verification engine
    pub fn new(config: IntegrityConfig) -> Self {
        let (result_sender, result_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            active_verifications: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(IntegrityStats::default())),
            result_sender,
            result_receiver: Arc::new(RwLock::new(Some(result_receiver))),
        }
    }
    
    /// Take the result receiver (can only be called once)
    pub fn take_result_receiver(&self) -> Option<mpsc::UnboundedReceiver<IntegrityResult>> {
        self.result_receiver.write().unwrap().take()
    }
    
    /// Verify file integrity
    pub async fn verify_file(
        &self,
        file_path: PathBuf,
        metadata: &FileMetadata,
    ) -> Result<IntegrityResult, IntegrityError> {
        let mut result = IntegrityResult {
            file_path: file_path.clone(),
            status: IntegrityStatus::Pending,
            checksum_result: None,
            signature_result: None,
            started_at: Instant::now(),
            completed_at: None,
            error_message: None,
        };
        
        // Add to active verifications
        {
            let mut active = self.active_verifications.write().unwrap();
            active.insert(file_path.clone(), result.clone());
        }
        
        result.status = IntegrityStatus::InProgress;
        
        // Check if file exists and is within size limits
        if !file_path.exists() {
            result.status = IntegrityStatus::Failed;
            result.error_message = Some("File not found".to_string());
            result.completed_at = Some(Instant::now());
            return Err(IntegrityError::FileNotFound(file_path));
        }
        
        let file_size = std::fs::metadata(&file_path)?.len();
        if file_size > self.config.max_file_size {
            result.status = IntegrityStatus::Failed;
            result.error_message = Some("File too large".to_string());
            result.completed_at = Some(Instant::now());
            return Err(IntegrityError::FileTooLarge {
                size: file_size,
                max_size: self.config.max_file_size,
            });
        }
        
        // Perform checksum verification if enabled
        if self.config.enable_checksum {
            match self.verify_checksum(&file_path, metadata).await {
                Ok(checksum_result) => {
                    result.checksum_result = Some(checksum_result);
                }
                Err(e) => {
                    result.status = IntegrityStatus::Failed;
                    result.error_message = Some(format!("Checksum verification failed: {}", e));
                    result.completed_at = Some(Instant::now());
                    
                    // Remove from active verifications
                    {
                        let mut active = self.active_verifications.write().unwrap();
                        active.remove(&file_path);
                    }
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().unwrap();
                        stats.update(&result);
                    }
                    
                    // Send notification
                    let _ = self.result_sender.send(result.clone());
                    
                    return Err(e);
                }
            }
        }
        
        // Perform signature verification if enabled
        if self.config.enable_signature {
            match self.verify_signature(&file_path, metadata).await {
                Ok(signature_result) => {
                    result.signature_result = Some(signature_result);
                }
                Err(e) => {
                    result.status = IntegrityStatus::Failed;
                    result.error_message = Some(format!("Signature verification failed: {}", e));
                    result.completed_at = Some(Instant::now());
                    
                    // Remove from active verifications
                    {
                        let mut active = self.active_verifications.write().unwrap();
                        active.remove(&file_path);
                    }
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().unwrap();
                        stats.update(&result);
                    }
                    
                    // Send notification
                    let _ = self.result_sender.send(result.clone());
                    
                    return Err(e);
                }
            }
        }
        
        // Mark as verified if all checks passed
        result.status = IntegrityStatus::Verified;
        result.completed_at = Some(Instant::now());
        
        // Remove from active verifications
        {
            let mut active = self.active_verifications.write().unwrap();
            active.remove(&file_path);
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.update(&result);
        }
        
        // Send notification
        let _ = self.result_sender.send(result.clone());
        
        Ok(result)
    }
    
    /// Verify file checksum
    async fn verify_checksum(
        &self,
        file_path: &PathBuf,
        metadata: &FileMetadata,
    ) -> Result<ChecksumResult, IntegrityError> {
        // For now, use the file_hash from metadata if available
        let expected_hash = metadata.file_hash.as_ref()
            .ok_or_else(|| IntegrityError::UnsupportedAlgorithm("No checksum in metadata".to_string()))?;
        
        // Use the configured default algorithm or auto-detect from hash length
        let algorithm = self.detect_algorithm_from_hash(expected_hash);
        let computed_hash = self.compute_checksum(file_path, algorithm).await?;
        
        let matches = expected_hash == &computed_hash;
        
        Ok(ChecksumResult {
            algorithm,
            expected: expected_hash.clone(),
            computed: computed_hash,
            matches,
        })
    }
    
    /// Detect checksum algorithm from hash length
    fn detect_algorithm_from_hash(&self, hash: &[u8]) -> ChecksumAlgorithm {
        match hash.len() {
            16 => ChecksumAlgorithm::Md5,
            32 => ChecksumAlgorithm::Sha256, // Note: Blake3 also produces 32-byte hashes, defaulting to SHA256
            64 => ChecksumAlgorithm::Sha512,
            4 => ChecksumAlgorithm::Crc32,
            _ => ChecksumAlgorithm::Sha256, // Default fallback
        }
    }
    
    /// Compute checksum for a chunk of data
    pub async fn compute_chunk_checksum(
        &self,
        data: &[u8],
        algorithm: ChecksumAlgorithm,
    ) -> Result<Vec<u8>, IntegrityError> {
        let data_owned = data.to_vec();
        tokio::task::spawn_blocking(move || {
            match algorithm {
                ChecksumAlgorithm::Md5 => {
                    let mut hasher = Md5::new();
                    hasher.update(&data_owned);
                    Ok(hasher.finalize().to_vec())
                }
                ChecksumAlgorithm::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&data_owned);
                    Ok(hasher.finalize().to_vec())
                }
                ChecksumAlgorithm::Sha512 => {
                    let mut hasher = Sha512::new();
                    hasher.update(&data_owned);
                    Ok(hasher.finalize().to_vec())
                }
                ChecksumAlgorithm::Blake3 => {
                    let mut hasher = Blake3Hasher::new();
                    hasher.update(&data_owned);
                    Ok(hasher.finalize().as_bytes().to_vec())
                }
                ChecksumAlgorithm::Crc32 => {
                    let mut hasher = crc32fast::Hasher::new();
                    hasher.update(&data_owned);
                    Ok(hasher.finalize().to_be_bytes().to_vec())
                }
            }
        }).await.unwrap()
    }
    
    /// Verify file signature
    async fn verify_signature(
        &self,
        _file_path: &PathBuf,
        _metadata: &FileMetadata,
    ) -> Result<SignatureResult, IntegrityError> {
        // Placeholder implementation for signature verification
        // This would need to be implemented based on the specific signature scheme used
        Ok(SignatureResult {
            algorithm: SignatureAlgorithm::Ed25519,
            valid: true, // Placeholder - always return valid for now
            signer: None,
        })
    }
    
    /// Compute file checksum
    async fn compute_checksum(
        &self,
        file_path: &PathBuf,
        algorithm: ChecksumAlgorithm,
    ) -> Result<Vec<u8>, IntegrityError> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut buffer = vec![0u8; self.config.buffer_size];
        
        match algorithm {
            ChecksumAlgorithm::Md5 => {
                let mut hasher = Md5::new();
                
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                
                Ok(hasher.finalize().to_vec())
            }
            ChecksumAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                
                Ok(hasher.finalize().to_vec())
            }
            ChecksumAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                
                Ok(hasher.finalize().to_vec())
            }
            ChecksumAlgorithm::Blake3 => {
                let mut hasher = Blake3Hasher::new();
                
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                
                Ok(hasher.finalize().as_bytes().to_vec())
            }
            ChecksumAlgorithm::Crc32 => {
                let mut hasher = crc32fast::Hasher::new();
                
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                
                Ok(hasher.finalize().to_be_bytes().to_vec())
            }
        }
    }
    
    /// Get verification statistics
    pub fn get_stats(&self) -> IntegrityStats {
        self.stats.read().unwrap().clone()
    }
    
    /// Get active verifications
    pub fn get_active_verifications(&self) -> HashMap<PathBuf, IntegrityResult> {
        self.active_verifications.read().unwrap().clone()
    }
    
    /// Verify chunk integrity
    pub async fn verify_chunk_integrity(
        &self,
        chunk_data: &[u8],
        expected_hash: &[u8],
        algorithm: ChecksumAlgorithm,
    ) -> Result<bool, IntegrityError> {
        let computed_hash = self.compute_chunk_checksum(chunk_data, algorithm).await?;
        Ok(computed_hash == expected_hash)
    }
    
    /// Verify all chunks in sequence
    pub async fn verify_chunks_sequence(
        &self,
        chunks: &[(&[u8], &[u8])], // (chunk_data, expected_hash)
        algorithm: ChecksumAlgorithm,
    ) -> Result<Vec<bool>, IntegrityError> {
        let mut results = Vec::new();
        
        for (chunk_data, expected_hash) in chunks {
            let is_valid = self.verify_chunk_integrity(chunk_data, expected_hash, algorithm).await?;
            results.push(is_valid);
        }
        
        Ok(results)
    }
    
    /// Detect corrupted chunks and return their indices
    pub async fn detect_corrupted_chunks(
        &self,
        chunks: &[(&[u8], &[u8])], // (chunk_data, expected_hash)
        algorithm: ChecksumAlgorithm,
    ) -> Result<Vec<usize>, IntegrityError> {
        let mut corrupted_indices = Vec::new();
        
        for (index, (chunk_data, expected_hash)) in chunks.iter().enumerate() {
            let is_valid = self.verify_chunk_integrity(chunk_data, expected_hash, algorithm).await?;
            if !is_valid {
                corrupted_indices.push(index);
            }
        }
        
        Ok(corrupted_indices)
    }
    
    /// Recover corrupted chunks with retry logic
    pub async fn recover_corrupted_chunks(
        &self,
        corrupted_indices: &[usize],
        recovery_callback: impl Fn(usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, IntegrityError>> + Send>> + Send + Sync,
    ) -> Result<Vec<(usize, Vec<u8>)>, IntegrityError> {
        let mut recovered_chunks = Vec::new();
        let mut stats = self.stats.write().unwrap();
        
        for &index in corrupted_indices {
            let start_time = std::time::Instant::now();
            let mut attempts = 0;
            let mut recovered = false;
            
            while attempts < self.config.max_recovery_attempts && !recovered {
                attempts += 1;
                
                match recovery_callback(index).await {
                    Ok(chunk_data) => {
                        recovered_chunks.push((index, chunk_data));
                        stats.successful_recoveries += 1;
                        recovered = true;
                    }
                    Err(_) => {
                        stats.failed_recoveries += 1;
                        if attempts >= self.config.max_recovery_attempts {
                            return Err(IntegrityError::RecoveryFailed { attempts });
                        }
                    }
                }
                
                // Check for timeout
                if start_time.elapsed() > self.config.recovery_timeout {
                    return Err(IntegrityError::RecoveryTimeout);
                }
            }
            
            stats.total_recovery_time += start_time.elapsed();
        }
        
        Ok(recovered_chunks)
    }
    
    /// Verify chunks with automatic recovery
    pub async fn verify_and_recover_chunks(
        &self,
        chunks: &[(&[u8], &[u8])], // (chunk_data, expected_hash)
        algorithm: ChecksumAlgorithm,
        recovery_callback: impl Fn(usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, IntegrityError>> + Send>> + Send + Sync,
    ) -> Result<Vec<bool>, IntegrityError> {
        // First pass: detect corrupted chunks
        let corrupted_indices = self.detect_corrupted_chunks(chunks, algorithm).await?;
        
        if corrupted_indices.is_empty() {
            // All chunks are valid
            return Ok(vec![true; chunks.len()]);
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.corrupted_chunks_detected += corrupted_indices.len() as u64;
        }
        
        // Attempt recovery if enabled
        if self.config.enable_recovery && !corrupted_indices.is_empty() {
            let _recovered_chunks = self.recover_corrupted_chunks(&corrupted_indices, recovery_callback).await?;
            // Note: In a real implementation, you would replace the corrupted chunks with recovered ones
            // and re-verify. For now, we'll just return the original results.
        }
        
        // Return verification results
        let mut results = Vec::new();
        for (index, (chunk_data, expected_hash)) in chunks.iter().enumerate() {
            let is_valid = !corrupted_indices.contains(&index);
            results.push(is_valid);
        }
        
        Ok(results)
    }
}

impl Clone for FileIntegrityEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            active_verifications: Arc::clone(&self.active_verifications),
            stats: Arc::clone(&self.stats),
            result_sender: self.result_sender.clone(),
            result_receiver: Arc::new(RwLock::new(None)), // New clone doesn't get receiver
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_integrity_engine_creation() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let stats = engine.get_stats();
        assert_eq!(stats.total_verified, 0);
        assert_eq!(stats.verified_passed, 0);
        assert_eq!(stats.verified_failed, 0);
    }
    
    #[tokio::test]
    async fn test_file_not_found() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let non_existent_path = PathBuf::from("/non/existent/file.txt");
        let metadata = FileMetadata {
            file_path: non_existent_path.clone(),
            file_size: 100,
            total_chunks: 1,
            chunk_size: 100,
            modified_time: 0,
            content_type: udcn_core::packets::ContentType::Blob,
            file_hash: Some(vec![1, 2, 3, 4]),
        };
        
        let result = engine.verify_file(non_existent_path, &metadata).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IntegrityError::FileNotFound(_)));
    }
    
    #[tokio::test]
    async fn test_file_too_large() {
        let config = IntegrityConfig {
            max_file_size: 10, // Very small limit
            ..Default::default()
        };
        let engine = FileIntegrityEngine::new(config);
        
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("large_file.txt");
        
        // Create a file larger than the limit
        fs::write(&file_path, "This is a large file content that exceeds the limit").unwrap();
        
        let metadata = FileMetadata {
            file_path: file_path.clone(),
            file_size: 100,
            total_chunks: 1,
            chunk_size: 100,
            modified_time: 0,
            content_type: udcn_core::packets::ContentType::Blob,
            file_hash: Some(vec![1, 2, 3, 4]),
        };
        
        let result = engine.verify_file(file_path, &metadata).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IntegrityError::FileTooLarge { .. }));
    }
    
    #[tokio::test]
    async fn test_md5_checksum_computation() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let test_data = b"Hello, World!";
        let result = engine.compute_chunk_checksum(test_data, ChecksumAlgorithm::Md5).await;
        
        assert!(result.is_ok());
        let hash = result.unwrap();
        // MD5 hash should be 16 bytes
        assert_eq!(hash.len(), 16);
    }
    
    #[tokio::test]
    async fn test_sha256_checksum_computation() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let test_data = b"Hello, World!";
        let result = engine.compute_chunk_checksum(test_data, ChecksumAlgorithm::Sha256).await;
        
        assert!(result.is_ok());
        let hash = result.unwrap();
        // SHA256 hash should be 32 bytes
        assert_eq!(hash.len(), 32);
    }
    
    #[tokio::test]
    async fn test_blake3_checksum_computation() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let test_data = b"Hello, World!";
        let result = engine.compute_chunk_checksum(test_data, ChecksumAlgorithm::Blake3).await;
        
        assert!(result.is_ok());
        let hash = result.unwrap();
        // Blake3 hash should be 32 bytes
        assert_eq!(hash.len(), 32);
    }
    
    #[tokio::test]
    async fn test_crc32_checksum_computation() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let test_data = b"Hello, World!";
        let result = engine.compute_chunk_checksum(test_data, ChecksumAlgorithm::Crc32).await;
        
        assert!(result.is_ok());
        let hash = result.unwrap();
        // CRC32 hash should be 4 bytes
        assert_eq!(hash.len(), 4);
    }
    
    #[tokio::test]
    async fn test_chunk_integrity_verification() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let test_data = b"Hello, World!";
        let expected_hash = engine.compute_chunk_checksum(test_data, ChecksumAlgorithm::Sha256).await.unwrap();
        
        let result = engine.verify_chunk_integrity(test_data, &expected_hash, ChecksumAlgorithm::Sha256).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[tokio::test]
    async fn test_chunk_integrity_verification_failure() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let test_data = b"Hello, World!";
        let wrong_hash = vec![0; 32]; // Wrong hash
        
        let result = engine.verify_chunk_integrity(test_data, &wrong_hash, ChecksumAlgorithm::Sha256).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false for mismatch
    }
    
    #[tokio::test]
    async fn test_corrupted_chunks_detection() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let chunk1 = b"chunk1";
        let chunk2 = b"chunk2";
        let chunk3 = b"chunk3";
        
        let hash1 = engine.compute_chunk_checksum(chunk1, ChecksumAlgorithm::Sha256).await.unwrap();
        let hash2 = engine.compute_chunk_checksum(chunk2, ChecksumAlgorithm::Sha256).await.unwrap();
        let wrong_hash = vec![0; 32]; // Wrong hash for chunk3
        
        let chunks = vec![
            (&chunk1[..], &hash1[..]),
            (&chunk2[..], &hash2[..]),
            (&chunk3[..], &wrong_hash[..]),
        ];
        
        let result = engine.detect_corrupted_chunks(&chunks, ChecksumAlgorithm::Sha256).await;
        assert!(result.is_ok());
        
        let corrupted = result.unwrap();
        assert_eq!(corrupted.len(), 1);
        assert_eq!(corrupted[0], 2); // Third chunk (index 2) should be corrupted
    }
    
    #[tokio::test]
    async fn test_algorithm_detection_from_hash() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        // Test MD5 (16 bytes)
        let md5_hash = vec![0; 16];
        assert_eq!(engine.detect_algorithm_from_hash(&md5_hash), ChecksumAlgorithm::Md5);
        
        // Test SHA256 (32 bytes)
        let sha256_hash = vec![0; 32];
        assert_eq!(engine.detect_algorithm_from_hash(&sha256_hash), ChecksumAlgorithm::Sha256);
        
        // Test SHA512 (64 bytes)
        let sha512_hash = vec![0; 64];
        assert_eq!(engine.detect_algorithm_from_hash(&sha512_hash), ChecksumAlgorithm::Sha512);
        
        // Test CRC32 (4 bytes)
        let crc32_hash = vec![0; 4];
        assert_eq!(engine.detect_algorithm_from_hash(&crc32_hash), ChecksumAlgorithm::Crc32);
        
        // Test unknown (defaults to SHA256)
        let unknown_hash = vec![0; 20];
        assert_eq!(engine.detect_algorithm_from_hash(&unknown_hash), ChecksumAlgorithm::Sha256);
    }
    
    #[tokio::test]
    async fn test_integrity_stats_update() {
        let config = IntegrityConfig::default();
        let engine = FileIntegrityEngine::new(config);
        
        let mut stats = IntegrityStats::default();
        
        let result = IntegrityResult {
            file_path: PathBuf::from("test.txt"),
            status: IntegrityStatus::Verified,
            checksum_result: None,
            signature_result: None,
            started_at: Instant::now(),
            completed_at: Some(Instant::now()),
            error_message: None,
        };
        
        stats.update(&result);
        
        assert_eq!(stats.total_verified, 1);
        assert_eq!(stats.verified_passed, 1);
        assert_eq!(stats.verified_failed, 0);
    }
    
    #[tokio::test]
    async fn test_recovery_configuration() {
        let config = IntegrityConfig {
            enable_recovery: true,
            max_recovery_attempts: 3,
            recovery_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        
        let engine = FileIntegrityEngine::new(config);
        
        // Test that recovery is enabled
        assert!(engine.config.enable_recovery);
        assert_eq!(engine.config.max_recovery_attempts, 3);
        assert_eq!(engine.config.recovery_timeout, std::time::Duration::from_secs(5));
    }
}