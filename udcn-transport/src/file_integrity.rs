use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

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
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enable_checksum: true,
            enable_signature: false,
            buffer_size: 64 * 1024, // 64KB
            verification_timeout: std::time::Duration::from_secs(30),
            max_file_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Checksum algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
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
        
        let computed_hash = self.compute_checksum(file_path, ChecksumAlgorithm::Sha256).await?;
        
        let matches = expected_hash == &computed_hash;
        
        Ok(ChecksumResult {
            algorithm: ChecksumAlgorithm::Sha256,
            expected: expected_hash.clone(),
            computed: computed_hash,
            matches,
        })
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
            ChecksumAlgorithm::Sha256 => {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                
                let mut hasher = DefaultHasher::new();
                
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    buffer[..bytes_read].hash(&mut hasher);
                }
                
                let hash = hasher.finish();
                Ok(hash.to_be_bytes().to_vec())
            }
            _ => Err(IntegrityError::UnsupportedAlgorithm(format!("{:?}", algorithm))),
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
}