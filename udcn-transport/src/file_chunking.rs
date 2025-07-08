use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use udcn_core::packets::{Name, Data, MetaInfo, ContentType};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

/// Configuration for file chunking operations
#[derive(Debug, Clone)]
pub struct ChunkingConfig {
    /// Maximum size of each chunk in bytes
    pub chunk_size: usize,
    /// Buffer size for streaming reads
    pub buffer_size: usize,
    /// Whether to include file metadata in chunks
    pub include_metadata: bool,
    /// Custom content type for chunks
    pub content_type: ContentType,
    /// Maximum number of chunks to create (-1 for unlimited)
    pub max_chunks: i64,
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 8192,  // 8KB - good balance for QUIC
            buffer_size: 32768, // 32KB read buffer
            include_metadata: true,
            content_type: ContentType::Blob,
            max_chunks: -1, // unlimited
        }
    }
}

impl ChunkingConfig {
    /// Create config optimized for QUIC transport
    pub fn for_quic() -> Self {
        Self {
            chunk_size: 1200,  // MTU-safe for QUIC
            buffer_size: 16384,
            include_metadata: true,
            content_type: ContentType::Blob,
            max_chunks: -1,
        }
    }

    /// Create config for small files
    pub fn for_small_files() -> Self {
        Self {
            chunk_size: 4096,
            buffer_size: 8192,
            include_metadata: true,
            content_type: ContentType::Blob,
            max_chunks: -1,
        }
    }

    /// Create config for large files
    pub fn for_large_files() -> Self {
        Self {
            chunk_size: 65536, // 64KB chunks
            buffer_size: 131072, // 128KB buffer
            include_metadata: true,
            content_type: ContentType::Blob,
            max_chunks: -1,
        }
    }
}

/// Metadata about a file being chunked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Original file path
    pub file_path: PathBuf,
    /// File size in bytes
    pub file_size: u64,
    /// Total number of chunks
    pub total_chunks: usize,
    /// Chunk size used
    pub chunk_size: usize,
    /// File modification time (Unix timestamp)
    pub modified_time: u64,
    /// Content type
    pub content_type: ContentType,
    /// File hash (optional)
    pub file_hash: Option<Vec<u8>>,
}

impl FileMetadata {
    /// Create metadata from file path and config
    pub fn from_file<P: AsRef<Path>>(
        path: P,
        config: &ChunkingConfig,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)?;
        let file_size = metadata.len();
        let total_chunks = (file_size as usize + config.chunk_size - 1) / config.chunk_size;
        
        let modified_time = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            file_path: path.to_path_buf(),
            file_size,
            total_chunks,
            chunk_size: config.chunk_size,
            modified_time,
            content_type: config.content_type,
            file_hash: None,
        })
    }

    /// Encode metadata as bytes for transmission
    pub fn encode(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Decode metadata from bytes
    pub fn decode(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(data)?)
    }
}

/// Information about a specific chunk
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    /// Chunk sequence number (0-based)
    pub sequence: usize,
    /// Size of this chunk in bytes
    pub size: usize,
    /// Offset in the original file
    pub offset: u64,
    /// Whether this is the final chunk
    pub is_final: bool,
    /// File metadata (included in first chunk)
    pub file_metadata: Option<FileMetadata>,
}

/// NDN Data packet for a file chunk
#[derive(Debug, Clone)]
pub struct FileChunk {
    /// NDN name for this chunk
    pub name: Name,
    /// Chunk data
    pub data: Data,
    /// Chunk information
    pub chunk_info: ChunkInfo,
}

impl FileChunk {
    /// Create NDN name for a file chunk
    pub fn create_chunk_name(base_name: &Name, sequence: usize) -> Name {
        let mut name = base_name.clone();
        name.append_str("segment")
            .append_str(&sequence.to_string());
        name
    }

    /// Create file chunk from data and metadata
    pub fn new(
        base_name: &Name,
        sequence: usize,
        chunk_data: Vec<u8>,
        chunk_info: ChunkInfo,
    ) -> Self {
        let name = Self::create_chunk_name(base_name, sequence);
        
        let mut meta_info = MetaInfo::default();
        meta_info.content_type = ContentType::Blob;
        
        // Set final block ID for the last chunk
        if chunk_info.is_final {
            meta_info.final_block_id = Some(sequence.to_string().into_bytes());
        }

        let data = Data::new(name.clone(), chunk_data)
            .with_meta_info(meta_info);

        Self {
            name,
            data,
            chunk_info,
        }
    }

    /// Get the encoded NDN packet for this chunk
    pub fn encode(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.data.encode()?)
    }
}

/// Error types for file chunking operations
#[derive(Debug, thiserror::Error)]
pub enum ChunkingError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("File not found: {path}")]
    FileNotFound { path: PathBuf },
    #[error("File too large: {size} bytes (max: {max})")]
    FileTooLarge { size: u64, max: u64 },
    #[error("Invalid chunk size: {size}")]
    InvalidChunkSize { size: usize },
    #[error("Chunk sequence out of bounds: {sequence} (max: {max})")]
    ChunkOutOfBounds { sequence: usize, max: usize },
    #[error("Metadata encoding error: {0}")]
    MetadataError(String),
    #[error("Chunk limit exceeded: {count} (max: {max})")]
    ChunkLimitExceeded { count: usize, max: usize },
}

/// Streaming file chunker for efficient memory usage
pub struct FileChunker {
    config: ChunkingConfig,
    file_metadata: Option<FileMetadata>,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
}

impl FileChunker {
    /// Create a new file chunker with the given configuration
    pub fn new(config: ChunkingConfig) -> Self {
        Self {
            config,
            file_metadata: None,
            progress_callback: None,
        }
    }

    /// Create chunker with default configuration
    pub fn default() -> Self {
        Self::new(ChunkingConfig::default())
    }

    /// Validate configuration
    pub fn validate_config(&self) -> Result<(), ChunkingError> {
        if self.config.chunk_size == 0 {
            return Err(ChunkingError::InvalidChunkSize {
                size: self.config.chunk_size,
            });
        }

        if self.config.buffer_size < self.config.chunk_size {
            warn!("Buffer size {} is smaller than chunk size {}", 
                  self.config.buffer_size, self.config.chunk_size);
        }

        Ok(())
    }

    /// Prepare file for chunking and generate metadata
    pub fn prepare_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<&FileMetadata, ChunkingError> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(ChunkingError::FileNotFound {
                path: path.to_path_buf(),
            });
        }

        let metadata = FileMetadata::from_file(path, &self.config)?;
        
        // Check chunk limits
        if self.config.max_chunks > 0 && metadata.total_chunks > self.config.max_chunks as usize {
            return Err(ChunkingError::ChunkLimitExceeded {
                count: metadata.total_chunks,
                max: self.config.max_chunks as usize,
            });
        }

        info!(
            "Prepared file {:?} for chunking: {} bytes, {} chunks",
            path, metadata.file_size, metadata.total_chunks
        );

        self.file_metadata = Some(metadata);
        Ok(self.file_metadata.as_ref().unwrap())
    }

    /// Get metadata for currently prepared file
    pub fn get_metadata(&self) -> Option<&FileMetadata> {
        self.file_metadata.as_ref()
    }

    /// Set a progress callback that will be called during chunking
    /// The callback receives (current_chunk, total_chunks)
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Set progress callback by reference
    pub fn set_progress_callback<F>(&mut self, callback: F)
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
    }

    /// Create a specific chunk by sequence number
    pub fn create_chunk(
        &self,
        base_name: &Name,
        sequence: usize,
        file: &mut File,
    ) -> Result<FileChunk, ChunkingError> {
        let metadata = self.file_metadata.as_ref()
            .ok_or_else(|| ChunkingError::MetadataError("File not prepared".to_string()))?;

        if sequence >= metadata.total_chunks {
            return Err(ChunkingError::ChunkOutOfBounds {
                sequence,
                max: metadata.total_chunks - 1,
            });
        }

        let offset = (sequence * self.config.chunk_size) as u64;
        let is_final = sequence == metadata.total_chunks - 1;
        
        // Calculate actual chunk size (last chunk may be smaller)
        let remaining_bytes = metadata.file_size - offset;
        let chunk_size = if is_final {
            remaining_bytes as usize
        } else {
            self.config.chunk_size
        };

        // Seek to chunk position
        file.seek(SeekFrom::Start(offset))?;

        // Read chunk data
        let mut chunk_data = vec![0u8; chunk_size];
        file.read_exact(&mut chunk_data)?;

        let chunk_info = ChunkInfo {
            sequence,
            size: chunk_size,
            offset,
            is_final,
            file_metadata: if sequence == 0 && self.config.include_metadata {
                Some(metadata.clone())
            } else {
                None
            },
        };

        debug!(
            "Created chunk {}/{}: {} bytes at offset {}",
            sequence + 1, metadata.total_chunks, chunk_size, offset
        );

        // Report progress if callback is set
        if let Some(callback) = &self.progress_callback {
            callback(sequence + 1, metadata.total_chunks);
        }

        Ok(FileChunk::new(base_name, sequence, chunk_data, chunk_info))
    }

    /// Create all chunks for a file as an iterator
    pub fn chunk_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        base_name: &Name,
    ) -> Result<FileChunkIterator, ChunkingError> {
        self.validate_config()?;
        let metadata = self.prepare_file(path.as_ref())?.clone();
        let file = File::open(path.as_ref())?;

        Ok(FileChunkIterator::new(
            file,
            base_name.clone(),
            metadata,
            self.config.clone(),
        ))
    }

    /// Create all chunks for a file as an iterator with progress callback
    pub fn chunk_file_with_progress<P: AsRef<Path>, F>(
        &mut self,
        path: P,
        base_name: &Name,
        progress_callback: F,
    ) -> Result<FileChunkIterator, ChunkingError>
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.validate_config()?;
        let metadata = self.prepare_file(path.as_ref())?.clone();
        let file = File::open(path.as_ref())?;

        Ok(FileChunkIterator::new(
            file,
            base_name.clone(),
            metadata,
            self.config.clone(),
        ).with_progress_callback(progress_callback))
    }

    /// Estimate optimal chunk size based on file size and transport
    pub fn estimate_optimal_chunk_size(file_size: u64, transport_mtu: usize) -> usize {
        const MIN_CHUNK_SIZE: usize = 1024;    // 1KB minimum
        const MAX_CHUNK_SIZE: usize = 65536;   // 64KB maximum

        let base_size = if file_size < 1024 * 1024 {
            // Small files: use smaller chunks
            transport_mtu.min(4096)
        } else if file_size < 100 * 1024 * 1024 {
            // Medium files: balance efficiency and memory
            transport_mtu.min(16384)
        } else {
            // Large files: use larger chunks for efficiency
            transport_mtu.min(MAX_CHUNK_SIZE)
        };

        base_size.max(MIN_CHUNK_SIZE).min(MAX_CHUNK_SIZE)
    }
}

/// Iterator for streaming file chunks
pub struct FileChunkIterator {
    file: File,
    base_name: Name,
    metadata: FileMetadata,
    config: ChunkingConfig,
    current_sequence: usize,
    current_offset: u64,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
}

impl FileChunkIterator {
    fn new(
        mut file: File,
        base_name: Name,
        metadata: FileMetadata,
        config: ChunkingConfig,
    ) -> Self {
        // Seek to beginning
        let _ = file.seek(SeekFrom::Start(0));
        
        Self {
            file,
            base_name,
            metadata,
            config,
            current_sequence: 0,
            current_offset: 0,
            progress_callback: None,
        }
    }

    /// Set a progress callback for the iterator
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Get total number of chunks
    pub fn total_chunks(&self) -> usize {
        self.metadata.total_chunks
    }

    /// Get current chunk sequence
    pub fn current_sequence(&self) -> usize {
        self.current_sequence
    }

    /// Skip to a specific chunk sequence
    pub fn seek_to_chunk(&mut self, sequence: usize) -> Result<(), ChunkingError> {
        if sequence >= self.metadata.total_chunks {
            return Err(ChunkingError::ChunkOutOfBounds {
                sequence,
                max: self.metadata.total_chunks - 1,
            });
        }

        self.current_sequence = sequence;
        self.current_offset = (sequence * self.config.chunk_size) as u64;
        self.file.seek(SeekFrom::Start(self.current_offset))?;
        
        Ok(())
    }
}

impl Iterator for FileChunkIterator {
    type Item = Result<FileChunk, ChunkingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_sequence >= self.metadata.total_chunks {
            return None;
        }

        let sequence = self.current_sequence;
        let is_final = sequence == self.metadata.total_chunks - 1;
        
        // Calculate chunk size
        let remaining_bytes = self.metadata.file_size - self.current_offset;
        let chunk_size = if is_final {
            remaining_bytes as usize
        } else {
            self.config.chunk_size
        };

        // Read chunk data
        let mut chunk_data = vec![0u8; chunk_size];
        match self.file.read_exact(&mut chunk_data) {
            Ok(()) => {},
            Err(e) => return Some(Err(ChunkingError::Io(e))),
        }

        let chunk_info = ChunkInfo {
            sequence,
            size: chunk_size,
            offset: self.current_offset,
            is_final,
            file_metadata: if sequence == 0 && self.config.include_metadata {
                Some(self.metadata.clone())
            } else {
                None
            },
        };

        let chunk = FileChunk::new(
            &self.base_name,
            sequence,
            chunk_data,
            chunk_info,
        );

        // Update state for next iteration
        self.current_sequence += 1;
        self.current_offset += chunk_size as u64;

        debug!(
            "Generated chunk {}/{}: {} bytes",
            sequence + 1, self.metadata.total_chunks, chunk_size
        );

        // Report progress if callback is set
        if let Some(callback) = &self.progress_callback {
            callback(sequence + 1, self.metadata.total_chunks);
        }

        Some(Ok(chunk))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.metadata.total_chunks - self.current_sequence;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FileChunkIterator {
    fn len(&self) -> usize {
        self.metadata.total_chunks - self.current_sequence
    }
}

/// Utility functions for file chunking
pub mod utils {
    use super::*;

    /// Calculate the optimal configuration for a file
    pub fn optimize_config_for_file<P: AsRef<Path>>(
        path: P,
        transport_mtu: usize,
    ) -> Result<ChunkingConfig, ChunkingError> {
        let metadata = std::fs::metadata(path.as_ref())?;
        let file_size = metadata.len();
        
        let chunk_size = FileChunker::estimate_optimal_chunk_size(file_size, transport_mtu);
        
        let mut config = if file_size < 1024 * 1024 {
            ChunkingConfig::for_small_files()
        } else {
            ChunkingConfig::for_large_files()
        };
        
        config.chunk_size = chunk_size;
        
        Ok(config)
    }

    /// Verify file chunk integrity
    pub fn verify_chunk_integrity(
        chunk: &FileChunk,
        expected_sequence: usize,
        expected_size: Option<usize>,
    ) -> bool {
        if chunk.chunk_info.sequence != expected_sequence {
            return false;
        }

        if let Some(size) = expected_size {
            if chunk.chunk_info.size != size {
                return false;
            }
        }

        true
    }

    /// Reconstruct file name from chunk name
    pub fn extract_base_name_from_chunk(chunk_name: &Name) -> Option<Name> {
        if chunk_name.len() < 2 {
            return None;
        }

        let mut base_name = chunk_name.clone();
        
        // Remove "segment" and sequence number components
        if base_name.len() >= 2 {
            base_name.components.truncate(base_name.len() - 2);
        }

        Some(base_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_file(size: usize) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let data = (0..size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_chunking_config() {
        let config = ChunkingConfig::default();
        assert_eq!(config.chunk_size, 8192);
        
        let quic_config = ChunkingConfig::for_quic();
        assert_eq!(quic_config.chunk_size, 1200);
    }

    #[test]
    fn test_file_metadata() {
        let temp_file = create_test_file(1000);
        let config = ChunkingConfig::default();
        
        let metadata = FileMetadata::from_file(temp_file.path(), &config).unwrap();
        assert_eq!(metadata.file_size, 1000);
        assert_eq!(metadata.total_chunks, 1); // 1000 bytes / 8192 chunk_size = 1 chunk
        assert_eq!(metadata.chunk_size, 8192);
    }

    #[test]
    fn test_file_chunker_validation() {
        let mut config = ChunkingConfig::default();
        config.chunk_size = 0;
        
        let chunker = FileChunker::new(config);
        assert!(chunker.validate_config().is_err());
    }

    #[test]
    fn test_file_chunking_small_file() {
        let temp_file = create_test_file(100);
        let config = ChunkingConfig {
            chunk_size: 50,
            ..Default::default()
        };
        
        let mut chunker = FileChunker::new(config);
        let base_name = Name::from_str("/test/file");
        
        let chunk_iter = chunker.chunk_file(temp_file.path(), &base_name).unwrap();
        let chunks: Result<Vec<_>, _> = chunk_iter.collect();
        let chunks = chunks.unwrap();
        
        assert_eq!(chunks.len(), 2); // 100 bytes / 50 chunk_size = 2 chunks
        assert_eq!(chunks[0].chunk_info.size, 50);
        assert_eq!(chunks[1].chunk_info.size, 50);
        assert!(!chunks[0].chunk_info.is_final);
        assert!(chunks[1].chunk_info.is_final);
    }

    #[test]
    fn test_file_chunking_exact_size() {
        let temp_file = create_test_file(100);
        let config = ChunkingConfig {
            chunk_size: 100,
            ..Default::default()
        };
        
        let mut chunker = FileChunker::new(config);
        let base_name = Name::from_str("/test/file");
        
        let chunk_iter = chunker.chunk_file(temp_file.path(), &base_name).unwrap();
        let chunks: Result<Vec<_>, _> = chunk_iter.collect();
        let chunks = chunks.unwrap();
        
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_info.size, 100);
        assert!(chunks[0].chunk_info.is_final);
    }

    #[test]
    fn test_file_chunking_large_file() {
        let temp_file = create_test_file(10000);
        let config = ChunkingConfig {
            chunk_size: 1000,
            ..Default::default()
        };
        
        let mut chunker = FileChunker::new(config);
        let base_name = Name::from_str("/test/large/file");
        
        let chunk_iter = chunker.chunk_file(temp_file.path(), &base_name).unwrap();
        let chunks: Result<Vec<_>, _> = chunk_iter.collect();
        let chunks = chunks.unwrap();
        
        assert_eq!(chunks.len(), 10); // 10000 bytes / 1000 chunk_size = 10 chunks
        
        // Verify sequence numbers and sizes
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.chunk_info.sequence, i);
            assert_eq!(chunk.chunk_info.size, 1000);
            assert_eq!(chunk.chunk_info.is_final, i == 9);
            
            // Verify NDN name structure
            let expected_name = FileChunk::create_chunk_name(&base_name, i);
            assert_eq!(chunk.name, expected_name);
        }
    }

    #[test]
    fn test_chunk_iterator_seek() {
        let temp_file = create_test_file(1000);
        let config = ChunkingConfig {
            chunk_size: 100,
            ..Default::default()
        };
        
        let mut chunker = FileChunker::new(config);
        let base_name = Name::from_str("/test/file");
        
        let mut chunk_iter = chunker.chunk_file(temp_file.path(), &base_name).unwrap();
        
        // Seek to chunk 5
        chunk_iter.seek_to_chunk(5).unwrap();
        assert_eq!(chunk_iter.current_sequence(), 5);
        
        // Next chunk should be sequence 5
        let chunk = chunk_iter.next().unwrap().unwrap();
        assert_eq!(chunk.chunk_info.sequence, 5);
    }

    #[test]
    fn test_metadata_encoding() {
        let temp_file = create_test_file(1000);
        let config = ChunkingConfig::default();
        
        let metadata = FileMetadata::from_file(temp_file.path(), &config).unwrap();
        let encoded = metadata.encode().unwrap();
        let decoded = FileMetadata::decode(&encoded).unwrap();
        
        assert_eq!(metadata.file_size, decoded.file_size);
        assert_eq!(metadata.total_chunks, decoded.total_chunks);
        assert_eq!(metadata.chunk_size, decoded.chunk_size);
    }

    #[test]
    fn test_chunk_limit() {
        let temp_file = create_test_file(1000);
        let config = ChunkingConfig {
            chunk_size: 100,
            max_chunks: 5,
            ..Default::default()
        };
        
        let mut chunker = FileChunker::new(config);
        
        // Should fail because file would create 10 chunks but limit is 5
        let result = chunker.prepare_file(temp_file.path());
        assert!(matches!(result, Err(ChunkingError::ChunkLimitExceeded { .. })));
    }

    #[test]
    fn test_optimal_chunk_size() {
        assert_eq!(FileChunker::estimate_optimal_chunk_size(1000, 1200), 1200);  // Small file, use MTU size
        assert_eq!(FileChunker::estimate_optimal_chunk_size(10_000_000, 1400), 1400);
        assert_eq!(FileChunker::estimate_optimal_chunk_size(1_000_000_000, 1400), 1400);
    }

    #[test]
    fn test_base_name_extraction() {
        let chunk_name = Name::from_str("/test/file/segment/5");
        let base_name = utils::extract_base_name_from_chunk(&chunk_name).unwrap();
        assert_eq!(base_name.to_string(), "/test/file");
    }

    #[test]
    fn test_chunk_integrity_verification() {
        let temp_file = create_test_file(100);
        let config = ChunkingConfig::default();
        
        let mut chunker = FileChunker::new(config);
        let base_name = Name::from_str("/test/file");
        
        let chunk_iter = chunker.chunk_file(temp_file.path(), &base_name).unwrap();
        let chunks: Result<Vec<_>, _> = chunk_iter.collect();
        let chunks = chunks.unwrap();
        
        // Test valid chunk
        assert!(utils::verify_chunk_integrity(&chunks[0], 0, Some(100)));
        
        // Test invalid sequence
        assert!(!utils::verify_chunk_integrity(&chunks[0], 1, Some(100)));
        
        // Test invalid size
        assert!(!utils::verify_chunk_integrity(&chunks[0], 0, Some(50)));
    }
}