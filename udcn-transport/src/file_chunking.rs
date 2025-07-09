use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use udcn_core::packets::{Name, Data, MetaInfo, ContentType};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::file_integrity::ChecksumAlgorithm;

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
    /// Enable large file handling mode (>1GB files)
    pub large_file_mode: bool,
    /// Maximum memory usage for large files (in bytes)
    pub max_memory_usage: usize,
    /// Read buffer size for streaming large files
    pub stream_buffer_size: usize,
    /// Enable chunk-level integrity verification
    pub enable_chunk_integrity: bool,
    /// Algorithm to use for chunk integrity
    pub chunk_hash_algorithm: ChecksumAlgorithm,
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 8192,  // 8KB - good balance for QUIC
            buffer_size: 32768, // 32KB read buffer
            include_metadata: true,
            content_type: ContentType::Blob,
            max_chunks: -1, // unlimited
            large_file_mode: false,
            max_memory_usage: 256 * 1024 * 1024, // 256MB default limit
            stream_buffer_size: 1024 * 1024, // 1MB streaming buffer
            enable_chunk_integrity: false, // Disabled by default for performance
            chunk_hash_algorithm: ChecksumAlgorithm::Sha256,
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
            large_file_mode: false,
            max_memory_usage: 128 * 1024 * 1024, // 128MB for QUIC
            stream_buffer_size: 512 * 1024, // 512KB streaming buffer
            enable_chunk_integrity: false,
            chunk_hash_algorithm: ChecksumAlgorithm::Sha256,
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
            large_file_mode: false,
            max_memory_usage: 64 * 1024 * 1024, // 64MB for small files
            stream_buffer_size: 256 * 1024, // 256KB streaming buffer
            enable_chunk_integrity: false,
            chunk_hash_algorithm: ChecksumAlgorithm::Sha256,
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
            large_file_mode: true,
            max_memory_usage: 512 * 1024 * 1024, // 512MB for large files
            stream_buffer_size: 2 * 1024 * 1024, // 2MB streaming buffer
            enable_chunk_integrity: false,
            chunk_hash_algorithm: ChecksumAlgorithm::Sha256,
        }
    }

    /// Create config specifically for very large files (>1GB)
    pub fn for_very_large_files() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1MB chunks for very large files
            buffer_size: 2 * 1024 * 1024, // 2MB buffer
            include_metadata: true,
            content_type: ContentType::Blob,
            max_chunks: -1,
            large_file_mode: true,
            max_memory_usage: 1024 * 1024 * 1024, // 1GB memory limit
            stream_buffer_size: 4 * 1024 * 1024, // 4MB streaming buffer
            enable_chunk_integrity: false,
            chunk_hash_algorithm: ChecksumAlgorithm::Sha256,
        }
    }

    /// Automatically configure based on file size
    pub fn auto_configure(file_size: u64) -> Self {
        const MB: u64 = 1024 * 1024;
        const GB: u64 = 1024 * MB;
        
        if file_size < 10 * MB {
            Self::for_small_files()
        } else if file_size < 100 * MB {
            Self::for_large_files()
        } else if file_size < GB {
            let mut config = Self::for_large_files();
            config.chunk_size = 256 * 1024; // 256KB chunks
            config.max_memory_usage = 768 * MB as usize; // 768MB
            config
        } else {
            Self::for_very_large_files()
        }
    }

    /// Validate configuration for large file mode
    pub fn validate_large_file_config(&self) -> Result<(), ChunkingError> {
        if self.large_file_mode {
            if self.stream_buffer_size < self.chunk_size {
                return Err(ChunkingError::InvalidConfiguration {
                    message: "Stream buffer size must be >= chunk size for large file mode".to_string(),
                });
            }
            
            if self.max_memory_usage < 2 * self.stream_buffer_size {
                return Err(ChunkingError::InvalidConfiguration {
                    message: "Max memory usage too low for large file mode streaming".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Metadata about a file being chunked
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Chunk integrity hash (optional)
    pub chunk_hash: Option<Vec<u8>>,
    /// Algorithm used for chunk hash
    pub hash_algorithm: Option<ChecksumAlgorithm>,
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
    #[error("Configuration error: {message}")]
    InvalidConfiguration { message: String },
    #[error("Memory limit exceeded: {used} bytes (max: {limit})")]
    MemoryLimitExceeded { used: usize, limit: usize },
    #[error("Invalid chunk offset: {offset} (total chunks: {total_chunks})")]
    InvalidChunkOffset { offset: u32, total_chunks: u32 },
}

/// Streaming file reader for large files with memory management
pub struct LargeFileReader {
    file: File,
    config: ChunkingConfig,
    read_buffer: Vec<u8>,
    current_position: u64,
    file_size: u64,
    memory_tracker: MemoryTracker,
}

/// Memory usage tracker for large file operations
#[derive(Debug, Clone)]
pub struct MemoryTracker {
    current_usage: usize,
    max_usage: usize,
    peak_usage: usize,
}

impl MemoryTracker {
    pub fn new(max_usage: usize) -> Self {
        Self {
            current_usage: 0,
            max_usage,
            peak_usage: 0,
        }
    }

    pub fn allocate(&mut self, size: usize) -> Result<(), ChunkingError> {
        let new_usage = self.current_usage + size;
        if new_usage > self.max_usage {
            return Err(ChunkingError::MemoryLimitExceeded {
                used: new_usage,
                limit: self.max_usage,
            });
        }
        
        self.current_usage = new_usage;
        if self.current_usage > self.peak_usage {
            self.peak_usage = self.current_usage;
        }
        
        Ok(())
    }

    pub fn deallocate(&mut self, size: usize) {
        self.current_usage = self.current_usage.saturating_sub(size);
    }

    pub fn current_usage(&self) -> usize {
        self.current_usage
    }

    pub fn peak_usage(&self) -> usize {
        self.peak_usage
    }

    pub fn available_memory(&self) -> usize {
        self.max_usage.saturating_sub(self.current_usage)
    }
}

impl LargeFileReader {
    pub fn new<P: AsRef<Path>>(path: P, config: ChunkingConfig) -> Result<Self, ChunkingError> {
        config.validate_large_file_config()?;
        
        let file = File::open(path.as_ref())?;
        let file_size = file.metadata()?.len();
        
        let memory_tracker = MemoryTracker::new(config.max_memory_usage);
        let mut reader = Self {
            file,
            config: config.clone(),
            read_buffer: Vec::new(),
            current_position: 0,
            file_size,
            memory_tracker,
        };
        
        // Pre-allocate buffer for streaming
        reader.memory_tracker.allocate(config.stream_buffer_size)?;
        reader.read_buffer = vec![0u8; config.stream_buffer_size];
        
        debug!(
            "Created large file reader: {} bytes, buffer size: {} bytes, memory limit: {} MB",
            file_size, 
            config.stream_buffer_size,
            config.max_memory_usage / (1024 * 1024)
        );
        
        Ok(reader)
    }

    /// Read a chunk from the file using streaming approach
    pub fn read_chunk(&mut self, sequence: usize, chunk_size: usize) -> Result<Vec<u8>, ChunkingError> {
        // Calculate chunk position
        let chunk_offset = (sequence * self.config.chunk_size) as u64;
        let remaining_bytes = self.file_size.saturating_sub(chunk_offset);
        let actual_chunk_size = chunk_size.min(remaining_bytes as usize);
        
        if actual_chunk_size == 0 {
            return Ok(Vec::new());
        }
        
        // Check memory before allocation
        self.memory_tracker.allocate(actual_chunk_size)?;
        
        // Seek to chunk position if needed
        if self.current_position != chunk_offset {
            self.file.seek(SeekFrom::Start(chunk_offset))?;
            self.current_position = chunk_offset;
        }
        
        let mut chunk_data = Vec::with_capacity(actual_chunk_size);
        let mut bytes_read = 0;
        
        // Read chunk in smaller buffers to manage memory
        while bytes_read < actual_chunk_size {
            let bytes_to_read = (actual_chunk_size - bytes_read).min(self.config.stream_buffer_size);
            
            // Read into our buffer
            let read_count = self.file.read(&mut self.read_buffer[..bytes_to_read])?;
            if read_count == 0 {
                break; // EOF
            }
            
            // Append to chunk data
            chunk_data.extend_from_slice(&self.read_buffer[..read_count]);
            bytes_read += read_count;
            self.current_position += read_count as u64;
        }
        
        // Release memory allocation tracking
        self.memory_tracker.deallocate(actual_chunk_size);
        
        debug!(
            "Read chunk {}: {} bytes at offset {}, memory usage: {} MB",
            sequence,
            chunk_data.len(),
            chunk_offset,
            self.memory_tracker.current_usage() / (1024 * 1024)
        );
        
        Ok(chunk_data)
    }

    /// Get memory usage statistics
    pub fn memory_stats(&self) -> (usize, usize, usize) {
        (
            self.memory_tracker.current_usage(),
            self.memory_tracker.peak_usage(),
            self.memory_tracker.available_memory(),
        )
    }

    /// Reset to beginning of file
    pub fn reset(&mut self) -> Result<(), ChunkingError> {
        self.file.seek(SeekFrom::Start(0))?;
        self.current_position = 0;
        Ok(())
    }
}

/// Streaming file chunker for efficient memory usage
pub struct FileChunker {
    config: ChunkingConfig,
    file_metadata: Option<FileMetadata>,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
    large_file_reader: Option<LargeFileReader>,
}

impl FileChunker {
    /// Create a new file chunker with the given configuration
    pub fn new(config: ChunkingConfig) -> Self {
        Self {
            config,
            file_metadata: None,
            progress_callback: None,
            large_file_reader: None,
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

        // Initialize large file reader if needed
        if self.config.large_file_mode || metadata.file_size > 1024 * 1024 * 1024 {
            info!("Initializing large file reader for {} byte file", metadata.file_size);
            self.large_file_reader = Some(LargeFileReader::new(path, self.config.clone())?);
        }

        info!(
            "Prepared file {:?} for chunking: {} bytes, {} chunks{}",
            path, 
            metadata.file_size, 
            metadata.total_chunks,
            if self.large_file_reader.is_some() { " (large file mode)" } else { "" }
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
            chunk_hash: None,
            hash_algorithm: None,
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

    /// Create a chunk with automatic large file handling
    pub fn create_chunk_optimized(
        &mut self,
        base_name: &Name,
        sequence: usize,
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

        // Use large file reader if available, otherwise fall back to regular read
        let chunk_data = if let Some(ref mut reader) = self.large_file_reader {
            reader.read_chunk(sequence, chunk_size)?
        } else {
            // Fallback to regular file reading for compatibility
            let mut file = File::open(&metadata.file_path)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut data = vec![0u8; chunk_size];
            file.read_exact(&mut data)?;
            data
        };

        let chunk_info = ChunkInfo {
            sequence,
            size: chunk_data.len(),
            offset,
            is_final,
            file_metadata: if sequence == 0 && self.config.include_metadata {
                Some(metadata.clone())
            } else {
                None
            },
            chunk_hash: None,
            hash_algorithm: None,
        };

        debug!(
            "Created optimized chunk {}/{}: {} bytes at offset {}{}",
            sequence + 1, 
            metadata.total_chunks, 
            chunk_data.len(), 
            offset,
            if self.large_file_reader.is_some() { " (streaming)" } else { " (regular)" }
        );

        // Report progress if callback is set
        if let Some(callback) = &self.progress_callback {
            callback(sequence + 1, metadata.total_chunks);
        }

        Ok(FileChunk::new(base_name, sequence, chunk_data, chunk_info))
    }

    /// Get memory usage statistics for large file operations
    pub fn memory_stats(&self) -> Option<(usize, usize, usize)> {
        self.large_file_reader.as_ref().map(|reader| reader.memory_stats())
    }

    /// Create all chunks for a file as an iterator
    pub fn chunk_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        base_name: &Name,
    ) -> Result<FileChunkIterator, ChunkingError> {
        self.validate_config()?;
        let metadata = self.prepare_file(path.as_ref())?.clone();
        
        // Use large file reader if available, otherwise regular file
        if let Some(reader) = self.large_file_reader.take() {
            Ok(FileChunkIterator::new_with_large_file_reader(
                base_name.clone(),
                metadata,
                self.config.clone(),
                reader,
            ))
        } else {
            let file = File::open(path.as_ref())?;
            Ok(FileChunkIterator::new(
                file,
                base_name.clone(),
                metadata,
                self.config.clone(),
            ))
        }
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
        
        // Use large file reader if available, otherwise regular file
        if let Some(reader) = self.large_file_reader.take() {
            Ok(FileChunkIterator::new_with_large_file_reader(
                base_name.clone(),
                metadata,
                self.config.clone(),
                reader,
            ).with_progress_callback(progress_callback))
        } else {
            let file = File::open(path.as_ref())?;
            Ok(FileChunkIterator::new(
                file,
                base_name.clone(),
                metadata,
                self.config.clone(),
            ).with_progress_callback(progress_callback))
        }
    }

    /// Create chunks for a file starting from a specific chunk offset (for resume)
    pub fn chunk_file_resume<P: AsRef<Path>>(
        &mut self,
        path: P,
        base_name: &Name,
        start_chunk_offset: u32,
        chunk_bitmap: Option<&[u8]>,
    ) -> Result<FileChunkIterator, ChunkingError> {
        self.validate_config()?;
        let metadata = self.prepare_file(path.as_ref())?.clone();
        
        // Validate start_chunk_offset
        if start_chunk_offset as usize > metadata.total_chunks {
            return Err(ChunkingError::InvalidChunkOffset { 
                offset: start_chunk_offset, 
                total_chunks: metadata.total_chunks as u32
            });
        }
        
        // Use large file reader if available, otherwise regular file
        if let Some(reader) = self.large_file_reader.take() {
            Ok(FileChunkIterator::new_with_large_file_reader_resume(
                base_name.clone(),
                metadata,
                self.config.clone(),
                reader,
                start_chunk_offset,
                chunk_bitmap,
            ))
        } else {
            let file = File::open(path.as_ref())?;
            Ok(FileChunkIterator::new_resume(
                file,
                base_name.clone(),
                metadata,
                self.config.clone(),
                start_chunk_offset,
                chunk_bitmap,
            ))
        }
    }
    
    /// Create chunks for a file with resume capability and progress callback
    pub fn chunk_file_resume_with_progress<P: AsRef<Path>, F>(
        &mut self,
        path: P,
        base_name: &Name,
        start_chunk_offset: u32,
        chunk_bitmap: Option<&[u8]>,
        progress_callback: F,
    ) -> Result<FileChunkIterator, ChunkingError>
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        self.validate_config()?;
        let metadata = self.prepare_file(path.as_ref())?.clone();
        
        // Validate start_chunk_offset
        if start_chunk_offset as usize > metadata.total_chunks {
            return Err(ChunkingError::InvalidChunkOffset { 
                offset: start_chunk_offset, 
                total_chunks: metadata.total_chunks as u32
            });
        }
        
        // Use large file reader if available, otherwise regular file
        if let Some(reader) = self.large_file_reader.take() {
            Ok(FileChunkIterator::new_with_large_file_reader_resume(
                base_name.clone(),
                metadata,
                self.config.clone(),
                reader,
                start_chunk_offset,
                chunk_bitmap,
            ).with_progress_callback(progress_callback))
        } else {
            let file = File::open(path.as_ref())?;
            Ok(FileChunkIterator::new_resume(
                file,
                base_name.clone(),
                metadata,
                self.config.clone(),
                start_chunk_offset,
                chunk_bitmap,
            ).with_progress_callback(progress_callback))
        }
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
    file: Option<File>,
    base_name: Name,
    metadata: FileMetadata,
    config: ChunkingConfig,
    current_sequence: usize,
    current_offset: u64,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
    large_file_reader: Option<LargeFileReader>,
    chunk_bitmap: Option<Vec<u8>>,
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
            file: Some(file),
            base_name,
            metadata,
            config,
            current_sequence: 0,
            current_offset: 0,
            progress_callback: None,
            large_file_reader: None,
            chunk_bitmap: None,
        }
    }

    fn new_resume(
        mut file: File,
        base_name: Name,
        metadata: FileMetadata,
        config: ChunkingConfig,
        start_chunk_offset: u32,
        chunk_bitmap: Option<&[u8]>,
    ) -> Self {
        // Seek to the starting chunk position
        let start_offset = (start_chunk_offset as usize * config.chunk_size) as u64;
        let _ = file.seek(SeekFrom::Start(start_offset));
        
        Self {
            file: Some(file),
            base_name,
            metadata,
            config,
            current_sequence: start_chunk_offset as usize,
            current_offset: start_offset,
            progress_callback: None,
            large_file_reader: None,
            chunk_bitmap: chunk_bitmap.map(|b| b.to_vec()),
        }
    }

    fn new_with_large_file_reader(
        base_name: Name,
        metadata: FileMetadata,
        config: ChunkingConfig,
        large_file_reader: LargeFileReader,
    ) -> Self {
        Self {
            file: None,
            base_name,
            metadata,
            config,
            current_sequence: 0,
            current_offset: 0,
            progress_callback: None,
            large_file_reader: Some(large_file_reader),
            chunk_bitmap: None,
        }
    }

    fn new_with_large_file_reader_resume(
        base_name: Name,
        metadata: FileMetadata,
        config: ChunkingConfig,
        large_file_reader: LargeFileReader,
        start_chunk_offset: u32,
        chunk_bitmap: Option<&[u8]>,
    ) -> Self {
        let current_offset = (start_chunk_offset as usize * config.chunk_size) as u64;
        
        Self {
            file: None,
            base_name,
            metadata,
            config,
            current_sequence: start_chunk_offset as usize,
            current_offset,
            progress_callback: None,
            large_file_reader: Some(large_file_reader),
            chunk_bitmap: chunk_bitmap.map(|b| b.to_vec()),
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
        
        if let Some(ref mut file) = self.file {
            file.seek(SeekFrom::Start(self.current_offset))?;
        }
        // Note: LargeFileReader handles seeking internally
        
        Ok(())
    }
}

impl Iterator for FileChunkIterator {
    type Item = Result<FileChunk, ChunkingError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Find next chunk that needs to be sent
        loop {
            if self.current_sequence >= self.metadata.total_chunks {
                return None;
            }

            let sequence = self.current_sequence;
            
            // Check if this chunk is already completed according to the bitmap
            if let Some(ref bitmap) = self.chunk_bitmap {
                let byte_idx = (sequence / 8) as usize;
                let bit_idx = sequence % 8;
                
                if byte_idx < bitmap.len() {
                    let is_completed = (bitmap[byte_idx] & (1 << bit_idx)) != 0;
                    if is_completed {
                        // Skip this chunk and move to next
                        self.current_sequence += 1;
                        self.current_offset = (self.current_sequence * self.config.chunk_size) as u64;
                        continue;
                    }
                }
            }

            let is_final = sequence == self.metadata.total_chunks - 1;
            
            // Calculate chunk size
            let remaining_bytes = self.metadata.file_size - self.current_offset;
            let chunk_size = if is_final {
                remaining_bytes as usize
            } else {
                self.config.chunk_size
            };

            // Read chunk data using appropriate method
            let chunk_data = if let Some(ref mut reader) = self.large_file_reader {
                match reader.read_chunk(sequence, chunk_size) {
                    Ok(data) => data,
                    Err(e) => return Some(Err(e)),
                }
            } else if let Some(ref mut file) = self.file {
                let mut data = vec![0u8; chunk_size];
                match file.read_exact(&mut data) {
                    Ok(()) => data,
                    Err(e) => return Some(Err(ChunkingError::Io(e))),
                }
            } else {
                return Some(Err(ChunkingError::MetadataError("No file or reader available".to_string())));
            };

            let chunk_info = ChunkInfo {
                sequence,
                size: chunk_data.len(),
                offset: self.current_offset,
                is_final,
                file_metadata: if sequence == 0 && self.config.include_metadata {
                    Some(self.metadata.clone())
                } else {
                    None
                },
                chunk_hash: None,
                hash_algorithm: None,
            };

            let chunk_data_len = chunk_data.len();
            let chunk = FileChunk::new(
                &self.base_name,
                sequence,
                chunk_data,
                chunk_info,
            );

            // Update state for next iteration
            self.current_sequence += 1;
            self.current_offset += chunk_data_len as u64;

            debug!(
                "Generated chunk {}/{}: {} bytes{} (resume mode: {})",
                sequence + 1, 
                self.metadata.total_chunks, 
                chunk_data_len,
                if self.large_file_reader.is_some() { " (streaming)" } else { "" },
                self.chunk_bitmap.is_some()
            );

            // Report progress if callback is set
            if let Some(callback) = &self.progress_callback {
                callback(sequence + 1, self.metadata.total_chunks);
            }

            return Some(Ok(chunk));
        }
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