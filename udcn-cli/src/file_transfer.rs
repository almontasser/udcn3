use std::path::Path;
use std::collections::HashMap;
use std::net::SocketAddr;
use log::{info, warn, error, debug};
use tokio::time::{timeout, Duration};

use udcn_core::name::Name;
use udcn_core::packets::{Interest, Data};
use udcn_transport::{
    FileChunker, ChunkingConfig, FileMetadata, ChunkInfo,
    FileReassemblyEngine, ReassemblyConfig, ReassemblyStatus,
    DataPacketPublisher, PublisherConfig,
    AsyncTransport, UdpTransport
};

use crate::utils::{FileChunker as UtilsFileChunker, ProgressTracker};

/// File transfer service for NDN-based file operations
pub struct FileTransferService {
    transport: UdpTransport,
    publisher: DataPacketPublisher,
    reassembly_engine: FileReassemblyEngine,
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
}

impl FileTransferService {
    /// Create a new file transfer service
    pub async fn new(local_port: u16, remote_addr: Option<SocketAddr>) -> Result<Self, Box<dyn std::error::Error>> {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], local_port));
        
        // Create UDP transport
        let transport = UdpTransport::new(local_addr).await?;
        
        // Create data publisher
        let publisher_config = PublisherConfig {
            max_content_size: 8192,
            enable_signing: false,
            enable_caching: true,
            cache_size: 1000,
            freshness_period: Duration::from_secs(60),
        };
        let publisher = DataPacketPublisher::new(publisher_config);
        
        // Create reassembly engine
        let reassembly_config = ReassemblyConfig {
            max_concurrent_files: 10,
            chunk_timeout: Duration::from_secs(30),
            max_chunk_retries: 3,
            enable_integrity_check: true,
            temp_dir: std::env::temp_dir(),
        };
        let reassembly_engine = FileReassemblyEngine::new(reassembly_config);
        
        Ok(Self {
            transport,
            publisher,
            reassembly_engine,
            local_addr,
            remote_addr,
        })
    }

    /// Send a file over NDN
    pub async fn send_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
        ndn_name: &str,
        chunk_size: usize,
        target_addr: SocketAddr,
        progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file_path = file_path.as_ref();
        info!("Sending file: {} with NDN name: {}", file_path.display(), ndn_name);

        // Validate file
        if !file_path.exists() {
            return Err(format!("File not found: {}", file_path.display()).into());
        }
        if !file_path.is_file() {
            return Err(format!("Path is not a file: {}", file_path.display()).into());
        }

        // Create file chunker
        let chunking_config = ChunkingConfig {
            chunk_size,
            enable_compression: false,
            enable_encryption: false,
        };
        let mut file_chunker = FileChunker::new(chunking_config);
        
        // Chunk the file
        let (metadata, chunks) = file_chunker.chunk_file(file_path).await?;
        
        info!("File chunked: {} chunks of {} bytes each", chunks.len(), chunk_size);
        
        // Create base NDN name
        let base_name = Name::from_str(ndn_name)?;
        
        // Send file metadata as a special chunk
        let metadata_name = base_name.append("metadata");
        let metadata_data = self.create_metadata_packet(&metadata, &metadata_name)?;
        self.send_data_packet(&metadata_data, target_addr).await?;
        
        // Send each chunk
        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_name = base_name.append(&format!("chunk{}", i));
            let chunk_data = self.create_chunk_packet(chunk, &chunk_name)?;
            self.send_data_packet(&chunk_data, target_addr).await?;
            
            // Call progress callback if provided
            if let Some(ref callback) = progress_callback {
                callback(i + 1, chunks.len());
            }
            
            debug!("Sent chunk {}/{}", i + 1, chunks.len());
        }
        
        info!("File sent successfully: {} chunks", chunks.len());
        Ok(())
    }

    /// Receive a file over NDN
    pub async fn receive_file<P: AsRef<Path>>(
        &mut self,
        ndn_name: &str,
        output_path: P,
        source_addr: SocketAddr,
        timeout_duration: Duration,
        progress_callback: Option<Box<dyn Fn(usize, usize) + Send + Sync>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_path = output_path.as_ref();
        info!("Receiving file with NDN name: {} to {}", ndn_name, output_path.display());

        // Create base NDN name
        let base_name = Name::from_str(ndn_name)?;
        
        // Request metadata first
        let metadata_name = base_name.append("metadata");
        let metadata_interest = Interest::new(metadata_name.clone());
        
        info!("Requesting file metadata");
        let metadata_data = self.request_data(&metadata_interest, source_addr, timeout_duration).await?;
        let metadata: FileMetadata = self.parse_metadata_packet(&metadata_data)?;
        
        info!("File metadata received: {} bytes, {} chunks", metadata.file_size, metadata.total_chunks);
        
        // Calculate number of chunks
        let total_chunks = metadata.total_chunks;
        let mut received_chunks = Vec::new();
        let mut successful_chunks = 0;
        
        // Request each chunk
        for chunk_index in 0..total_chunks {
            let chunk_name = base_name.append(&format!("chunk{}", chunk_index));
            let chunk_interest = Interest::new(chunk_name.clone());
            
            match self.request_data(&chunk_interest, source_addr, timeout_duration).await {
                Ok(chunk_data) => {
                    let chunk_info = self.parse_chunk_packet(&chunk_data)?;
                    received_chunks.push(chunk_info);
                    successful_chunks += 1;
                    
                    // Call progress callback if provided
                    if let Some(ref callback) = progress_callback {
                        callback(successful_chunks, total_chunks);
                    }
                    
                    debug!("Received chunk {}/{}", successful_chunks, total_chunks);
                }
                Err(e) => {
                    error!("Failed to receive chunk {}: {}", chunk_index, e);
                    return Err(format!("Failed to receive chunk {}: {}", chunk_index, e).into());
                }
            }
        }
        
        // Reassemble the file
        info!("Reassembling file from {} chunks", received_chunks.len());
        let reassembly_result = self.reassembly_engine.reassemble_file(
            &metadata,
            received_chunks,
            output_path,
        ).await?;
        
        match reassembly_result.status {
            ReassemblyStatus::Complete => {
                info!("File received successfully: {}", output_path.display());
                Ok(())
            }
            ReassemblyStatus::Incomplete => {
                Err("File reassembly incomplete".into())
            }
            ReassemblyStatus::Failed => {
                Err("File reassembly failed".into())
            }
        }
    }

    /// Request data using an Interest packet
    async fn request_data(
        &self,
        interest: &Interest,
        addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Data, Box<dyn std::error::Error>> {
        // Encode and send the Interest
        let interest_data = interest.encode()?;
        self.transport.send_to_async(&interest_data, addr).await?;
        
        // Wait for response with timeout
        let response = timeout(timeout_duration, self.transport.receive_async()).await??;
        
        // Decode the response
        let data_packet = Data::decode(&response)?;
        Ok(data_packet)
    }

    /// Send a data packet
    async fn send_data_packet(&self, data: &Data, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let encoded_data = data.encode()?;
        self.transport.send_to_async(&encoded_data, addr).await?;
        Ok(())
    }

    /// Create a metadata packet
    fn create_metadata_packet(&self, metadata: &FileMetadata, name: &Name) -> Result<Data, Box<dyn std::error::Error>> {
        let metadata_bytes = serde_json::to_vec(metadata)?;
        let data = Data::new(name.clone(), metadata_bytes);
        Ok(data)
    }

    /// Create a chunk packet
    fn create_chunk_packet(&self, chunk: &ChunkInfo, name: &Name) -> Result<Data, Box<dyn std::error::Error>> {
        let chunk_bytes = serde_json::to_vec(chunk)?;
        let data = Data::new(name.clone(), chunk_bytes);
        Ok(data)
    }

    /// Parse a metadata packet
    fn parse_metadata_packet(&self, data: &Data) -> Result<FileMetadata, Box<dyn std::error::Error>> {
        let metadata: FileMetadata = serde_json::from_slice(&data.content)?;
        Ok(metadata)
    }

    /// Parse a chunk packet
    fn parse_chunk_packet(&self, data: &Data) -> Result<ChunkInfo, Box<dyn std::error::Error>> {
        let chunk: ChunkInfo = serde_json::from_slice(&data.content)?;
        Ok(chunk)
    }
}

/// Simplified file transfer functions for CLI use
pub struct SimpleFileTransfer;

impl SimpleFileTransfer {
    /// Send a file using the CLI utilities with NDN transport
    pub async fn send_file_simple<P: AsRef<Path>>(
        file_path: P,
        ndn_name: &str,
        chunk_size: usize,
        target_addr: SocketAddr,
        show_progress: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file_path = file_path.as_ref();
        
        // Create file transfer service
        let mut transfer_service = FileTransferService::new(0, Some(target_addr)).await?;
        
        // Set up progress callback
        let progress_callback = if show_progress {
            Some(Box::new(|current: usize, total: usize| {
                let percentage = (current as f64 / total as f64) * 100.0;
                println!("Progress: {}/{} chunks ({:.1}%)", current, total, percentage);
            }) as Box<dyn Fn(usize, usize) + Send + Sync>)
        } else {
            None
        };
        
        // Send the file
        transfer_service.send_file(
            file_path,
            ndn_name,
            chunk_size,
            target_addr,
            progress_callback,
        ).await?;
        
        Ok(())
    }

    /// Receive a file using the CLI utilities with NDN transport
    pub async fn receive_file_simple<P: AsRef<Path>>(
        ndn_name: &str,
        output_path: P,
        source_addr: SocketAddr,
        timeout_seconds: u64,
        show_progress: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_path = output_path.as_ref();
        
        // Create file transfer service
        let mut transfer_service = FileTransferService::new(0, Some(source_addr)).await?;
        
        // Set up progress callback
        let progress_callback = if show_progress {
            Some(Box::new(|current: usize, total: usize| {
                let percentage = (current as f64 / total as f64) * 100.0;
                println!("Progress: {}/{} chunks ({:.1}%)", current, total, percentage);
            }) as Box<dyn Fn(usize, usize) + Send + Sync>)
        } else {
            None
        };
        
        // Receive the file
        transfer_service.receive_file(
            ndn_name,
            output_path,
            source_addr,
            Duration::from_secs(timeout_seconds),
            progress_callback,
        ).await?;
        
        Ok(())
    }
}

/// Mock transport for testing when real transport is not available
#[derive(Clone)]
pub struct MockTransport {
    chunks: std::sync::Arc<std::sync::RwLock<HashMap<String, Vec<u8>>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            chunks: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
    
    pub fn add_chunk(&self, name: String, data: Vec<u8>) {
        let mut chunks = self.chunks.write().unwrap();
        chunks.insert(name, data);
    }
}

#[async_trait::async_trait]
impl AsyncTransport for MockTransport {
    async fn send_async(&self, _data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Mock implementation - just pretend to send
        Ok(())
    }
    
    async fn receive_async(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Mock implementation - return empty data
        Ok(vec![])
    }
    
    async fn close_async(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    
    async fn send_to_async(&self, _data: &[u8], _addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Mock implementation - just pretend to send
        Ok(())
    }
    
    async fn receive_timeout_async(&self, _timeout: Duration) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Mock implementation - return empty data
        Ok(vec![])
    }
}