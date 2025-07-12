use std::path::Path;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::io::Write;
use std::sync::Arc;
use log::{info, error, debug};
use tokio::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};

use udcn_core::packets::{Interest, Data, Name};
use udcn_transport::{
    FileChunker, ChunkingConfig, FileMetadata,
    FileReassemblyEngine, ReassemblyConfig,
    DataPacketPublisher, PublisherConfig,
    AsyncTransport, NdnQuicTransport, NdnQuicConfig, QuicTransport, QuicConfig
};

// use crate::utils::{FileChunker as UtilsFileChunker, ProgressTracker};

/// NDN-QUIC transport adapter for AsyncTransport compatibility
#[derive(Clone)]
pub struct NdnQuicAsyncTransport {
    ndn_transport: Arc<NdnQuicTransport>,
    local_addr: SocketAddr,
}

impl NdnQuicAsyncTransport {
    pub async fn new(local_addr: SocketAddr, server_mode: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let mut quic_config = QuicConfig::default();
        // Use development TLS config for testing with self-signed certificates
        quic_config.tls_config = udcn_transport::TlsSecurityConfig::development();
        let ndn_config = NdnQuicConfig::default();
        
        let quic_transport = if server_mode {
            QuicTransport::new_server(local_addr, quic_config).await?
        } else {
            QuicTransport::new_client(quic_config).await?
        };
        
        let ndn_transport = NdnQuicTransport::new(Arc::new(quic_transport), ndn_config);
        
        Ok(Self {
            ndn_transport: Arc::new(ndn_transport),
            local_addr,
        })
    }

    pub fn ndn_transport(&self) -> &Arc<NdnQuicTransport> {
        &self.ndn_transport
    }
}

#[async_trait::async_trait]
impl AsyncTransport for NdnQuicAsyncTransport {
    async fn send_async(&self, _data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Direct send not supported for QUIC - use send_to_async with address".into())
    }
    
    async fn receive_async(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // For QUIC, receiving requires accepting connections
        let connection = self.ndn_transport.quic_transport().accept().await
            .map_err(|e| format!("Failed to accept QUIC connection: {}", e))?;
        
        // Receive NDN frame and extract payload
        let (frame, _send_stream) = self.ndn_transport.receive_frame(&connection).await
            .map_err(|e| format!("Failed to receive NDN frame: {}", e))?;
        
        Ok(frame.payload)
    }
    
    async fn close_async(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.ndn_transport.quic_transport().close().await
            .map_err(|e| format!("Failed to close QUIC transport: {}", e))?;
        Ok(())
    }
    
    async fn send_to_async(&self, data: &[u8], addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For file transfer, we need to send NDN Data packets
        // Parse the data as NDN packet and send via QUIC
        match Data::decode(data) {
            Ok((data_packet, _)) => {
                self.ndn_transport.send_data(&data_packet, addr).await
                    .map_err(|e| format!("Failed to send NDN Data via QUIC: {}", e))?;
            }
            Err(_) => {
                // If not NDN Data, try as Interest
                match Interest::decode(data) {
                    Ok((interest_packet, _)) => {
                        self.ndn_transport.send_interest(&interest_packet, addr).await
                            .map_err(|e| format!("Failed to send NDN Interest via QUIC: {}", e))?;
                    }
                    Err(e) => {
                        return Err(format!("Data is not a valid NDN packet: {}", e).into());
                    }
                }
            }
        }
        Ok(())
    }
    
    async fn receive_timeout_async(&self, timeout: Duration) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::timeout(timeout, self.receive_async()).await
            .map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "Receive timeout")) as Box<dyn std::error::Error + Send + Sync>)?
    }
}

/// File transfer service for NDN-based file operations
pub struct FileTransferService {
    transport: NdnQuicAsyncTransport,
    publisher: DataPacketPublisher,
    reassembly_engine: FileReassemblyEngine,
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    /// Cached QUIC connection for reuse
    cached_connection: tokio::sync::RwLock<Option<Arc<udcn_transport::Connection>>>,
}

impl FileTransferService {
    /// Create a new file transfer service
    pub async fn new(local_port: u16, remote_addr: Option<SocketAddr>) -> Result<Self, Box<dyn std::error::Error>> {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], local_port));
        
        // Create QUIC transport (server mode if no remote address, client mode otherwise)
        let server_mode = remote_addr.is_none();
        let transport = NdnQuicAsyncTransport::new(local_addr, server_mode).await?;
        
        // Create data publisher
        let publisher_config = PublisherConfig {
            default_freshness_period: Some(Duration::from_secs(60)),
            enable_signatures: false,
            signature_type: 1,
            key_locator: None,
            max_cache_size: 1000,
            default_content_type: udcn_core::packets::ContentType::Blob,
            include_chunk_metadata: true,
        };
        let publisher = DataPacketPublisher::new(publisher_config);
        
        // Create reassembly engine
        let reassembly_config = ReassemblyConfig {
            max_concurrent_files: 10,
            reassembly_timeout: Duration::from_secs(300),
            max_buffer_memory: 50 * 1024 * 1024,
            enable_duplicate_detection: true,
            temp_directory: std::env::temp_dir(),
            verify_integrity: true,
            max_out_of_order_chunks: 100,
        };
        let reassembly_engine = FileReassemblyEngine::new(reassembly_config);
        
        Ok(Self {
            transport,
            publisher,
            reassembly_engine,
            local_addr,
            remote_addr,
            cached_connection: tokio::sync::RwLock::new(None),
        })
    }
    
    /// Get or establish a connection to the target address
    async fn get_or_create_connection(&self, target_addr: SocketAddr) -> Result<Arc<udcn_transport::Connection>, Box<dyn std::error::Error>> {
        // Check if we have a cached connection
        let cached_conn = self.cached_connection.read().await;
        if let Some(ref conn) = *cached_conn {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        drop(cached_conn);
        
        // Create new connection
        info!("Establishing new QUIC connection to {}", target_addr);
        let connection = self.transport.ndn_transport().quic_transport().connect(target_addr).await?;
        let connection_arc = Arc::new(connection);
        
        // Cache the connection
        let mut cached_conn = self.cached_connection.write().await;
        *cached_conn = Some(connection_arc.clone());
        
        Ok(connection_arc)
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
            buffer_size: 32768,
            include_metadata: true,
            content_type: udcn_core::packets::ContentType::Blob,
            max_chunks: -1,
            large_file_mode: false,
            max_memory_usage: 256 * 1024 * 1024,
            stream_buffer_size: 1024 * 1024,
            enable_chunk_integrity: false,
            chunk_hash_algorithm: udcn_transport::file_integrity::ChecksumAlgorithm::Sha256,
        };
        let mut file_chunker = FileChunker::new(chunking_config);
        
        // Create base NDN name
        let base_name = Name::from_str(ndn_name);
        
        // Prepare file and get metadata
        let metadata = file_chunker.prepare_file(file_path)?.clone();
        let total_chunks = metadata.total_chunks;
        
        // Chunk the file  
        let chunk_iterator = file_chunker.chunk_file(file_path, &base_name)?;
        
        info!("File chunked: {} chunks of {} bytes each", total_chunks, chunk_size);
        
        // Establish connection first
        let connection = self.get_or_create_connection(target_addr).await?;
        info!("Using QUIC connection to {}", target_addr);
        
        // Send file metadata as a special chunk
        let mut metadata_name = base_name.clone();
        metadata_name.append_str("metadata");
        let metadata_data = self.create_metadata_packet(&metadata, &metadata_name)?;
        info!("Sending metadata packet to {}", target_addr);
        self.send_data_packet(&metadata_data, target_addr).await?;
        info!("Metadata packet sent successfully");
        
        // Collect all chunks first
        let chunks: Vec<_> = chunk_iterator.collect::<Result<Vec<_>, _>>()?;
        let chunk_count = chunks.len();
        
        // Send chunks in parallel batches
        const PARALLEL_BATCH_SIZE: usize = 4;
        for (batch_idx, batch) in chunks.chunks(PARALLEL_BATCH_SIZE).enumerate() {
            let batch_start = batch_idx * PARALLEL_BATCH_SIZE;
            
            // Create tasks for parallel sending
            let mut send_tasks = Vec::new();
            for (offset, chunk) in batch.iter().enumerate() {
                let chunk_idx = batch_start + offset;
                let data = chunk.data.clone();
                let conn = connection.clone();
                let transport = self.transport.ndn_transport().clone();
                
                let task = tokio::spawn(async move {
                    transport.send_data_on_connection(&data, conn.as_ref()).await
                        .map_err(|e| format!("Failed to send chunk {}: {}", chunk_idx, e))
                });
                send_tasks.push((chunk_idx, task));
            }
            
            // Wait for all tasks in batch to complete
            for (chunk_idx, task) in send_tasks {
                task.await??;
                debug!("Sent chunk {}/{}", chunk_idx + 1, total_chunks);
                
                // Call progress callback if provided
                if let Some(ref callback) = progress_callback {
                    callback(chunk_idx + 1, total_chunks);
                }
            }
        }
        
        info!("File sent successfully: {} chunks", chunk_count);
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
        let base_name = Name::from_str(ndn_name);
        
        // Request metadata first
        let mut metadata_name = base_name.clone();
        metadata_name.append_str("metadata");
        let metadata_interest = Interest::new(metadata_name.clone());
        
        info!("Requesting file metadata via QUIC");
        let metadata_data = self.transport.ndn_transport().send_interest_request_multiplexed(
            &metadata_interest,
            source_addr,
            timeout_duration,
            None
        ).await?;
        let metadata: FileMetadata = self.parse_metadata_packet(metadata_data)?;
        
        info!("File metadata received: {} bytes, {} chunks", metadata.file_size, metadata.total_chunks);
        
        // Calculate number of chunks
        let total_chunks = metadata.total_chunks;
        let mut received_chunks = Vec::new();
        
        // QUIC provides reliable delivery, so we can request chunks sequentially
        // and rely on QUIC's built-in retry and congestion control
        info!("Starting reliable QUIC-based chunk retrieval for {} chunks", total_chunks);
        
        for chunk_index in 0..total_chunks {
            let mut chunk_name = base_name.clone();
            chunk_name.append_str(&format!("segment/{}", chunk_index));
            let chunk_interest = Interest::new(chunk_name);
            
            // Send Interest and receive Data via QUIC transport using NDN protocol
            match self.transport.ndn_transport().send_interest_request_multiplexed(
                &chunk_interest,
                source_addr, 
                Duration::from_secs(30), // Generous timeout since QUIC handles retries
                None // Default priority
            ).await {
                Ok(data_packet) => {
                    received_chunks.push((chunk_index, data_packet.content));
                    
                    // Call progress callback if provided
                    if let Some(ref callback) = progress_callback {
                        callback(chunk_index + 1, total_chunks);
                    }
                    
                    debug!("Received chunk {}/{} via QUIC", chunk_index + 1, total_chunks);
                }
                Err(e) => {
                    error!("Failed to receive chunk {} via QUIC: {}", chunk_index, e);
                    return Err(format!("Chunk {} retrieval failed: {}", chunk_index, e).into());
                }
            }
        }
        // With QUIC's reliable delivery, we should have received all chunks
        info!("Successfully received all {} chunks via QUIC", total_chunks);
        
        // Reassemble the file - simple implementation
        info!("Reassembling file from {} chunks", received_chunks.len());
        
        // Sort chunks by index to ensure correct order
        let mut sorted_chunks = received_chunks;
        sorted_chunks.sort_by_key(|(chunk_index, _)| *chunk_index);
        
        // Create output file
        let mut output_file = std::fs::File::create(output_path)?;
        
        // Write each chunk to the file in order
        for (_chunk_index, chunk_data) in sorted_chunks {
            output_file.write_all(&chunk_data)?;
        }
        
        output_file.sync_all()?;
        info!("File received successfully: {}", output_path.display());
        Ok(())
    }


    /// Send a data packet using cached connection
    async fn send_data_packet(&self, data: &Data, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Attempting to send data packet to {}", addr);
        
        // Get or create connection
        let connection = self.get_or_create_connection(addr).await?;
        
        // Send data using the existing connection (dereference Arc to get &Connection)
        self.transport.ndn_transport().send_data_on_connection(data, connection.as_ref()).await
            .map_err(|e| format!("Failed to send data via QUIC: {}", e))?;
        
        debug!("Data packet sent successfully to {}", addr);
        Ok(())
    }

    /// Create a metadata packet
    fn create_metadata_packet(&self, metadata: &FileMetadata, name: &Name) -> Result<Data, Box<dyn std::error::Error>> {
        let metadata_bytes = serde_json::to_vec(metadata)?;
        let data = Data::new(name.clone(), metadata_bytes);
        Ok(data)
    }


    /// Parse a metadata packet
    fn parse_metadata_packet(&self, data: Data) -> Result<FileMetadata, Box<dyn std::error::Error>> {
        let metadata: FileMetadata = serde_json::from_slice(&data.content)?;
        Ok(metadata)
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
            let pb = ProgressBar::new(0);
            pb.set_style(ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} chunks ({percent}%) {msg}"
            ).unwrap());
            let pb_clone = pb.clone();
            Some(Box::new(move |current: usize, total: usize| {
                if pb_clone.length().unwrap_or(0) != total as u64 {
                    pb_clone.set_length(total as u64);
                    pb_clone.set_message("Sending");
                }
                pb_clone.set_position(current as u64);
                if current == total {
                    pb_clone.finish_with_message("Sent");
                }
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
            let pb = ProgressBar::new(0);
            pb.set_style(ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} chunks ({percent}%) {msg}"
            ).unwrap());
            let pb_clone = pb.clone();
            Some(Box::new(move |current: usize, total: usize| {
                if pb_clone.length().unwrap_or(0) != total as u64 {
                    pb_clone.set_length(total as u64);
                    pb_clone.set_message("Receiving");
                }
                pb_clone.set_position(current as u64);
                if current == total {
                    pb_clone.finish_with_message("Received");
                }
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