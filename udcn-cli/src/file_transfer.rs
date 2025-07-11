use std::path::Path;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::io::Write;
use log::{info, warn, error, debug};
use tokio::time::{timeout, Duration};
use indicatif::{ProgressBar, ProgressStyle};

use udcn_core::{ComponentName, NameComponent};
use udcn_core::packets::{Interest, Data, Name};
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
        let transport = UdpTransport::new_bound(local_addr).await?;
        
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
        
        // Send file metadata as a special chunk
        let mut metadata_name = base_name.clone();
        metadata_name.append_str("metadata");
        let metadata_data = self.create_metadata_packet(&metadata, &metadata_name)?;
        self.send_data_packet(&metadata_data, target_addr).await?;
        
        // Send each chunk
        let mut chunk_count = 0;
        for chunk_result in chunk_iterator {
            let chunk = chunk_result?;
            self.send_data_packet(&chunk.data, target_addr).await?;
            chunk_count += 1;
            
            // Call progress callback if provided
            if let Some(ref callback) = progress_callback {
                callback(chunk_count, total_chunks);
            }
            
            debug!("Sent chunk {}/{}", chunk_count, total_chunks);
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
        
        info!("Requesting file metadata");
        let metadata_data = self.request_data(&metadata_interest, source_addr, timeout_duration).await?;
        let metadata: FileMetadata = self.parse_metadata_packet(&metadata_data)?;
        
        info!("File metadata received: {} bytes, {} chunks", metadata.file_size, metadata.total_chunks);
        
        // Calculate number of chunks
        let total_chunks = metadata.total_chunks;
        let mut received_chunks = Vec::new();
        let mut successful_chunks = 0;
        
        // Use streaming approach with single receiver and request pipelining
        let window_size = 16; // Large pipeline window
        let chunk_timeout = Duration::from_secs(2); // Shorter timeout for faster flow
        let mut failed_chunks = Vec::new();
        
        // Channels for coordination
        let (result_tx, mut result_rx) = tokio::sync::mpsc::channel(window_size * 3);
        let (request_tx, mut request_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(window_size * 2);
        
        // Single receiver task - eliminates UDP socket contention
        let transport_receiver = self.transport.clone();
        let receiver_result_tx = result_tx.clone();
        tokio::spawn(async move {
            let mut pending_requests = std::collections::HashMap::new();
            
            loop {
                tokio::select! {
                    // Handle incoming requests
                    request = request_rx.recv() => {
                        match request {
                            Some((chunk_index, interest_data)) => {
                                // Send Interest immediately
                                if let Err(e) = transport_receiver.send_to_async(&interest_data, source_addr).await {
                                    let _ = receiver_result_tx.send((chunk_index, Err(format!("Send failed: {}", e)))).await;
                                } else {
                                    // Track this request
                                    pending_requests.insert(chunk_index, std::time::Instant::now());
                                }
                            }
                            None => break, // Channel closed
                        }
                    }
                    
                    // Handle incoming responses  
                    response = transport_receiver.receive_async() => {
                        match response {
                            Ok(response) => {
                                // Find NDN Data packet
                                let decode_data = if response.len() > 0 && response[0] == 0x06 {
                                    &response
                                } else if response.len() > 16 {
                                    let mut found_offset = None;
                                    for offset in 1..std::cmp::min(32, response.len() - 8) {
                                        if offset < response.len() && response[offset] == 0x06 {
                                            found_offset = Some(offset);
                                            break;
                                        }
                                    }
                                    if let Some(offset) = found_offset {
                                        &response[offset..]
                                    } else {
                                        &response
                                    }
                                } else {
                                    &response
                                };
                                
                                // Decode and match to pending request
                                match Data::decode(decode_data) {
                                    Ok((data_packet, _)) => {
                                        // Extract chunk index from name
                                        if let Some(last_component) = data_packet.name.components.last() {
                                            if let Ok(index_str) = std::str::from_utf8(last_component) {
                                                if let Ok(chunk_index) = index_str.parse::<usize>() {
                                                    pending_requests.remove(&chunk_index);
                                                    let _ = receiver_result_tx.send((chunk_index, Ok(data_packet.content))).await;
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        // Ignore decode errors for continuous flow
                                    }
                                }
                            }
                            Err(_) => {
                                // Continue on transport errors
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        }
                    }
                    
                    // Timeout handling
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        let now = std::time::Instant::now();
                        let mut timed_out = Vec::new();
                        
                        for (&chunk_index, &request_time) in &pending_requests {
                            if now.duration_since(request_time) > chunk_timeout {
                                timed_out.push(chunk_index);
                            }
                        }
                        
                        for chunk_index in timed_out {
                            pending_requests.remove(&chunk_index);
                            let _ = receiver_result_tx.send((chunk_index, Err("Request timed out".to_string()))).await;
                        }
                    }
                }
            }
        });
        
        // Request sender task - maintains pipeline flow
        let request_sender = request_tx.clone();
        let base_name_clone = base_name.clone();
        tokio::spawn(async move {
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(window_size));
            
            for chunk_index in 0..total_chunks {
                let _permit = semaphore.acquire().await.unwrap();
                
                let mut chunk_name = base_name_clone.clone();
                chunk_name.append_str(&format!("segment/{}", chunk_index));
                let chunk_interest = Interest::new(chunk_name.clone());
                
                match chunk_interest.encode() {
                    Ok(interest_data) => {
                        if request_sender.send((chunk_index, interest_data)).await.is_err() {
                            break; // Channel closed
                        }
                    }
                    Err(e) => {
                        let _ = result_tx.send((chunk_index, Err(format!("Encode error: {}", e)))).await;
                    }
                }
                
                // Small delay to control flow rate
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        
        // Collect results continuously
        while successful_chunks + failed_chunks.len() < total_chunks {
            match result_rx.recv().await {
                Some((chunk_index, Ok(chunk_data))) => {
                    received_chunks.push((chunk_index, chunk_data));
                    successful_chunks += 1;
                    
                    // Call progress callback if provided
                    if let Some(ref callback) = progress_callback {
                        callback(successful_chunks, total_chunks);
                    }
                    
                    debug!("Received chunk {}/{}", successful_chunks, total_chunks);
                }
                Some((chunk_index, Err(e))) => {
                    warn!("Failed to receive chunk {}: {}", chunk_index, e);
                    failed_chunks.push(chunk_index);
                }
                None => break,
            }
        }
        
        // Report on failed chunks
        if !failed_chunks.is_empty() {
            warn!("Failed to receive {} chunks: {:?}", failed_chunks.len(), failed_chunks);
            warn!("Successfully received {}/{} chunks ({:.1}%)", 
                  successful_chunks, total_chunks, 
                  (successful_chunks as f64 / total_chunks as f64) * 100.0);
            
            // If we got most chunks, continue with partial file
            if successful_chunks > total_chunks * 3 / 4 { // At least 75% success
                warn!("Continuing with partial file ({:.1}% complete)", 
                      (successful_chunks as f64 / total_chunks as f64) * 100.0);
            } else {
                return Err(format!("Too many failed chunks: {}/{} failed", 
                                 failed_chunks.len(), total_chunks).into());
            }
        }
        
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

    /// Request data using an Interest packet
    async fn request_data(
        &self,
        interest: &Interest,
        addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Data, Box<dyn std::error::Error>> {
        // Encode and send the Interest
        let interest_data = interest.encode()?;
        self.transport.send_to_async(&interest_data, addr).await
            .map_err(|e| format!("Failed to send interest: {}", e))?;
        
        // Wait for response with timeout
        let response = timeout(timeout_duration, self.transport.receive_async()).await
            .map_err(|_| "Request timed out")?
            .map_err(|e| format!("Transport error: {}", e))?;
        
        // Debug: log response data for troubleshooting
        debug!("Response data length: {}, first 32 bytes: {:?}", response.len(), &response[..std::cmp::min(32, response.len())]);
        
        // Check if response starts with proper NDN packet type (0x06 for Data)
        let decode_data = if response.len() > 0 && response[0] == 0x06 {
            // Proper NDN Data packet
            debug!("Found NDN Data packet at start");
            &response
        } else if response.len() > 16 {
            // Look for NDN Data packet starting at different offsets
            let mut found_offset = None;
            for offset in 1..std::cmp::min(32, response.len() - 8) {
                if offset < response.len() && response[offset] == 0x06 {
                    // Verify this looks like valid NDN packet by checking length encoding
                    if offset + 3 < response.len() {
                        let remaining_len = response.len() - offset;
                        debug!("Found potential NDN Data packet at offset {}, remaining length: {}", offset, remaining_len);
                        debug!("NDN header at offset {}: {:02X?}", offset, &response[offset..std::cmp::min(offset+8, response.len())]);
                        found_offset = Some(offset);
                        break;
                    }
                }
            }
            if let Some(offset) = found_offset {
                &response[offset..]
            } else {
                error!("No NDN Data packet found in response");
                &response
            }
        } else {
            &response
        };
        
        // Decode the response
        let (data_packet, _) = Data::decode(decode_data).map_err(|e| {
            error!("Failed to decode data packet. Response length: {}, error: {}", response.len(), e);
            if response.len() >= 8 {
                error!("Response header bytes: {:02X?}", &response[..8]);
            }
            if decode_data != &response {
                error!("Attempted decode from offset, decode data: {:02X?}", &decode_data[..std::cmp::min(8, decode_data.len())]);
            }
            format!("Failed to decode data: {}", e)
        })?;
        Ok(data_packet)
    }

    /// Send a data packet
    async fn send_data_packet(&self, data: &Data, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let encoded_data = data.encode()?;
        self.transport.send_to_async(&encoded_data, addr).await
            .map_err(|e| format!("Failed to send data: {}", e))?;
        Ok(())
    }

    /// Create a metadata packet
    fn create_metadata_packet(&self, metadata: &FileMetadata, name: &Name) -> Result<Data, Box<dyn std::error::Error>> {
        let metadata_bytes = serde_json::to_vec(metadata)?;
        let data = Data::new(name.clone(), metadata_bytes);
        Ok(data)
    }


    /// Parse a metadata packet
    fn parse_metadata_packet(&self, data: &Data) -> Result<FileMetadata, Box<dyn std::error::Error>> {
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