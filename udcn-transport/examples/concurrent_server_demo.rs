use std::path::Path;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::sleep;
use udcn_core::packets::{Interest, Name};
use udcn_transport::{
    ConcurrentServer, ConcurrentServerConfig, DataPacketPublisher, PublisherConfig,
    FileChunker, ChunkingConfig,
};
use std::io::Write;

/// Create a test file with specified size
fn create_test_file(size: usize) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    let data = (0..size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    file.write_all(&data).unwrap();
    file.flush().unwrap();
    file
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("🚀 Starting Concurrent Server Demo");
    println!("=====================================");
    
    // Create a test file
    let test_file = create_test_file(50000); // 50KB file
    println!("📁 Created test file: {} bytes", 50000);
    
    // Set up file chunking
    let chunking_config = ChunkingConfig::for_quic();
    let mut chunker = FileChunker::new(chunking_config);
    
    let base_name = Name::from_str("/demo/largefile");
    let chunks = chunker.chunk_file(test_file.path(), &base_name)?
        .collect::<Result<Vec<_>, _>>()?;
    
    println!("📦 File chunked into {} segments", chunks.len());
    
    // Set up data publisher
    let publisher_config = PublisherConfig::for_file_transfer();
    let publisher = DataPacketPublisher::new(publisher_config);
    
    // Publish all chunks
    let published_packets = publisher.publish_chunks(chunks.clone()).await?;
    println!("📤 Published {} data packets", published_packets.len());
    
    // Create concurrent server with optimized configuration
    let server_config = ConcurrentServerConfig::for_file_transfer();
    let mut server = ConcurrentServer::new(server_config, publisher);
    
    println!("⚙️  Server configuration:");
    println!("   - Max concurrent requests: {}", server.get_config().max_concurrent_requests);
    println!("   - Worker threads: {}", server.get_config().max_worker_threads);
    println!("   - Request timeout: {:?}", server.get_config().request_timeout);
    println!("   - Deduplication enabled: {}", server.get_config().enable_deduplication);
    
    // Start the server
    server.start().await?;
    println!("🟢 Concurrent server started successfully");
    
    // Simulate concurrent client requests
    println!("\n📡 Simulating concurrent client requests...");
    
    let mut tasks = Vec::new();
    
    // Create multiple concurrent requests for different chunks
    for i in 0..10 {
        let chunk_name = Name::from_str(&format!("/demo/largefile/segment/{}", i % chunks.len()));
        let interest = Interest::new(chunk_name);
        
        let server_handle = &server;
        let task = tokio::spawn(async move {
            let client_id = format!("client_{}", i);
            let start_time = std::time::SystemTime::now();
            
            match server_handle.handle_request(interest, Some(client_id.clone())).await {
                Ok(response) => {
                    let elapsed = start_time.elapsed().unwrap_or_default();
                    println!("✅ {}: Got response in {:?} (cache_hit: {})", 
                            client_id, elapsed, response.cache_hit);
                    
                    if let Some(data) = response.data {
                        println!("   📊 Data packet: {} bytes", data.encoded.len());
                    }
                }
                Err(e) => {
                    println!("❌ {}: Request failed: {}", client_id, e);
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all requests to complete
    for task in tasks {
        task.await?;
    }
    
    // Wait a bit to let statistics update
    sleep(Duration::from_millis(100)).await;
    
    // Show server statistics
    println!("\n📊 Server Statistics:");
    println!("====================");
    let stats = server.get_stats().await;
    println!("Requests received: {}", stats.requests_received);
    println!("Requests processed: {}", stats.requests_processed);
    println!("Requests failed: {}", stats.requests_failed);
    println!("Requests deduplicated: {}", stats.requests_deduplicated);
    println!("Success rate: {:.2}%", stats.success_rate() * 100.0);
    println!("Average processing time: {:.2}ms", stats.avg_processing_time_ms);
    println!("Peak concurrent requests: {}", stats.peak_concurrent_requests);
    println!("Cache hit ratio: {:.2}%", stats.cache_hit_ratio * 100.0);
    println!("Uptime: {}s", stats.uptime_seconds);
    
    // Test request deduplication
    println!("\n🔄 Testing request deduplication...");
    let duplicate_requests = vec![
        Interest::new(Name::from_str("/demo/largefile/segment/0")),
        Interest::new(Name::from_str("/demo/largefile/segment/0")),
        Interest::new(Name::from_str("/demo/largefile/segment/0")),
    ];
    
    let mut dedup_tasks = Vec::new();
    for (i, interest) in duplicate_requests.into_iter().enumerate() {
        let server_handle = &server;
        let task = tokio::spawn(async move {
            let client_id = format!("dedup_client_{}", i);
            let start_time = std::time::SystemTime::now();
            
            match server_handle.handle_request(interest, Some(client_id.clone())).await {
                Ok(response) => {
                    let elapsed = start_time.elapsed().unwrap_or_default();
                    println!("✅ {}: Response in {:?} (cache_hit: {})", 
                            client_id, elapsed, response.cache_hit);
                }
                Err(e) => {
                    println!("❌ {}: Request failed: {}", client_id, e);
                }
            }
        });
        
        dedup_tasks.push(task);
    }
    
    for task in dedup_tasks {
        task.await?;
    }
    
    // Final statistics
    println!("\n📊 Final Statistics:");
    println!("====================");
    let final_stats = server.get_stats().await;
    println!("Total requests: {}", final_stats.requests_received);
    println!("Deduplicated requests: {}", final_stats.requests_deduplicated);
    println!("Success rate: {:.2}%", final_stats.success_rate() * 100.0);
    println!("Throughput: {:.2} MB/s", final_stats.throughput_mbps());
    
    // Stop the server
    server.stop().await?;
    println!("\n🔴 Server stopped successfully");
    
    println!("\n🎉 Demo completed successfully!");
    println!("The concurrent server effectively handled multiple simultaneous requests");
    println!("with proper caching, deduplication, and resource management.");
    
    Ok(())
}