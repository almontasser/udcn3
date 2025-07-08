/*!
 * NDN Data Packet Publication System Demo
 * 
 * This example demonstrates the complete file transfer pipeline:
 * 1. File chunking using the FileChunker
 * 2. Publishing file chunks as NDN Data packets
 * 3. Handling Interest packets and serving cached Data packets
 * 4. Statistics tracking and cache management
 */

use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;
use udcn_core::packets::{Name, Interest, KeyLocator};
use udcn_transport::{
    FileChunker, ChunkingConfig, DataPacketPublisher, PublisherConfig
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 NDN Data Packet Publication System Demo");
    println!("==========================================\n");

    // Step 1: Create a sample file for demonstration
    println!("📁 Creating sample file...");
    let sample_file = create_sample_file(10_000)?; // 10KB file
    let file_path = sample_file.path();
    println!("   Created file: {:?} (10KB)", file_path);

    // Step 2: Configure file chunking
    println!("\n🔧 Configuring file chunking...");
    let chunking_config = ChunkingConfig::for_quic(); // QUIC-optimized chunks
    let mut chunker = FileChunker::new(chunking_config.clone());
    println!("   Chunk size: {} bytes", chunking_config.chunk_size);

    // Step 3: Configure data publisher
    println!("\n📡 Configuring data packet publisher...");
    let publisher_config = PublisherConfig::for_file_transfer()
        .with_signatures(
            KeyLocator::Name(Name::from_str("/demo/publisher/key")),
            1 // SHA256withRSA
        );
    
    let publisher = DataPacketPublisher::new(publisher_config)
        .with_signature_value(b"demo_signature_value".to_vec());
    
    println!("   Freshness period: 2 hours");
    println!("   Signatures: enabled");
    println!("   Cache size limit: 2000 packets");

    // Step 4: Chunk the file and publish packets
    println!("\n✂️  Chunking file and publishing packets...");
    let base_name = Name::from_str("/demo/file/sample.dat");
    let chunk_iterator = chunker.chunk_file(file_path, &base_name)?;
    
    let mut published_packets = Vec::new();
    let mut chunk_count = 0;
    
    for chunk_result in chunk_iterator {
        let chunk = chunk_result?;
        chunk_count += 1;
        
        println!("   📦 Publishing chunk {}: {} bytes, sequence: {}, final: {}", 
                 chunk_count, 
                 chunk.chunk_info.size,
                 chunk.chunk_info.sequence,
                 chunk.chunk_info.is_final);
        
        let published_packet = publisher.publish_chunk(chunk).await?;
        published_packets.push(published_packet);
    }
    
    println!("   ✅ Published {} chunks successfully", chunk_count);

    // Step 5: Display publication statistics
    println!("\n📊 Publication Statistics:");
    let stats = publisher.get_stats().await;
    println!("   Packets published: {}", stats.packets_published);
    println!("   Total bytes published: {} bytes", stats.bytes_published);
    println!("   Average packet size: {:.1} bytes", stats.avg_packet_size);
    
    let (cache_size, max_cache_size) = publisher.get_cache_info().await?;
    println!("   Cache utilization: {}/{} packets", cache_size, max_cache_size);

    // Step 6: Simulate Interest packet handling
    println!("\n🔍 Simulating Interest packet handling...");
    
    // Create Interest packets for different chunks
    let interest_scenarios = vec![
        (Name::from_str("/demo/file/sample.dat/segment/0"), "First chunk"),
        (Name::from_str("/demo/file/sample.dat/segment/3"), "Middle chunk"),
        (Name::from_str("/demo/file/sample.dat/segment/8"), "Last chunk"),
        (Name::from_str("/demo/file/sample.dat/segment/99"), "Non-existent chunk"),
        (Name::from_str("/demo/different/file/segment/0"), "Different file"),
    ];

    for (interest_name, description) in interest_scenarios {
        let interest = Interest::new(interest_name.clone())
            .with_nonce(12345u32)
            .with_lifetime(Duration::from_secs(4));
        
        println!("   📥 Processing Interest: {} ({})", interest_name, description);
        
        match publisher.handle_interest(&interest).await? {
            Some(response_packet) => {
                println!("      ✅ Served cached packet: {} bytes, served {} times",
                         response_packet.encoded.len(),
                         response_packet.serve_count);
            }
            None => {
                println!("      ❌ No data available");
            }
        }
    }

    // Step 7: Display final statistics
    println!("\n📈 Final Statistics:");
    let final_stats = publisher.get_stats().await;
    println!("   Interests processed: {}", final_stats.interests_processed);
    println!("   Cache hits: {}", final_stats.cache_hits);
    println!("   Cache misses: {}", final_stats.cache_misses);
    println!("   Cache hit ratio: {:.1}%", final_stats.cache_hit_ratio() * 100.0);
    println!("   Publication failures: {}", final_stats.publication_failures);

    // Step 8: Demonstrate cache management
    println!("\n🧹 Cache Management Demo:");
    let cached_names = publisher.list_cached_packets().await?;
    println!("   Cached packet names:");
    for name in &cached_names[..5.min(cached_names.len())] {
        println!("      - {}", name);
    }
    if cached_names.len() > 5 {
        println!("      ... and {} more", cached_names.len() - 5);
    }

    // Step 9: Test freshness by simulating stale packets
    println!("\n⏰ Testing packet freshness...");
    let mut quick_config = PublisherConfig::default();
    quick_config.default_freshness_period = Some(Duration::from_millis(1)); // Very short
    
    let quick_publisher = DataPacketPublisher::new(quick_config);
    
    // Publish a packet
    let test_chunk = create_test_chunk(0, false);
    let test_name = test_chunk.name.clone();
    quick_publisher.publish_chunk(test_chunk).await?;
    
    println!("   📦 Published packet with 1ms freshness period");
    
    // Wait for it to become stale
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // Try to retrieve it
    let stale_interest = Interest::new(test_name);
    match quick_publisher.handle_interest(&stale_interest).await? {
        Some(_) => println!("      ⚠️  Packet still served (unexpected)"),
        None => println!("      ✅ Stale packet correctly rejected"),
    }

    // Step 10: Performance demonstration
    println!("\n⚡ Performance Test:");
    let perf_config = PublisherConfig::for_streaming();
    let perf_publisher = DataPacketPublisher::new(perf_config);
    
    let start_time = std::time::Instant::now();
    let mut perf_chunks = Vec::new();
    
    // Create and publish 100 chunks rapidly
    for i in 0..100 {
        let chunk = create_test_chunk(i, i == 99);
        perf_chunks.push(chunk);
    }
    
    perf_publisher.publish_chunks(perf_chunks).await?;
    let publish_duration = start_time.elapsed();
    
    println!("   Published 100 chunks in {:?}", publish_duration);
    println!("   Throughput: {:.1} chunks/second", 
             100.0 / publish_duration.as_secs_f64());

    println!("\n🎉 Demo completed successfully!");
    println!("   The NDN Data Packet Publication System demonstrates:");
    println!("   ✓ File chunking with configurable chunk sizes");
    println!("   ✓ NDN Data packet creation with proper metadata"); 
    println!("   ✓ Interest/Data matching and serving");
    println!("   ✓ Packet caching with freshness control");
    println!("   ✓ Digital signature support");
    println!("   ✓ Comprehensive statistics tracking");
    println!("   ✓ High-performance batch operations");

    Ok(())
}

/// Create a sample file with test data
fn create_sample_file(size: usize) -> Result<NamedTempFile, Box<dyn std::error::Error>> {
    let mut file = NamedTempFile::new()?;
    
    // Create interesting test data with patterns
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        data.push(match i % 256 {
            n if n < 64 => (i % 256) as u8,           // Counter pattern
            n if n < 128 => ((i * 3) % 256) as u8,    // Pseudo-random pattern
            n if n < 192 => 0xFF,                     // Block of 0xFF
            _ => 0x00,                                // Block of 0x00
        });
    }
    
    file.write_all(&data)?;
    file.flush()?;
    Ok(file)
}

/// Create a test chunk for demonstration purposes
fn create_test_chunk(sequence: usize, is_final: bool) -> udcn_transport::FileChunk {
    use udcn_transport::file_chunking::{ChunkInfo, FileChunk};
    
    let base_name = Name::from_str("/test/performance/chunk");
    let chunk_data = vec![42u8; 1200]; // QUIC-safe size
    
    let chunk_info = ChunkInfo {
        sequence,
        size: chunk_data.len(),
        offset: (sequence * 1200) as u64,
        is_final,
        file_metadata: None,
    };

    FileChunk::new(&base_name, sequence, chunk_data, chunk_info)
}