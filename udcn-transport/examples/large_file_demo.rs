// Demo for large file handling capability
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;
use udcn_transport::file_chunking::{ChunkingConfig, FileChunker};
use udcn_core::packets::Name;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a large test file (10MB)
    let mut temp_file = NamedTempFile::new()?;
    let data_size = 10 * 1024 * 1024; // 10MB
    let test_data = (0..data_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    temp_file.write_all(&test_data)?;
    temp_file.flush()?;
    
    println!("🚀 Large File Handling Demo");
    println!("==========================");
    println!("Created test file with {} bytes ({} MB)", test_data.len(), test_data.len() / (1024 * 1024));
    
    // Test auto-configuration
    let auto_config = ChunkingConfig::auto_configure(data_size as u64);
    println!("\n📊 Auto-configured settings:");
    println!("  Chunk size: {} bytes", auto_config.chunk_size);
    println!("  Large file mode: {}", auto_config.large_file_mode);
    println!("  Memory limit: {} MB", auto_config.max_memory_usage / (1024 * 1024));
    println!("  Stream buffer: {} KB", auto_config.stream_buffer_size / 1024);
    
    // Create chunker and prepare file
    let mut chunker = FileChunker::new(auto_config);
    let metadata = chunker.prepare_file(temp_file.path())?;
    
    println!("\n📄 File metadata:");
    println!("  Size: {} bytes", metadata.file_size);
    println!("  Total chunks: {}", metadata.total_chunks);
    println!("  Chunk size: {} bytes", metadata.chunk_size);
    
    let file_size = metadata.file_size; // Copy for later use
    
    // Test memory statistics
    if let Some((current, peak, available)) = chunker.memory_stats() {
        println!("\n💾 Memory usage after preparation:");
        println!("  Current: {} MB", current / (1024 * 1024));
        println!("  Peak: {} MB", peak / (1024 * 1024));
        println!("  Available: {} MB", available / (1024 * 1024));
    }
    
    // Define base name for the file
    let base_name = Name::from_str("/test/large/file");
    
    // Test a few chunks with the optimized method
    println!("\n🔧 Testing optimized chunking:");
    for i in 0..5 {
        let chunk = chunker.create_chunk_optimized(&base_name, i)?;
        println!("  Chunk {}: {} bytes, final: {}", 
                 i, chunk.chunk_info.size, chunk.chunk_info.is_final);
    }
    
    // Test memory stats after chunk creation
    if let Some((current, peak, available)) = chunker.memory_stats() {
        println!("\n💾 Memory usage after chunking:");
        println!("  Current: {} MB", current / (1024 * 1024));
        println!("  Peak: {} MB", peak / (1024 * 1024));
        println!("  Available: {} MB", available / (1024 * 1024));
    }
    
    // Test with iterator for streaming
    println!("\n🔄 Testing streaming iterator:");
    let chunk_iter = chunker.chunk_file(temp_file.path(), &base_name)?;
    
    let mut processed = 0;
    for (i, chunk_result) in chunk_iter.enumerate() {
        let chunk = chunk_result?;
        processed += chunk.chunk_info.size;
        
        if i < 3 || i % 100 == 0 {
            println!("  Chunk {}: {} bytes, processed: {:.1}%", 
                     i, 
                     chunk.chunk_info.size, 
                     (processed as f64 / file_size as f64) * 100.0);
        }
        
        if i >= 10 && i % 100 != 0 {
            break; // Don't process all chunks in demo
        }
    }
    
    println!("\n✅ Large file handling demo completed successfully!");
    
    Ok(())
}