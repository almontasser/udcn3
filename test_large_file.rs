// Test script for large file handling
use udcn_transport::file_chunking::{ChunkingConfig, FileChunker};
use udcn_core::packets::Name;
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a large test file (10MB)
    let mut temp_file = NamedTempFile::new()?;
    let data_size = 10 * 1024 * 1024; // 10MB
    let test_data = (0..data_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    temp_file.write_all(&test_data)?;
    temp_file.flush()?;
    
    println!("Created test file with {} bytes ({} MB)", test_data.len(), test_data.len() / (1024 * 1024));
    
    // Test auto-configuration
    let auto_config = ChunkingConfig::auto_configure(data_size as u64);
    println!("Auto-configured chunk size: {} bytes", auto_config.chunk_size);
    println!("Large file mode: {}", auto_config.large_file_mode);
    println!("Memory limit: {} MB", auto_config.max_memory_usage / (1024 * 1024));
    
    // Create chunker and prepare file
    let mut chunker = FileChunker::new(auto_config);
    let metadata = chunker.prepare_file(temp_file.path())?;
    
    println!("File metadata:");
    println!("  Size: {} bytes", metadata.file_size);
    println!("  Total chunks: {}", metadata.total_chunks);
    println!("  Chunk size: {} bytes", metadata.chunk_size);
    
    // Test memory statistics
    if let Some((current, peak, available)) = chunker.memory_stats() {
        println!("Memory usage:");
        println!("  Current: {} MB", current / (1024 * 1024));
        println!("  Peak: {} MB", peak / (1024 * 1024));
        println!("  Available: {} MB", available / (1024 * 1024));
    }
    
    // Define base name for the file
    let base_name = Name::from_str("/test/large/file");
    
    // Test a few chunks with the optimized method
    println!("\nTesting optimized chunking:");
    for i in 0..5 {
        let chunk = chunker.create_chunk_optimized(&base_name, i)?;
        println!("  Chunk {}: {} bytes, final: {}", 
                 i, chunk.chunk_info.size, chunk.chunk_info.is_final);
    }
    
    // Test memory stats after chunk creation
    if let Some((current, peak, available)) = chunker.memory_stats() {
        println!("Memory usage after chunking:");
        println!("  Current: {} MB", current / (1024 * 1024));
        println!("  Peak: {} MB", peak / (1024 * 1024));
        println!("  Available: {} MB", available / (1024 * 1024));
    }
    
    println!("\nLarge file handling test completed successfully!");
    
    Ok(())
}