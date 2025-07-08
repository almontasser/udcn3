use std::io::Write;
use tempfile::NamedTempFile;
use udcn_core::packets::Name;
use udcn_transport::{FileChunker, ChunkingConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create a test file
    let mut temp_file = NamedTempFile::new()?;
    let test_data = (0..10000).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    temp_file.write_all(&test_data)?;
    temp_file.flush()?;
    
    println!("Created test file with {} bytes", test_data.len());
    
    // Configure chunking for QUIC transport
    let config = ChunkingConfig::for_quic();
    println!("Using chunk size: {} bytes", config.chunk_size);
    
    // Create chunker and prepare file
    let mut chunker = FileChunker::new(config);
    let metadata = chunker.prepare_file(temp_file.path())?;
    
    println!("File metadata:");
    println!("  Size: {} bytes", metadata.file_size);
    println!("  Total chunks: {}", metadata.total_chunks);
    println!("  Chunk size: {} bytes", metadata.chunk_size);
    
    // Define base name for the file
    let base_name = Name::from_str("/example/file/data");
    
    // Chunk the file
    let chunk_iter = chunker.chunk_file(temp_file.path(), &base_name)?;
    
    println!("\nProcessing chunks:");
    for (i, chunk_result) in chunk_iter.enumerate() {
        let chunk = chunk_result?;
        
        println!(
            "  Chunk {}: {} bytes, NDN name: {}, is_final: {}",
            i,
            chunk.chunk_info.size,
            chunk.name,
            chunk.chunk_info.is_final
        );
        
        // Encode chunk as NDN Data packet
        let encoded = chunk.encode()?;
        println!("    Encoded packet size: {} bytes", encoded.len());
        
        // Only show first few chunks to avoid spam
        if i >= 5 {
            println!("    ... (showing first 6 chunks only)");
            break;
        }
    }
    
    println!("\nFile chunking demonstration completed successfully!");
    
    Ok(())
}