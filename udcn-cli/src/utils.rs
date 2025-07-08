use std::{fs, path::Path, io::{self, Read}};
use log::{info, debug};

pub fn read_config_file<P: AsRef<Path>>(path: P) -> Result<String, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    Ok(contents)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

pub fn parse_address(address: &str) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = address.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid address format. Expected host:port".into());
    }

    let host = parts[0].to_string();
    let port = parts[1].parse::<u16>()?;

    Ok((host, port))
}

pub struct FileChunker {
    chunk_size: usize,
}

impl FileChunker {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    pub fn chunk_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut file = fs::File::open(path)?;
        let mut chunks = Vec::new();
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            match file.read(&mut buffer)? {
                0 => break, // EOF
                n => {
                    chunks.push(buffer[..n].to_vec());
                    debug!("Created chunk {} of size {}", chunks.len(), n);
                }
            }
        }

        info!("File chunked into {} segments", chunks.len());
        Ok(chunks)
    }

    pub fn estimate_chunks<P: AsRef<Path>>(&self, path: P) -> Result<usize, Box<dyn std::error::Error>> {
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len() as usize;
        let chunk_count = (file_size + self.chunk_size - 1) / self.chunk_size; // Ceiling division
        Ok(chunk_count)
    }
}

pub struct ProgressTracker {
    total: usize,
    current: usize,
    start_time: std::time::Instant,
}

impl ProgressTracker {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            current: 0,
            start_time: std::time::Instant::now(),
        }
    }

    pub fn update(&mut self, current: usize, message: Option<String>) {
        self.current = current;
        let percentage = if self.total > 0 {
            (current * 100) / self.total
        } else {
            0
        };

        let elapsed = self.start_time.elapsed();
        let progress_bar = self.create_progress_bar(percentage);
        
        if let Some(msg) = message {
            println!("\r[{}] {}% - {} ({:.1}s)", progress_bar, percentage, msg, elapsed.as_secs_f64());
        } else {
            println!("\r[{}] {}% ({}/{}) - {:.1}s", progress_bar, percentage, current, self.total, elapsed.as_secs_f64());
        }
    }

    pub fn finish(&self, message: &str) {
        let elapsed = self.start_time.elapsed();
        println!("\n✓ {} ({:.1}s)", message, elapsed.as_secs_f64());
    }

    fn create_progress_bar(&self, percentage: usize) -> String {
        const BAR_LENGTH: usize = 30;
        let filled = (percentage * BAR_LENGTH) / 100;
        let empty = BAR_LENGTH - filled;
        
        format!("{}{}",
            "█".repeat(filled),
            "░".repeat(empty)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_parse_address() {
        let (host, port) = parse_address("127.0.0.1:8080").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_file_chunker() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a test file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, World! This is a test file for chunking.";
        temp_file.write_all(test_data).unwrap();

        let chunker = FileChunker::new(10);
        let chunks = chunker.chunk_file(temp_file.path()).unwrap();
        
        // Verify chunks
        assert_eq!(chunks.len(), 5); // 48 bytes in 10-byte chunks = 5 chunks
        
        // Reconstruct data
        let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reconstructed, test_data);
    }

    #[test]
    fn test_progress_tracker() {
        let mut tracker = ProgressTracker::new(100);
        tracker.update(50, Some("Half way".to_string()));
        assert_eq!(tracker.current, 50);
        assert_eq!(tracker.total, 100);
    }
}
