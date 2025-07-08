/// Example demonstrating progress tracking for file transfers
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use udcn_transport::{
    progress_tracker::{ProgressTracker, ProgressTrackerConfig, TransferSessionId},
    data_publisher::{DataPacketPublisher, PublisherConfig},
    concurrent_server::{ConcurrentServer, ConcurrentServerConfig},
    file_chunking::{FileChunker, ChunkingConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Progress Tracking Demo");
    println!("========================");
    
    // Create progress tracker with configuration
    let config = ProgressTrackerConfig {
        max_concurrent_transfers: 10,
        reporting_interval: Duration::from_millis(500),
        enable_chunk_tracking: true,
        max_event_buffer: 1000,
    };
    
    let tracker = Arc::new(ProgressTracker::new(config));
    
    // Create data publisher with progress tracking
    let publisher = DataPacketPublisher::new(PublisherConfig::for_file_transfer())
        .with_progress_tracker(tracker.clone());
    
    // Create concurrent server with progress tracking
    let server = ConcurrentServer::new(ConcurrentServerConfig::for_file_transfer(), publisher)
        .with_progress_tracker(tracker.clone());
    
    // Subscribe to progress events
    let mut event_receiver = tracker.subscribe_events();
    
    // Spawn background task to monitor progress events
    let tracker_clone = tracker.clone();
    tokio::spawn(async move {
        while let Ok(event) = event_receiver.recv().await {
            match event {
                udcn_transport::progress_tracker::ProgressEvent::TransferStarted { 
                    session_id, file_name, file_size, .. 
                } => {
                    println!("📁 Transfer started: {} ({} bytes)", file_name, file_size);
                }
                udcn_transport::progress_tracker::ProgressEvent::ChunkSent { 
                    session_id, chunk_id, .. 
                } => {
                    if let Some(progress) = tracker_clone.get_progress(&session_id) {
                        println!(
                            "📦 Chunk {}: {:.1}% complete", 
                            chunk_id, 
                            progress.progress_percentage() * 100.0
                        );
                    }
                }
                udcn_transport::progress_tracker::ProgressEvent::TransferCompleted { 
                    session_id, bytes_sent, duration, .. 
                } => {
                    println!(
                        "✅ Transfer completed: {} bytes in {:.2}s ({:.2} KB/s)",
                        bytes_sent,
                        duration.as_secs_f64(),
                        bytes_sent as f64 / duration.as_secs_f64() / 1024.0
                    );
                }
                udcn_transport::progress_tracker::ProgressEvent::TransferFailed { 
                    session_id, error, .. 
                } => {
                    println!("❌ Transfer failed: {}", error);
                }
                _ => {}
            }
        }
    });
    
    // Simulate file transfers
    println!("\n🎯 Starting simulated file transfers...");
    
    // Transfer 1: Small file
    simulate_transfer(&tracker, "small_file.txt", 1024, 4).await?;
    
    // Transfer 2: Medium file
    simulate_transfer(&tracker, "medium_file.dat", 10240, 20).await?;
    
    // Transfer 3: Large file with some failures
    simulate_transfer_with_failures(&tracker, "large_file.bin", 102400, 100).await?;
    
    // Wait a bit for events to process
    time::sleep(Duration::from_secs(1)).await;
    
    // Display final statistics
    println!("\n📊 Final Statistics:");
    println!("===================");
    
    let metrics = tracker.get_metrics();
    println!("Active transfers: {}", metrics.active_transfers);
    println!("Completed transfers: {}", metrics.completed_transfers);
    println!("Failed transfers: {}", metrics.failed_transfers);
    println!("Total bytes sent: {}", metrics.total_bytes_sent);
    println!("Total chunks sent: {}", metrics.total_chunks_sent);
    println!("Failed chunks: {}", metrics.total_failed_chunks);
    println!("Overall rate: {:.2} KB/s", metrics.overall_rate / 1024.0);
    
    // Display health status
    match tracker.get_health_status() {
        Ok(health) => {
            println!("\n🏥 Health Status:");
            println!("================");
            println!("Total transfers: {}", health.total_transfers);
            println!("Active transfers: {}", health.active_transfers);
            println!("Failed transfers: {}", health.failed_transfers);
            println!("Failure rate: {:.1}%", health.failure_rate * 100.0);
            println!("Memory usage: {:.1} MB", health.memory_usage_mb);
        }
        Err(e) => println!("Error getting health status: {}", e),
    }
    
    // Cleanup finished transfers
    let cleaned = tracker.cleanup_transfers();
    println!("\n🧹 Cleaned up {} finished transfers", cleaned);
    
    println!("\n✨ Demo completed successfully!");
    
    Ok(())
}

async fn simulate_transfer(
    tracker: &Arc<ProgressTracker>,
    file_name: &str,
    file_size: u64,
    total_chunks: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = TransferSessionId::new(file_name, "demo_client");
    
    // Start transfer
    tracker.start_transfer(session_id.clone(), file_name.to_string(), file_size, total_chunks)?;
    tracker.update_state(&session_id, udcn_transport::progress_tracker::TransferState::Active)?;
    
    // Simulate chunk transfers
    let chunk_size = file_size / total_chunks as u64;
    for chunk_id in 0..total_chunks {
        time::sleep(Duration::from_millis(100)).await;
        tracker.update_chunk_sent(&session_id, chunk_id, chunk_size)?;
    }
    
    // Complete transfer
    tracker.complete_transfer(&session_id)?;
    
    Ok(())
}

async fn simulate_transfer_with_failures(
    tracker: &Arc<ProgressTracker>,
    file_name: &str,
    file_size: u64,
    total_chunks: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = TransferSessionId::new(file_name, "demo_client");
    
    // Start transfer
    tracker.start_transfer(session_id.clone(), file_name.to_string(), file_size, total_chunks)?;
    tracker.update_state(&session_id, udcn_transport::progress_tracker::TransferState::Active)?;
    
    // Simulate chunk transfers with some failures
    let chunk_size = file_size / total_chunks as u64;
    for chunk_id in 0..total_chunks {
        time::sleep(Duration::from_millis(50)).await;
        
        // Simulate 10% failure rate
        if chunk_id % 10 == 9 {
            tracker.update_chunk_failed(&session_id, chunk_id, "Simulated network error".to_string())?;
            // Retry after failure
            time::sleep(Duration::from_millis(200)).await;
            tracker.update_chunk_sent(&session_id, chunk_id, chunk_size)?;
        } else {
            tracker.update_chunk_sent(&session_id, chunk_id, chunk_size)?;
        }
    }
    
    // Complete transfer
    tracker.complete_transfer(&session_id)?;
    
    Ok(())
}