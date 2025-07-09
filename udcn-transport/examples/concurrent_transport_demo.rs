use std::time::Duration;

use udcn_transport::{
    Transport, AsyncTransport, ConcurrentTransport,
    ConcurrentTransportWrapper, ConcurrentTransportConfig,
    ConcurrentOperationPool, TransportStats,
};

/// Mock transport for demonstration
#[derive(Clone)]
struct MockTransport {
    id: String,
    delay: Duration,
}

impl MockTransport {
    fn new(id: &str, delay_ms: u64) -> Self {
        Self {
            id: id.to_string(),
            delay: Duration::from_millis(delay_ms),
        }
    }
}

impl Transport for MockTransport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Simulate network delay
        std::thread::sleep(self.delay);
        println!("Transport {} sent {} bytes", self.id, data.len());
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Simulate network delay
        std::thread::sleep(self.delay);
        let data = format!("Response from {}", self.id).into_bytes();
        println!("Transport {} received {} bytes", self.id, data.len());
        Ok(data)
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Transport {} closed", self.id);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo starting

    println!("Starting concurrent transport demonstration");

    // Create mock transports with different delays
    let transports = vec![
        MockTransport::new("fast", 50),
        MockTransport::new("medium", 100),
        MockTransport::new("slow", 200),
    ];

    demo_concurrent_wrapper(&transports[0]).await?;
    demo_operation_pool(transports).await?;

    println!("Concurrent transport demonstration completed");
    Ok(())
}

async fn demo_concurrent_wrapper(transport: &MockTransport) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Concurrent Transport Wrapper Demo ===");

    // Create configuration for concurrent operations
    let config = ConcurrentTransportConfig {
        max_concurrent_ops: 10,
        default_timeout: Duration::from_secs(5),
        enable_stats: true,
        max_retries: 2,
        retry_backoff: Duration::from_millis(100),
        enable_pooling: true,
        max_pool_size: 5,
    };

    // Wrap the transport for concurrent operations
    let concurrent_transport = ConcurrentTransportWrapper::new(transport.clone(), config);

    println!("Testing concurrent send operations...");

    // Test concurrent sends
    let send_handles: Vec<_> = (0..5).map(|i| {
        let transport = concurrent_transport.clone();
        let message = format!("Message {}", i);
        tokio::spawn(async move {
            transport.send_async(message.as_bytes()).await
        })
    }).collect();

    // Wait for all sends to complete
    for (i, handle) in send_handles.into_iter().enumerate() {
        match handle.await? {
            Ok(_) => println!("Send {} completed successfully", i),
            Err(e) => println!("Send {} failed: {}", i, e),
        }
    }

    println!("Testing concurrent receive operations...");

    // Test concurrent receives
    let receive_handles: Vec<_> = (0..3).map(|i| {
        let transport = concurrent_transport.clone();
        tokio::spawn(async move {
            let result = transport.receive_async().await;
            (i, result)
        })
    }).collect();

    // Wait for all receives to complete
    for handle in receive_handles {
        let (i, result) = handle.await?;
        match result {
            Ok(data) => println!("Receive {} got: {}", i, String::from_utf8_lossy(&data)),
            Err(e) => println!("Receive {} failed: {}", i, e),
        }
    }

    // Test timeout functionality
    println!("Testing receive with timeout...");
    match concurrent_transport.receive_timeout_async(Duration::from_millis(50)).await {
        Ok(data) => println!("Timeout receive got: {}", String::from_utf8_lossy(&data)),
        Err(_) => println!("Receive timed out as expected"),
    }

    // Display statistics
    let stats = concurrent_transport.get_stats();
    print_stats("Concurrent Transport", &stats);

    // Test graceful shutdown
    println!("Testing graceful shutdown...");
    if let Err(e) = concurrent_transport.shutdown().await {
        println!("Shutdown failed: {}", e);
    }

    Ok(())
}

async fn demo_operation_pool(transports: Vec<MockTransport>) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Concurrent Operation Pool Demo ===");

    let config = ConcurrentTransportConfig::default();

    // Wrap each transport for concurrent operations
    let concurrent_transports: Vec<_> = transports.into_iter()
        .map(|t| ConcurrentTransportWrapper::with_default_config(t))
        .collect();

    // Create operation pool
    let pool = ConcurrentOperationPool::new(concurrent_transports, config);

    println!("Testing load balancing across transports...");

    // Test round-robin distribution
    for i in 0..6 {
        if let Some(transport) = pool.get_next_transport() {
            let message = format!("Load balanced message {}", i);
            match transport.send_async(message.as_bytes()).await {
                Ok(_) => println!("Message {} sent via transport", i),
                Err(e) => println!("Message {} failed: {}", i, e),
            }
        }
    }

    println!("Testing best transport selection...");

    // Test operations on best transport (lowest error rate)
    let message = b"Best transport test";
    if let Some(best_transport) = pool.get_next_transport() {
        match best_transport.send_async(message).await {
            Ok(_) => println!("Best transport operation completed"),
            Err(e) => println!("Best transport operation failed: {}", e),
        }
    }

    println!("Testing concurrent execution across all transports...");

    // Test concurrent execution across all transports
    println!("Sending broadcast message to all transports...");
    
    // Get all transports and send concurrently
    let mut handles = Vec::new();
    for i in 0..3 {
        if let Some(transport) = pool.get_next_transport() {
            let transport_clone = transport.clone();
            let handle = tokio::spawn(async move {
                transport_clone.send_async(b"Broadcast message").await
            });
            handles.push((i, handle));
        }
    }
    
    // Wait for all to complete
    for (i, handle) in handles {
        match handle.await {
            Ok(Ok(_)) => println!("Concurrent send {} completed", i),
            Ok(Err(e)) => println!("Concurrent send {} failed: {}", i, e),
            Err(e) => println!("Concurrent send {} task failed: {}", i, e),
        }
    }

    // Display aggregate statistics
    let aggregate_stats = pool.get_aggregate_stats();
    print_stats("Operation Pool", &aggregate_stats);

    Ok(())
}

fn print_stats(label: &str, stats: &TransportStats) {
    println!("=== {} Statistics ===", label);
    println!("Bytes sent: {}", stats.bytes_sent);
    println!("Bytes received: {}", stats.bytes_received);
    println!("Packets sent: {}", stats.packets_sent);
    println!("Packets received: {}", stats.packets_received);
    println!("Send errors: {}", stats.send_errors);
    println!("Receive errors: {}", stats.receive_errors);
    println!("Active connections: {}", stats.active_connections);
    println!("Total connections: {}", stats.total_connections);
    println!("Throughput: {:.2} bytes/sec", stats.throughput_bps());
    println!("Error rate: {:.2}%", stats.error_rate() * 100.0);
    println!("Uptime: {:?}", stats.created_at.elapsed());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_transport_basic() {
        let transport = MockTransport::new("test", 10);
        let concurrent_transport = ConcurrentTransportWrapper::with_default_config(transport);

        // Test basic send
        let result = concurrent_transport.send_async(b"test data").await;
        assert!(result.is_ok());

        // Test basic receive
        let result = concurrent_transport.receive_async().await;
        assert!(result.is_ok());

        // Check stats
        let stats = concurrent_transport.get_stats();
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
    }

    #[tokio::test]
    async fn test_operation_pool() {
        let transports = vec![
            MockTransport::new("test1", 10),
            MockTransport::new("test2", 20),
        ];

        let concurrent_transports: Vec<_> = transports.into_iter()
            .map(|t| ConcurrentTransportWrapper::with_default_config(t))
            .collect();

        let pool = ConcurrentOperationPool::new(concurrent_transports, ConcurrentTransportConfig::default());

        // Test round-robin
        let transport1 = pool.get_next_transport().unwrap();
        let transport2 = pool.get_next_transport().unwrap();

        let result1 = transport1.send_async(b"test1").await;
        let result2 = transport2.send_async(b"test2").await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Check aggregate stats
        let stats = pool.get_aggregate_stats();
        assert_eq!(stats.packets_sent, 2);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let transport = MockTransport::new("concurrent", 5);
        let concurrent_transport = ConcurrentTransportWrapper::with_default_config(transport);

        // Execute multiple concurrent operations
        let handles: Vec<_> = (0..10).map(|_| {
            let transport = concurrent_transport.clone();
            tokio::spawn(async move {
                transport.send_async(b"concurrent test").await
            })
        }).collect();

        // Wait for all to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        let stats = concurrent_transport.get_stats();
        assert_eq!(stats.packets_sent, 10);
    }
}