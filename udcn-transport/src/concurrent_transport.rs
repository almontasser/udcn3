use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio::time::timeout;
use tracing::{debug, warn, error};
use async_trait::async_trait;

use crate::{Transport, AsyncTransport, ConcurrentTransport, TransportStats};

/// Configuration for concurrent transport operations
#[derive(Debug, Clone)]
pub struct ConcurrentTransportConfig {
    /// Maximum number of concurrent operations
    pub max_concurrent_ops: usize,
    /// Default timeout for operations
    pub default_timeout: Duration,
    /// Enable operation statistics tracking
    pub enable_stats: bool,
    /// Maximum retry attempts for failed operations
    pub max_retries: usize,
    /// Backoff duration between retries
    pub retry_backoff: Duration,
    /// Enable connection pooling
    pub enable_pooling: bool,
    /// Maximum connections in pool
    pub max_pool_size: usize,
}

impl Default for ConcurrentTransportConfig {
    fn default() -> Self {
        Self {
            max_concurrent_ops: 100,
            default_timeout: Duration::from_secs(30),
            enable_stats: true,
            max_retries: 3,
            retry_backoff: Duration::from_millis(100),
            enable_pooling: true,
            max_pool_size: 10,
        }
    }
}

/// Thread-safe wrapper around any Transport implementation
#[derive(Clone)]
pub struct ConcurrentTransportWrapper<T: Transport + Send + Sync + Clone> {
    inner: Arc<T>,
    stats: Arc<RwLock<TransportStats>>,
    config: ConcurrentTransportConfig,
    semaphore: Arc<Semaphore>,
    shutdown_sender: Arc<Mutex<Option<broadcast::Sender<()>>>>,
}

impl<T: Transport + Send + Sync + Clone + 'static> ConcurrentTransportWrapper<T> {
    /// Create a new concurrent transport wrapper
    pub fn new(inner: T, config: ConcurrentTransportConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_ops));
        let (shutdown_sender, _) = broadcast::channel(1);
        
        Self {
            inner: Arc::new(inner),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            config,
            semaphore,
            shutdown_sender: Arc::new(Mutex::new(Some(shutdown_sender))),
        }
    }

    /// Create with default configuration
    pub fn with_default_config(inner: T) -> Self {
        Self::new(inner, ConcurrentTransportConfig::default())
    }

    /// Update statistics for successful operation
    fn update_stats_success(&self, bytes: usize, is_send: bool) {
        if !self.config.enable_stats {
            return;
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.last_activity = Some(Instant::now());
            if is_send {
                stats.bytes_sent += bytes as u64;
                stats.packets_sent += 1;
            } else {
                stats.bytes_received += bytes as u64;
                stats.packets_received += 1;
            }
        }
    }

    /// Update statistics for failed operation
    fn update_stats_error(&self, is_send: bool) {
        if !self.config.enable_stats {
            return;
        }

        if let Ok(mut stats) = self.stats.write() {
            if is_send {
                stats.send_errors += 1;
            } else {
                stats.receive_errors += 1;
            }
        }
    }

    /// Execute operation with retry logic
    async fn execute_with_retry<F, Fut, R>(&self, operation: F) -> Result<R, Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>>,
    {
        let mut last_error = None;
        
        for attempt in 1..=self.config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("Operation failed on attempt {}/{}: {}", attempt, self.config.max_retries, e);
                    last_error = Some(e);
                    
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(self.config.retry_backoff * attempt as u32).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| "All retry attempts failed".into()))
    }

    /// Shutdown the concurrent transport
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Shutting down concurrent transport");
        
        // Send shutdown signal
        let sender_guard = self.shutdown_sender.lock().await;
        if let Some(sender) = sender_guard.as_ref() {
            let _ = sender.send(());
        }

        // Wait for all operations to complete
        let _permits = self.semaphore.acquire_many(self.config.max_concurrent_ops as u32).await
            .map_err(|e| format!("Failed to acquire shutdown permits: {}", e))?;

        // Close the inner transport
        self.inner.close()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("Failed to close inner transport: {}", e).into() })
    }
}

impl<T: Transport + Send + Sync + Clone + 'static> Transport for ConcurrentTransportWrapper<T> {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let result = self.inner.send(data);
        
        match &result {
            Ok(_) => self.update_stats_success(data.len(), true),
            Err(_) => self.update_stats_error(true),
        }
        
        result
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let result = self.inner.receive();
        
        match &result {
            Ok(data) => self.update_stats_success(data.len(), false),
            Err(_) => self.update_stats_error(false),
        }
        
        result
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.inner.close()
    }
}

#[async_trait]
impl<T: Transport + Send + Sync + Clone + 'static> AsyncTransport for ConcurrentTransportWrapper<T> {
    async fn send_async(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _permit = self.semaphore.acquire().await
            .map_err(|e| format!("Failed to acquire semaphore: {}", e))?;

        let inner = Arc::clone(&self.inner);
        let data = data.to_vec();
        let data_len = data.len();

        let result = self.execute_with_retry(|| {
            let inner = Arc::clone(&inner);
            let data = data.clone();
            async move {
                let result = tokio::task::spawn_blocking(move || {
                    inner.send(&data).map_err(|e| e.to_string())
                }).await;

                match result {
                    Ok(transport_result) => transport_result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() }),
                    Err(e) => Err(format!("Task join error: {}", e).into()),
                }
            }
        }).await;

        match &result {
            Ok(_) => self.update_stats_success(data_len, true),
            Err(_) => self.update_stats_error(true),
        }

        result
    }

    async fn receive_async(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let _permit = self.semaphore.acquire().await
            .map_err(|e| format!("Failed to acquire semaphore: {}", e))?;

        let inner = Arc::clone(&self.inner);

        let result = self.execute_with_retry(|| {
            let inner = Arc::clone(&inner);
            async move {
                let result = tokio::task::spawn_blocking(move || {
                    inner.receive().map_err(|e| e.to_string())
                }).await;

                match result {
                    Ok(transport_result) => transport_result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() }),
                    Err(e) => Err(format!("Task join error: {}", e).into()),
                }
            }
        }).await;

        match &result {
            Ok(data) => self.update_stats_success(data.len(), false),
            Err(_) => self.update_stats_error(false),
        }

        result
    }

    async fn close_async(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let inner = Arc::clone(&self.inner);
        
        tokio::task::spawn_blocking(move || {
            inner.close().map_err(|e| e.to_string())
        }).await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("Task join error: {}", e).into() })?
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
    }

    async fn send_to_async(&self, data: &[u8], _addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For transports that don't support addressing, fall back to regular send
        self.send_async(data).await
    }

    async fn receive_timeout_async(&self, timeout_duration: Duration) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        timeout(timeout_duration, self.receive_async()).await
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> { "Receive operation timed out".into() })?
    }
}

impl<T: Transport + Send + Sync + Clone + 'static> ConcurrentTransport for ConcurrentTransportWrapper<T> {
    fn get_stats(&self) -> TransportStats {
        self.stats.read().map(|stats| stats.clone()).unwrap_or_else(|_| {
            warn!("Failed to read transport stats, returning default");
            TransportStats::default()
        })
    }

    fn reset_stats(&self) {
        if let Ok(mut stats) = self.stats.write() {
            *stats = TransportStats::default();
            debug!("Transport stats reset");
        } else {
            warn!("Failed to reset transport stats");
        }
    }
}

/// Concurrent operation pool for managing multiple transport operations
pub struct ConcurrentOperationPool<T: ConcurrentTransport> {
    transports: Vec<T>,
    current_index: Arc<RwLock<usize>>,
    config: ConcurrentTransportConfig,
}

impl<T: ConcurrentTransport> ConcurrentOperationPool<T> {
    /// Create a new operation pool
    pub fn new(transports: Vec<T>, config: ConcurrentTransportConfig) -> Self {
        Self {
            transports,
            current_index: Arc::new(RwLock::new(0)),
            config,
        }
    }

    /// Get the next transport in round-robin fashion
    pub fn get_next_transport(&self) -> Option<&T> {
        if self.transports.is_empty() {
            return None;
        }

        let mut index = self.current_index.write().ok()?;
        let transport = self.transports.get(*index)?;
        *index = (*index + 1) % self.transports.len();
        Some(transport)
    }

    /// Execute operation on the least loaded transport
    pub async fn execute_on_best_transport<F, Fut, R>(&self, operation: F) -> Result<R, Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(&T) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send,
        R: Send,
    {
        if self.transports.is_empty() {
            return Err("No transports available in pool".into());
        }

        // Find transport with lowest error rate
        let best_transport = self.transports.iter()
            .min_by(|a, b| {
                let a_error_rate = a.get_stats().error_rate();
                let b_error_rate = b.get_stats().error_rate();
                a_error_rate.partial_cmp(&b_error_rate).unwrap_or(std::cmp::Ordering::Equal)
            })
            .ok_or("Failed to find best transport")?;

        operation(best_transport).await
    }

    /// Execute operation concurrently on multiple transports
    pub async fn execute_concurrent<F, Fut, R>(&self, operation: F) -> Vec<Result<R, Box<dyn std::error::Error + Send + Sync>>>
    where
        F: Fn(&T) -> Fut + Send + Sync + Clone,
        Fut: std::future::Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send,
        R: Send,
    {
        let futures: Vec<_> = self.transports.iter()
            .map(|transport| operation(transport))
            .collect();

        futures::future::join_all(futures).await
    }

    /// Get aggregate statistics from all transports
    pub fn get_aggregate_stats(&self) -> TransportStats {
        let mut aggregate = TransportStats::default();
        
        for transport in &self.transports {
            let stats = transport.get_stats();
            aggregate.bytes_sent += stats.bytes_sent;
            aggregate.bytes_received += stats.bytes_received;
            aggregate.packets_sent += stats.packets_sent;
            aggregate.packets_received += stats.packets_received;
            aggregate.send_errors += stats.send_errors;
            aggregate.receive_errors += stats.receive_errors;
            aggregate.active_connections += stats.active_connections;
            aggregate.total_connections += stats.total_connections;
            
            // Use the earliest created_at time
            if stats.created_at < aggregate.created_at {
                aggregate.created_at = stats.created_at;
            }
            
            // Use the latest activity time
            if let Some(activity) = stats.last_activity {
                match aggregate.last_activity {
                    Some(last) if activity > last => aggregate.last_activity = Some(activity),
                    None => aggregate.last_activity = Some(activity),
                    _ => {}
                }
            }
        }
        
        aggregate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockTransport {
        call_count: Arc<AtomicUsize>,
        should_fail: bool,
    }

    impl MockTransport {
        fn new(should_fail: bool) -> Self {
            Self {
                call_count: Arc::new(AtomicUsize::new(0)),
                should_fail,
            }
        }

        fn get_call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl Clone for MockTransport {
        fn clone(&self) -> Self {
            Self {
                call_count: Arc::clone(&self.call_count),
                should_fail: self.should_fail,
            }
        }
    }

    impl Transport for MockTransport {
        fn send(&self, _data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err("Mock send failure".into())
            } else {
                Ok(())
            }
        }

        fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err("Mock receive failure".into())
            } else {
                Ok(vec![1, 2, 3, 4])
            }
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_concurrent_transport_wrapper() {
        let mock_transport = MockTransport::new(false);
        let concurrent_transport = ConcurrentTransportWrapper::with_default_config(mock_transport.clone());

        // Test async send
        let result = concurrent_transport.send_async(b"test data").await;
        assert!(result.is_ok());

        // Test async receive
        let result = concurrent_transport.receive_async().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![1, 2, 3, 4]);

        // Verify stats
        let stats = concurrent_transport.get_stats();
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let mock_transport = MockTransport::new(false);
        let concurrent_transport = ConcurrentTransportWrapper::with_default_config(mock_transport.clone());

        // Execute multiple concurrent operations
        let handles: Vec<_> = (0..10).map(|_| {
            let transport = concurrent_transport.clone();
            tokio::spawn(async move {
                transport.send_async(b"test").await
            })
        }).collect();

        // Wait for all operations to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        let stats = concurrent_transport.get_stats();
        assert_eq!(stats.packets_sent, 10);
    }

    #[tokio::test]
    async fn test_retry_logic() {
        let mock_transport = MockTransport::new(true); // Always fails
        let mut config = ConcurrentTransportConfig::default();
        config.max_retries = 3;
        config.retry_backoff = Duration::from_millis(1);
        
        let concurrent_transport = ConcurrentTransportWrapper::new(mock_transport.clone(), config);

        let result = concurrent_transport.send_async(b"test data").await;
        assert!(result.is_err());

        // Should have tried 3 times
        assert_eq!(mock_transport.get_call_count(), 3);
    }
}