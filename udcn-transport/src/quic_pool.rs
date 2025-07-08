use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{Result, Context};
use log::{debug, info};
use tokio::sync::RwLock;
use tokio::time::interval;
use quinn::Connection;

use crate::quic::QuicTransport;

/// Configuration for the connection pool
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum number of connections per peer
    pub max_connections_per_peer: usize,
    /// Maximum total connections in the pool
    pub max_total_connections: usize,
    /// Connection idle timeout before cleanup
    pub idle_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Load balancing strategy
    pub load_balancing_strategy: LoadBalancingStrategy,
    /// Connection reuse strategy
    pub reuse_strategy: ConnectionReuseStrategy,
    /// Health thresholds for connection monitoring
    pub health_thresholds: HealthThresholds,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_peer: 10,
            max_total_connections: 100,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            health_check_interval: Duration::from_secs(30),
            load_balancing_strategy: LoadBalancingStrategy::RoundRobin,
            reuse_strategy: ConnectionReuseStrategy::LeastUsed,
            health_thresholds: HealthThresholds::default(),
        }
    }
}

/// Load balancing strategies
#[derive(Clone, Debug)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    HealthBased,
}

/// Connection reuse strategies
#[derive(Clone, Debug)]
pub enum ConnectionReuseStrategy {
    LeastUsed,
    MostRecent,
    HealthiestFirst,
    StickySession,
}

/// Health thresholds for connection monitoring
#[derive(Clone, Debug)]
pub struct HealthThresholds {
    /// Maximum RTT before marking connection as degraded
    pub max_rtt: Duration,
    /// Minimum RTT for optimal connections
    pub optimal_rtt: Duration,
    /// Maximum number of failed health checks before marking unhealthy
    pub max_failed_checks: u32,
    /// Minimum connection age before health checking
    pub min_connection_age: Duration,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            max_rtt: Duration::from_millis(500),
            optimal_rtt: Duration::from_millis(100),
            max_failed_checks: 3,
            min_connection_age: Duration::from_secs(30),
        }
    }
}

/// Connection health status
#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Enhanced connection entry with health monitoring
#[derive(Clone)]
pub struct PooledConnection {
    pub connection: Connection,
    pub created_at: Instant,
    pub last_used: Instant,
    pub use_count: u64,
    pub health: ConnectionHealth,
    pub failed_health_checks: u32,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub stream_count: u32,
    pub health_metrics: ConnectionHealthMetrics,
}

/// Detailed health metrics for a connection
#[derive(Clone, Debug)]
pub struct ConnectionHealthMetrics {
    /// Average RTT over recent measurements
    pub avg_rtt: Duration,
    /// RTT variance for stability measurement
    pub rtt_variance: Duration,
    /// Estimated packet loss rate (0.0 to 1.0)
    pub packet_loss_rate: f64,
    /// Bandwidth utilization rate (bytes per second)
    pub bandwidth_utilization: u64,
    /// Number of stream errors encountered
    pub stream_errors: u32,
    /// Number of retransmissions detected
    pub retransmission_count: u32,
    /// Connection stability score (0.0 to 1.0)
    pub stability_score: f64,
    /// Last health check timestamp
    pub last_health_check: Instant,
    /// Recent RTT measurements for trend analysis
    pub recent_rtts: Vec<Duration>,
}

impl Default for ConnectionHealthMetrics {
    fn default() -> Self {
        Self {
            avg_rtt: Duration::from_millis(100),
            rtt_variance: Duration::ZERO,
            packet_loss_rate: 0.0,
            bandwidth_utilization: 0,
            stream_errors: 0,
            retransmission_count: 0,
            stability_score: 1.0,
            last_health_check: Instant::now(),
            recent_rtts: Vec::with_capacity(10),
        }
    }
}

impl PooledConnection {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            created_at: Instant::now(),
            last_used: Instant::now(),
            use_count: 0,
            health: ConnectionHealth::Healthy,
            failed_health_checks: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            stream_count: 0,
            health_metrics: ConnectionHealthMetrics::default(),
        }
    }
    
    pub fn mark_used(&mut self, bytes_sent: u64, bytes_received: u64) {
        let now = Instant::now();
        let duration_since_last_use = now.duration_since(self.last_used);
        
        self.last_used = now;
        self.use_count += 1;
        self.total_bytes_sent += bytes_sent;
        self.total_bytes_received += bytes_received;
        
        // Update bandwidth utilization
        if duration_since_last_use > Duration::ZERO {
            let bytes_per_second = ((bytes_sent + bytes_received) as f64 / duration_since_last_use.as_secs_f64()) as u64;
            self.health_metrics.bandwidth_utilization = bytes_per_second;
        }
    }
    
    pub fn update_health_metrics(&mut self, thresholds: &HealthThresholds) {
        let now = Instant::now();
        let current_rtt = self.connection.rtt();
        
        // Update RTT tracking
        self.health_metrics.recent_rtts.push(current_rtt);
        if self.health_metrics.recent_rtts.len() > 10 {
            self.health_metrics.recent_rtts.remove(0);
        }
        
        // Calculate average RTT and variance
        if !self.health_metrics.recent_rtts.is_empty() {
            let sum = self.health_metrics.recent_rtts.iter().sum::<Duration>();
            self.health_metrics.avg_rtt = sum / self.health_metrics.recent_rtts.len() as u32;
            
            // Calculate variance
            let avg_millis = self.health_metrics.avg_rtt.as_millis() as f64;
            let variance_sum: f64 = self.health_metrics.recent_rtts.iter()
                .map(|rtt| {
                    let diff = rtt.as_millis() as f64 - avg_millis;
                    diff * diff
                })
                .sum();
            let variance_millis = variance_sum / self.health_metrics.recent_rtts.len() as f64;
            self.health_metrics.rtt_variance = Duration::from_millis(variance_millis.sqrt() as u64);
        }
        
        // Calculate stability score based on RTT variance and other factors
        let rtt_stability = if self.health_metrics.rtt_variance.as_millis() > 50 {
            0.5 // High variance = low stability
        } else if self.health_metrics.rtt_variance.as_millis() > 20 {
            0.8 // Medium variance = medium stability
        } else {
            1.0 // Low variance = high stability
        };
        
        let health_factor = match self.health {
            ConnectionHealth::Healthy => 1.0,
            ConnectionHealth::Degraded => 0.6,
            ConnectionHealth::Unhealthy => 0.2,
        };
        
        self.health_metrics.stability_score = rtt_stability * health_factor;
        self.health_metrics.last_health_check = now;
        
        // Update health status based on comprehensive metrics
        self.update_health_status(thresholds);
    }
    
    fn update_health_status(&mut self, thresholds: &HealthThresholds) {
        let current_rtt = self.connection.rtt();
        
        // Check if connection is closed
        if self.is_closed() {
            self.health = ConnectionHealth::Unhealthy;
            self.failed_health_checks = thresholds.max_failed_checks;
            return;
        }
        
        // Multi-factor health assessment
        let mut health_issues = 0;
        
        // RTT check
        if current_rtt > thresholds.max_rtt {
            health_issues += 2;
        } else if current_rtt > thresholds.optimal_rtt * 2 {
            health_issues += 1;
        }
        
        // Stability check
        if self.health_metrics.stability_score < 0.5 {
            health_issues += 2;
        } else if self.health_metrics.stability_score < 0.8 {
            health_issues += 1;
        }
        
        // Stream error check
        if self.health_metrics.stream_errors > 5 {
            health_issues += 2;
        } else if self.health_metrics.stream_errors > 2 {
            health_issues += 1;
        }
        
        // Packet loss check
        if self.health_metrics.packet_loss_rate > 0.05 {
            health_issues += 2;
        } else if self.health_metrics.packet_loss_rate > 0.01 {
            health_issues += 1;
        }
        
        // Update health based on total issues
        match health_issues {
            0..=1 => {
                self.health = ConnectionHealth::Healthy;
                self.failed_health_checks = 0;
            }
            2..=3 => {
                self.health = ConnectionHealth::Degraded;
                self.failed_health_checks = (self.failed_health_checks + 1).min(thresholds.max_failed_checks);
            }
            _ => {
                self.health = ConnectionHealth::Unhealthy;
                self.failed_health_checks = thresholds.max_failed_checks;
            }
        }
    }
    
    pub fn record_stream_error(&mut self) {
        self.health_metrics.stream_errors += 1;
    }
    
    pub fn record_retransmission(&mut self) {
        self.health_metrics.retransmission_count += 1;
        // Estimate packet loss based on retransmissions
        let total_packets = (self.total_bytes_sent + self.total_bytes_received) / 1400; // Approximate packet size
        if total_packets > 0 {
            self.health_metrics.packet_loss_rate = self.health_metrics.retransmission_count as f64 / total_packets as f64;
        }
    }
    
    pub fn is_healthy(&self) -> bool {
        matches!(self.health, ConnectionHealth::Healthy)
    }
    
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
    
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }
    
    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_used)
    }
    
    /// Get comprehensive health report
    pub fn get_health_report(&self) -> ConnectionHealthReport {
        ConnectionHealthReport {
            peer_address: self.connection.remote_address(),
            health_status: self.health.clone(),
            current_rtt: self.connection.rtt(),
            average_rtt: self.health_metrics.avg_rtt,
            rtt_variance: self.health_metrics.rtt_variance,
            packet_loss_rate: self.health_metrics.packet_loss_rate,
            bandwidth_utilization: self.health_metrics.bandwidth_utilization,
            stability_score: self.health_metrics.stability_score,
            failed_health_checks: self.failed_health_checks,
            stream_errors: self.health_metrics.stream_errors,
            use_count: self.use_count,
            age: self.age(),
            idle_time: self.idle_time(),
        }
    }
}

/// Comprehensive health report for a connection
#[derive(Debug, Clone)]
pub struct ConnectionHealthReport {
    pub peer_address: SocketAddr,
    pub health_status: ConnectionHealth,
    pub current_rtt: Duration,
    pub average_rtt: Duration,
    pub rtt_variance: Duration,
    pub packet_loss_rate: f64,
    pub bandwidth_utilization: u64,
    pub stability_score: f64,
    pub failed_health_checks: u32,
    pub stream_errors: u32,
    pub use_count: u64,
    pub age: Duration,
    pub idle_time: Duration,
}

/// Aggregated health metrics for the entire connection pool
#[derive(Debug, Clone)]
pub struct PoolHealthMetrics {
    pub total_connections: usize,
    pub healthy_connections: usize,
    pub degraded_connections: usize,
    pub unhealthy_connections: usize,
    pub average_rtt: Duration,
    pub total_bandwidth_utilization: u64,
    pub total_stream_errors: u32,
    pub health_percentage: f64,
}

/// Connection pool manager with advanced features
pub struct ConnectionPoolManager {
    config: PoolConfig,
    pools: Arc<RwLock<HashMap<SocketAddr, Vec<PooledConnection>>>>,
    round_robin_counters: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    transport: Arc<QuicTransport>,
    health_checker_handle: Option<tokio::task::JoinHandle<()>>,
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionPoolManager {
    /// Create a new connection pool manager
    pub fn new(config: PoolConfig, transport: Arc<QuicTransport>) -> Self {
        Self {
            config,
            pools: Arc::new(RwLock::new(HashMap::new())),
            round_robin_counters: Arc::new(RwLock::new(HashMap::new())),
            transport,
            health_checker_handle: None,
            cleanup_handle: None,
        }
    }
    
    /// Start background tasks for health checking and cleanup
    pub async fn start(&mut self) -> Result<()> {
        // Start health checker
        let health_checker = self.start_health_checker().await;
        self.health_checker_handle = Some(health_checker);
        
        // Start cleanup task
        let cleanup_task = self.start_cleanup_task().await;
        self.cleanup_handle = Some(cleanup_task);
        
        info!("Connection pool manager started with config: max_per_peer={}, max_total={}, strategy={:?}", 
              self.config.max_connections_per_peer, 
              self.config.max_total_connections,
              self.config.load_balancing_strategy);
        
        Ok(())
    }
    
    /// Stop the connection pool manager
    pub async fn stop(&mut self) -> Result<()> {
        // Stop background tasks
        if let Some(handle) = self.health_checker_handle.take() {
            handle.abort();
        }
        
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
        
        // Close all connections
        let mut pools = self.pools.write().await;
        for (peer, connections) in pools.iter() {
            for conn in connections {
                conn.connection.close(0u32.into(), b"Pool shutdown");
            }
            debug!("Closed {} connections to peer {}", connections.len(), peer);
        }
        pools.clear();
        
        info!("Connection pool manager stopped");
        Ok(())
    }
    
    /// Get or create a connection to a peer using load balancing
    pub async fn get_connection(&self, peer: SocketAddr) -> Result<PooledConnection> {
        // Try to get an existing connection first using load balancing strategy
        if let Some(connection) = self.get_existing_connection_with_load_balancing(peer).await {
            return Ok(connection);
        }
        
        // Create a new connection if pool allows
        self.create_new_connection(peer).await
    }
    
    /// Get or create a connection using specific reuse strategy
    pub async fn get_connection_with_strategy(&self, peer: SocketAddr, strategy: ConnectionReuseStrategy) -> Result<PooledConnection> {
        if let Some(connection) = self.get_existing_connection_with_strategy(peer, strategy).await {
            return Ok(connection);
        }
        
        self.create_new_connection(peer).await
    }
    
    /// Get multiple connections for load distribution
    pub async fn get_connections_for_load_balancing(&self, peers: &[SocketAddr], count: usize) -> Result<Vec<(SocketAddr, PooledConnection)>> {
        let mut connections = Vec::new();
        
        match self.config.load_balancing_strategy {
            LoadBalancingStrategy::RoundRobin => {
                self.get_connections_round_robin(peers, count, &mut connections).await?;
            }
            LoadBalancingStrategy::LeastConnections => {
                self.get_connections_least_connections(peers, count, &mut connections).await?;
            }
            LoadBalancingStrategy::WeightedRoundRobin => {
                self.get_connections_weighted(peers, count, &mut connections).await?;
            }
            LoadBalancingStrategy::HealthBased => {
                self.get_connections_health_based(peers, count, &mut connections).await?;
            }
        }
        
        Ok(connections)
    }
    
    /// Get an existing connection using load balancing strategy
    async fn get_existing_connection_with_load_balancing(&self, peer: SocketAddr) -> Option<PooledConnection> {
        self.get_existing_connection_with_strategy(peer, self.config.reuse_strategy.clone()).await
    }
    
    /// Get an existing connection using a specific strategy
    async fn get_existing_connection_with_strategy(&self, peer: SocketAddr, strategy: ConnectionReuseStrategy) -> Option<PooledConnection> {
        let mut pools = self.pools.write().await;
        
        if let Some(connections) = pools.get_mut(&peer) {
            // Remove closed connections
            connections.retain(|conn| !conn.is_closed());
            
            if connections.is_empty() {
                return None;
            }
            
            // Select connection based on strategy
            let selected_index = self.select_connection_by_strategy(connections, &strategy);
            
            if let Some(index) = selected_index {
                if index < connections.len() {
                    let mut connection = connections[index].clone();
                    connection.mark_used(0, 0); // Will be updated when actually used
                    
                    debug!("Reusing connection to {} using strategy {:?} (use_count: {}, health: {:?})", 
                           peer, strategy, connection.use_count, connection.health);
                    
                    return Some(connection);
                }
            }
        }
        
        None
    }
    
    /// Select connection index based on reuse strategy
    fn select_connection_by_strategy(&self, connections: &[PooledConnection], strategy: &ConnectionReuseStrategy) -> Option<usize> {
        if connections.is_empty() {
            return None;
        }
        
        match strategy {
            ConnectionReuseStrategy::LeastUsed => {
                connections.iter()
                    .enumerate()
                    .filter(|(_, conn)| conn.is_healthy())
                    .min_by_key(|(_, conn)| conn.use_count)
                    .map(|(i, _)| i)
                    .or_else(|| Some(0)) // Fallback to first connection
            }
            ConnectionReuseStrategy::MostRecent => {
                connections.iter()
                    .enumerate()
                    .filter(|(_, conn)| conn.is_healthy())
                    .max_by_key(|(_, conn)| conn.last_used)
                    .map(|(i, _)| i)
                    .or_else(|| Some(0))
            }
            ConnectionReuseStrategy::HealthiestFirst => {
                // First try healthy connections with lowest failed checks
                connections.iter()
                    .enumerate()
                    .filter(|(_, conn)| matches!(conn.health, ConnectionHealth::Healthy))
                    .min_by_key(|(_, conn)| (conn.failed_health_checks, conn.connection.rtt()))
                    .map(|(i, _)| i)
                    .or_else(|| {
                        // Fallback to degraded connections
                        connections.iter()
                            .enumerate()
                            .filter(|(_, conn)| matches!(conn.health, ConnectionHealth::Degraded))
                            .min_by_key(|(_, conn)| conn.failed_health_checks)
                            .map(|(i, _)| i)
                    })
                    .or_else(|| Some(0))
            }
            ConnectionReuseStrategy::StickySession => {
                // For sticky sessions, prefer connections with lowest use count
                // In a real implementation, this would consider session affinity
                connections.iter()
                    .enumerate()
                    .filter(|(_, conn)| conn.is_healthy())
                    .min_by_key(|(_, conn)| conn.use_count)
                    .map(|(i, _)| i)
                    .or_else(|| Some(0))
            }
        }
    }
    
    /// Round-robin load balancing
    async fn get_connections_round_robin(&self, peers: &[SocketAddr], count: usize, connections: &mut Vec<(SocketAddr, PooledConnection)>) -> Result<()> {
        let mut rr_counters = self.round_robin_counters.write().await;
        
        for _ in 0..count {
            for peer in peers {
                if connections.len() >= count {
                    break;
                }
                
                let counter = rr_counters.entry(*peer).or_insert(0);
                *counter = (*counter + 1) % peers.len();
                
                if let Some(conn) = self.get_existing_connection(*peer).await {
                    connections.push((*peer, conn));
                } else if let Ok(conn) = self.create_new_connection(*peer).await {
                    connections.push((*peer, conn));
                }
            }
        }
        
        Ok(())
    }
    
    /// Least connections load balancing
    async fn get_connections_least_connections(&self, peers: &[SocketAddr], count: usize, connections: &mut Vec<(SocketAddr, PooledConnection)>) -> Result<()> {
        let pools = self.pools.read().await;
        
        // Create a sorted list of peers by connection count
        let mut peer_counts: Vec<(SocketAddr, usize)> = peers.iter()
            .map(|peer| {
                let conn_count = pools.get(peer).map(|v| v.len()).unwrap_or(0);
                (*peer, conn_count)
            })
            .collect();
        
        peer_counts.sort_by_key(|(_, count)| *count);
        drop(pools);
        
        // Get connections from peers with least connections first
        for _ in 0..count {
            for (peer, _) in &peer_counts {
                if connections.len() >= count {
                    break;
                }
                
                if let Some(conn) = self.get_existing_connection(*peer).await {
                    connections.push((*peer, conn));
                } else if let Ok(conn) = self.create_new_connection(*peer).await {
                    connections.push((*peer, conn));
                }
            }
        }
        
        Ok(())
    }
    
    /// Weighted round-robin load balancing
    async fn get_connections_weighted(&self, peers: &[SocketAddr], count: usize, connections: &mut Vec<(SocketAddr, PooledConnection)>) -> Result<()> {
        let pools = self.pools.read().await;
        
        // Calculate weights based on connection health and performance
        let mut peer_weights: Vec<(SocketAddr, f64)> = peers.iter()
            .map(|peer| {
                let weight = if let Some(conns) = pools.get(peer) {
                    let healthy_ratio = conns.iter().filter(|c| c.is_healthy()).count() as f64 / conns.len().max(1) as f64;
                    let avg_rtt = if !conns.is_empty() {
                        conns.iter().map(|c| c.connection.rtt().as_millis() as f64).sum::<f64>() / conns.len() as f64
                    } else {
                        100.0 // Default RTT
                    };
                    // Higher weight for healthier connections with lower RTT
                    healthy_ratio * (1000.0 / (avg_rtt + 1.0))
                } else {
                    1.0 // Default weight for new peers
                };
                (*peer, weight)
            })
            .collect();
        
        // Sort by weight (descending)
        peer_weights.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        drop(pools);
        
        // Distribute connections based on weights
        for _ in 0..count {
            for (peer, _) in &peer_weights {
                if connections.len() >= count {
                    break;
                }
                
                if let Some(conn) = self.get_existing_connection(*peer).await {
                    connections.push((*peer, conn));
                } else if let Ok(conn) = self.create_new_connection(*peer).await {
                    connections.push((*peer, conn));
                }
            }
        }
        
        Ok(())
    }
    
    /// Health-based load balancing
    async fn get_connections_health_based(&self, peers: &[SocketAddr], count: usize, connections: &mut Vec<(SocketAddr, PooledConnection)>) -> Result<()> {
        let pools = self.pools.read().await;
        
        // Sort peers by health score
        let mut peer_health: Vec<(SocketAddr, f64)> = peers.iter()
            .map(|peer| {
                let health_score = if let Some(conns) = pools.get(peer) {
                    if conns.is_empty() {
                        1.0 // New peers get good score
                    } else {
                        let healthy_count = conns.iter().filter(|c| matches!(c.health, ConnectionHealth::Healthy)).count();
                        let degraded_count = conns.iter().filter(|c| matches!(c.health, ConnectionHealth::Degraded)).count();
                        
                        // Health score: healthy=1.0, degraded=0.5, unhealthy=0.1
                        let total_score = healthy_count as f64 + (degraded_count as f64 * 0.5) + 
                                        ((conns.len() - healthy_count - degraded_count) as f64 * 0.1);
                        total_score / conns.len() as f64
                    }
                } else {
                    1.0 // Default for new peers
                };
                (*peer, health_score)
            })
            .collect();
        
        peer_health.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        drop(pools);
        
        // Get connections from healthiest peers first
        for _ in 0..count {
            for (peer, _) in &peer_health {
                if connections.len() >= count {
                    break;
                }
                
                if let Some(conn) = self.get_existing_connection(*peer).await {
                    connections.push((*peer, conn));
                } else if let Ok(conn) = self.create_new_connection(*peer).await {
                    connections.push((*peer, conn));
                }
            }
        }
        
        Ok(())
    }
    
    /// Get an existing connection from the pool
    async fn get_existing_connection(&self, peer: SocketAddr) -> Option<PooledConnection> {
        let mut pools = self.pools.write().await;
        
        if let Some(connections) = pools.get_mut(&peer) {
            // Remove closed connections
            connections.retain(|conn| !conn.is_closed());
            
            if connections.is_empty() {
                return None;
            }
            
            // Select connection based on strategy
            let selected_index = match self.config.reuse_strategy {
                ConnectionReuseStrategy::LeastUsed => {
                    connections.iter()
                        .enumerate()
                        .min_by_key(|(_, conn)| conn.use_count)
                        .map(|(i, _)| i)
                        .unwrap_or(0)
                }
                ConnectionReuseStrategy::MostRecent => {
                    connections.iter()
                        .enumerate()
                        .max_by_key(|(_, conn)| conn.last_used)
                        .map(|(i, _)| i)
                        .unwrap_or(0)
                }
                ConnectionReuseStrategy::HealthiestFirst => {
                    connections.iter()
                        .enumerate()
                        .filter(|(_, conn)| conn.is_healthy())
                        .min_by_key(|(_, conn)| conn.failed_health_checks)
                        .map(|(i, _)| i)
                        .unwrap_or(0)
                }
                ConnectionReuseStrategy::StickySession => {
                    // For sticky sessions, we'd need additional context
                    // For now, use least used as fallback
                    connections.iter()
                        .enumerate()
                        .min_by_key(|(_, conn)| conn.use_count)
                        .map(|(i, _)| i)
                        .unwrap_or(0)
                }
            };
            
            if selected_index < connections.len() {
                let mut connection = connections[selected_index].clone();
                connection.mark_used(0, 0); // Will be updated when actually used
                
                debug!("Reusing connection to {} (use_count: {}, health: {:?})", 
                       peer, connection.use_count, connection.health);
                
                return Some(connection);
            }
        }
        
        None
    }
    
    /// Create a new connection to a peer
    async fn create_new_connection(&self, peer: SocketAddr) -> Result<PooledConnection> {
        // Check if we can add more connections
        let pools = self.pools.read().await;
        let current_peer_count = pools.get(&peer).map(|v| v.len()).unwrap_or(0);
        let total_connections: usize = pools.values().map(|v| v.len()).sum();
        
        if current_peer_count >= self.config.max_connections_per_peer {
            return Err(anyhow::anyhow!("Maximum connections per peer ({}) reached for {}", 
                                     self.config.max_connections_per_peer, peer));
        }
        
        if total_connections >= self.config.max_total_connections {
            return Err(anyhow::anyhow!("Maximum total connections ({}) reached", 
                                     self.config.max_total_connections));
        }
        
        drop(pools); // Release read lock
        
        // Create new connection
        let connection = self.transport.connect(peer).await
            .context("Failed to create new connection")?;
        
        let pooled_connection = PooledConnection::new(connection);
        
        // Add to pool
        let mut pools = self.pools.write().await;
        pools.entry(peer)
            .or_insert_with(Vec::new)
            .push(pooled_connection.clone());
        
        info!("Created new connection to {} (pool size: {})", 
              peer, pools.get(&peer).unwrap().len());
        
        Ok(pooled_connection)
    }
    
    /// Return a connection to the pool after use
    pub async fn return_connection(&self, peer: SocketAddr, mut connection: PooledConnection, 
                                  bytes_sent: u64, bytes_received: u64) {
        connection.mark_used(bytes_sent, bytes_received);
        
        let mut pools = self.pools.write().await;
        if let Some(connections) = pools.get_mut(&peer) {
            // Find and update the connection in the pool
            for pool_conn in connections.iter_mut() {
                if pool_conn.connection.stable_id() == connection.connection.stable_id() {
                    *pool_conn = connection;
                    break;
                }
            }
        }
    }
    
    /// Get connection pool statistics
    pub async fn get_pool_stats(&self) -> HashMap<SocketAddr, PoolStats> {
        let pools = self.pools.read().await;
        let mut stats = HashMap::new();
        
        for (peer, connections) in pools.iter() {
            let healthy_count = connections.iter().filter(|c| c.is_healthy()).count();
            let degraded_count = connections.iter().filter(|c| matches!(c.health, ConnectionHealth::Degraded)).count();
            let unhealthy_count = connections.iter().filter(|c| matches!(c.health, ConnectionHealth::Unhealthy)).count();
            let total_use_count = connections.iter().map(|c| c.use_count).sum();
            let avg_rtt = if !connections.is_empty() {
                connections.iter().map(|c| c.connection.rtt()).sum::<Duration>() / connections.len() as u32
            } else {
                Duration::ZERO
            };
            
            stats.insert(*peer, PoolStats {
                total_connections: connections.len(),
                healthy_connections: healthy_count,
                degraded_connections: degraded_count,
                unhealthy_connections: unhealthy_count,
                total_use_count,
                average_rtt: avg_rtt,
            });
        }
        
        stats
    }
    
    /// Start health checker background task
    async fn start_health_checker(&self) -> tokio::task::JoinHandle<()> {
        let pools = self.pools.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(config.health_check_interval);
            
            loop {
                interval.tick().await;
                
                let mut pools = pools.write().await;
                let mut unhealthy_connections = Vec::new();
                
                for (peer, connections) in pools.iter_mut() {
                    for connection in connections.iter_mut() {
                        // Skip health check for new connections
                        if connection.age() < config.health_thresholds.min_connection_age {
                            continue;
                        }
                        
                        // Update comprehensive health metrics
                        connection.update_health_metrics(&config.health_thresholds);
                        
                        // Track unhealthy connections for reporting
                        if matches!(connection.health, ConnectionHealth::Unhealthy) {
                            unhealthy_connections.push((*peer, connection.get_health_report()));
                        }
                    }
                    
                    // Log detailed health status
                    let healthy = connections.iter().filter(|c| matches!(c.health, ConnectionHealth::Healthy)).count();
                    let degraded = connections.iter().filter(|c| matches!(c.health, ConnectionHealth::Degraded)).count();
                    let unhealthy = connections.iter().filter(|c| matches!(c.health, ConnectionHealth::Unhealthy)).count();
                    let total = connections.len();
                    
                    if degraded > 0 || unhealthy > 0 {
                        debug!("Health check for {}: {}/{} healthy, {} degraded, {} unhealthy", 
                               peer, healthy, total, degraded, unhealthy);
                        
                        // Log detailed metrics for degraded/unhealthy connections
                        for conn in connections.iter().filter(|c| !c.is_healthy()) {
                            let report = conn.get_health_report();
                            debug!("Unhealthy connection to {}: RTT={:?} (avg={:?}), loss={:.3}%, stability={:.2}, errors={}", 
                                   report.peer_address, 
                                   report.current_rtt, 
                                   report.average_rtt,
                                   report.packet_loss_rate * 100.0,
                                   report.stability_score,
                                   report.stream_errors);
                        }
                    }
                }
                
                // Report summary if there are issues
                if !unhealthy_connections.is_empty() {
                    info!("Health check completed: {} unhealthy connections detected", unhealthy_connections.len());
                }
            }
        })
    }
    
    /// Get detailed health reports for all connections
    pub async fn get_health_reports(&self) -> HashMap<SocketAddr, Vec<ConnectionHealthReport>> {
        let pools = self.pools.read().await;
        let mut reports = HashMap::new();
        
        for (peer, connections) in pools.iter() {
            let peer_reports: Vec<ConnectionHealthReport> = connections.iter()
                .map(|conn| conn.get_health_report())
                .collect();
            reports.insert(*peer, peer_reports);
        }
        
        reports
    }
    
    /// Get aggregated health metrics for the entire pool
    pub async fn get_aggregate_health_metrics(&self) -> PoolHealthMetrics {
        let pools = self.pools.read().await;
        
        let mut total_connections = 0;
        let mut healthy_connections = 0;
        let mut degraded_connections = 0;
        let mut unhealthy_connections = 0;
        let mut total_rtt_millis = 0u64;
        let mut total_bandwidth = 0u64;
        let mut total_stream_errors = 0u32;
        
        for connections in pools.values() {
            for conn in connections {
                total_connections += 1;
                
                match conn.health {
                    ConnectionHealth::Healthy => healthy_connections += 1,
                    ConnectionHealth::Degraded => degraded_connections += 1,
                    ConnectionHealth::Unhealthy => unhealthy_connections += 1,
                }
                
                total_rtt_millis += conn.connection.rtt().as_millis() as u64;
                total_bandwidth += conn.health_metrics.bandwidth_utilization;
                total_stream_errors += conn.health_metrics.stream_errors;
            }
        }
        
        let avg_rtt = if total_connections > 0 {
            Duration::from_millis(total_rtt_millis / total_connections as u64)
        } else {
            Duration::ZERO
        };
        
        PoolHealthMetrics {
            total_connections,
            healthy_connections,
            degraded_connections,
            unhealthy_connections,
            average_rtt: avg_rtt,
            total_bandwidth_utilization: total_bandwidth,
            total_stream_errors,
            health_percentage: if total_connections > 0 {
                (healthy_connections as f64 / total_connections as f64) * 100.0
            } else {
                100.0
            },
        }
    }
    
    /// Start cleanup task for removing stale connections
    async fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let pools = self.pools.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(config.idle_timeout / 3); // Check more frequently
            
            loop {
                interval.tick().await;
                
                let mut pools = pools.write().await;
                let mut cleanup_stats = CleanupStats::default();
                
                // Calculate total connections before cleanup
                let total_connections_before: usize = pools.values().map(|v| v.len()).sum();
                
                // Perform cleanup based on resource pressure
                let resource_pressure = Self::calculate_resource_pressure(total_connections_before, &config);
                
                for (peer, connections) in pools.iter_mut() {
                    let initial_count = connections.len();
                    
                    // Sort connections by cleanup priority (worst connections first)
                    connections.sort_by(|a, b| {
                        Self::cleanup_priority_score(a, &config)
                            .partial_cmp(&Self::cleanup_priority_score(b, &config))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    
                    // Apply different cleanup strategies based on resource pressure
                    let cleanup_threshold = match resource_pressure {
                        ResourcePressure::Low => Self::should_remove_connection_relaxed,
                        ResourcePressure::Medium => Self::should_remove_connection_standard,
                        ResourcePressure::High => Self::should_remove_connection_aggressive,
                    };
                    
                    // Remove connections based on cleanup strategy
                    connections.retain(|conn| {
                        let should_keep = !cleanup_threshold(conn, &config);
                        
                        if !should_keep {
                            conn.connection.close(0u32.into(), b"Connection cleanup");
                            
                            // Update cleanup statistics
                            match conn.health {
                                ConnectionHealth::Healthy => cleanup_stats.healthy_removed += 1,
                                ConnectionHealth::Degraded => cleanup_stats.degraded_removed += 1,
                                ConnectionHealth::Unhealthy => cleanup_stats.unhealthy_removed += 1,
                            }
                            
                            if conn.is_closed() {
                                cleanup_stats.closed_removed += 1;
                            }
                            if conn.idle_time() > config.idle_timeout {
                                cleanup_stats.idle_removed += 1;
                            }
                        }
                        
                        should_keep
                    });
                    
                    let removed = initial_count - connections.len();
                    cleanup_stats.total_removed += removed;
                    
                    if removed > 0 {
                        debug!("Cleaned up {} connections to {} (remaining: {}, pressure: {:?})", 
                               removed, peer, connections.len(), resource_pressure);
                    }
                }
                
                // Remove empty peer entries
                pools.retain(|_, connections| !connections.is_empty());
                
                let total_connections_after: usize = pools.values().map(|v| v.len()).sum();
                cleanup_stats.connections_before = total_connections_before;
                cleanup_stats.connections_after = total_connections_after;
                
                // Log cleanup summary
                if cleanup_stats.total_removed > 0 {
                    info!("Pool cleanup completed: {} connections removed ({}→{}), pressure: {:?}", 
                          cleanup_stats.total_removed, 
                          cleanup_stats.connections_before,
                          cleanup_stats.connections_after,
                          resource_pressure);
                    
                    debug!("Cleanup breakdown: {} unhealthy, {} degraded, {} idle, {} closed", 
                           cleanup_stats.unhealthy_removed,
                           cleanup_stats.degraded_removed, 
                           cleanup_stats.idle_removed,
                           cleanup_stats.closed_removed);
                }
                
                // Trigger connection pre-warming if pools are getting low
                if resource_pressure == ResourcePressure::Low && total_connections_after < config.max_total_connections / 2 {
                    // Connection warming could be implemented here
                    debug!("Pool capacity low, consider connection pre-warming");
                }
            }
        })
    }
    
    /// Calculate resource pressure based on current usage
    fn calculate_resource_pressure(total_connections: usize, config: &PoolConfig) -> ResourcePressure {
        let usage_ratio = total_connections as f64 / config.max_total_connections as f64;
        
        if usage_ratio > 0.9 {
            ResourcePressure::High
        } else if usage_ratio > 0.7 {
            ResourcePressure::Medium
        } else {
            ResourcePressure::Low
        }
    }
    
    /// Calculate cleanup priority score (lower = higher priority for removal)
    fn cleanup_priority_score(conn: &PooledConnection, config: &PoolConfig) -> f64 {
        let mut score = 1000.0; // Base score (higher = keep)
        
        // Health factor (unhealthy connections get removed first)
        match conn.health {
            ConnectionHealth::Healthy => score += 300.0,
            ConnectionHealth::Degraded => score += 100.0,
            ConnectionHealth::Unhealthy => score -= 500.0,
        }
        
        // Closed connections get removed immediately
        if conn.is_closed() {
            return -1000.0;
        }
        
        // Idle time factor
        let idle_ratio = conn.idle_time().as_secs_f64() / config.idle_timeout.as_secs_f64();
        score -= idle_ratio * 200.0;
        
        // Usage frequency factor (more used = higher priority to keep)
        score += (conn.use_count as f64).ln() * 50.0;
        
        // Age factor (very old connections get lower priority)
        let age_hours = conn.age().as_secs_f64() / 3600.0;
        if age_hours > 24.0 {
            score -= (age_hours - 24.0) * 10.0;
        }
        
        // Stability factor
        score += conn.health_metrics.stability_score * 100.0;
        
        // RTT factor (faster connections get higher priority)
        let rtt_penalty = conn.connection.rtt().as_millis() as f64 / 100.0;
        score -= rtt_penalty;
        
        score
    }
    
    /// Relaxed cleanup strategy (only remove obviously bad connections)
    fn should_remove_connection_relaxed(conn: &PooledConnection, config: &PoolConfig) -> bool {
        conn.is_closed() 
            || matches!(conn.health, ConnectionHealth::Unhealthy)
            || conn.idle_time() > config.idle_timeout * 2
    }
    
    /// Standard cleanup strategy
    fn should_remove_connection_standard(conn: &PooledConnection, config: &PoolConfig) -> bool {
        conn.is_closed() 
            || matches!(conn.health, ConnectionHealth::Unhealthy)
            || conn.idle_time() > config.idle_timeout
            || (matches!(conn.health, ConnectionHealth::Degraded) && conn.failed_health_checks >= config.health_thresholds.max_failed_checks / 2)
    }
    
    /// Aggressive cleanup strategy (remove more connections to free resources)
    fn should_remove_connection_aggressive(conn: &PooledConnection, config: &PoolConfig) -> bool {
        conn.is_closed() 
            || !matches!(conn.health, ConnectionHealth::Healthy)
            || conn.idle_time() > config.idle_timeout / 2
            || conn.use_count == 0 // Remove unused connections
            || conn.health_metrics.stability_score < 0.7
    }
    
    /// Pre-warm connections to frequently used peers
    pub async fn prewarm_connections(&self, peers: &[SocketAddr], connections_per_peer: usize) -> Result<usize> {
        let mut total_created = 0;
        
        for peer in peers {
            let current_count = {
                let pools = self.pools.read().await;
                pools.get(peer).map(|v| v.len()).unwrap_or(0)
            };
            
            let target_count = connections_per_peer.min(self.config.max_connections_per_peer);
            let needed = target_count.saturating_sub(current_count);
            
            for _ in 0..needed {
                match self.create_new_connection(*peer).await {
                    Ok(_) => {
                        total_created += 1;
                        debug!("Pre-warmed connection to {}", peer);
                    }
                    Err(e) => {
                        debug!("Failed to pre-warm connection to {}: {}", peer, e);
                        break; // Stop trying for this peer if we hit limits
                    }
                }
            }
        }
        
        if total_created > 0 {
            info!("Pre-warmed {} connections across {} peers", total_created, peers.len());
        }
        
        Ok(total_created)
    }
    
    /// Force cleanup of connections to free resources immediately
    pub async fn force_cleanup(&self, target_reduction: usize) -> usize {
        let mut pools = self.pools.write().await;
        let mut removed = 0;
        
        // Collect all connections with their cleanup scores
        let mut all_connections: Vec<(SocketAddr, usize, f64)> = Vec::new();
        
        for (peer, connections) in pools.iter() {
            for (idx, conn) in connections.iter().enumerate() {
                let score = Self::cleanup_priority_score(conn, &self.config);
                all_connections.push((*peer, idx, score));
            }
        }
        
        // Sort by cleanup priority (lowest scores first)
        all_connections.sort_by(|(_, _, a), (_, _, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        // Remove connections with lowest scores
        let to_remove = all_connections.into_iter().take(target_reduction);
        
        for (peer, _idx, _score) in to_remove {
            if let Some(connections) = pools.get_mut(&peer) {
                if let Some(conn) = connections.pop() {
                    conn.connection.close(0u32.into(), b"Force cleanup");
                    removed += 1;
                }
            }
        }
        
        // Remove empty peer entries
        pools.retain(|_, connections| !connections.is_empty());
        
        info!("Force cleanup removed {} connections", removed);
        removed
    }
    
    /// Get resource utilization metrics
    pub async fn get_resource_metrics(&self) -> ResourceMetrics {
        let pools = self.pools.read().await;
        
        let total_connections: usize = pools.values().map(|v| v.len()).sum();
        let total_peers = pools.len();
        
        let mut memory_usage_estimate = 0u64;
        let mut oldest_connection_age = Duration::ZERO;
        let mut total_idle_time = Duration::ZERO;
        
        for connections in pools.values() {
            for conn in connections {
                // Rough memory estimate per connection (connection state + buffers)
                memory_usage_estimate += 64 * 1024; // ~64KB per connection estimate
                
                let age = conn.age();
                if age > oldest_connection_age {
                    oldest_connection_age = age;
                }
                
                total_idle_time += conn.idle_time();
            }
        }
        
        let avg_idle_time = if total_connections > 0 {
            total_idle_time / total_connections as u32
        } else {
            Duration::ZERO
        };
        
        ResourceMetrics {
            total_connections,
            total_peers,
            memory_usage_estimate,
            pool_utilization: (total_connections as f64 / self.config.max_total_connections as f64) * 100.0,
            oldest_connection_age,
            average_idle_time: avg_idle_time,
            resource_pressure: Self::calculate_resource_pressure(total_connections, &self.config),
        }
    }
}

/// Resource pressure levels for adaptive cleanup
#[derive(Debug, Clone, PartialEq)]
pub enum ResourcePressure {
    Low,
    Medium,
    High,
}

/// Statistics collected during cleanup operations
#[derive(Debug, Default)]
struct CleanupStats {
    pub total_removed: usize,
    pub healthy_removed: usize,
    pub degraded_removed: usize,
    pub unhealthy_removed: usize,
    pub closed_removed: usize,
    pub idle_removed: usize,
    pub connections_before: usize,
    pub connections_after: usize,
}

/// Resource utilization metrics for the connection pool
#[derive(Debug, Clone)]
pub struct ResourceMetrics {
    pub total_connections: usize,
    pub total_peers: usize,
    pub memory_usage_estimate: u64,
    pub pool_utilization: f64,
    pub oldest_connection_age: Duration,
    pub average_idle_time: Duration,
    pub resource_pressure: ResourcePressure,
}

/// Statistics for a connection pool
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub healthy_connections: usize,
    pub degraded_connections: usize,
    pub unhealthy_connections: usize,
    pub total_use_count: u64,
    pub average_rtt: Duration,
}

impl Drop for ConnectionPoolManager {
    fn drop(&mut self) {
        // Clean shutdown of background tasks
        if let Some(handle) = self.health_checker_handle.take() {
            handle.abort();
        }
        
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_peer, 10);
        assert_eq!(config.max_total_connections, 100);
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
    }
    
    #[tokio::test]
    async fn test_health_thresholds() {
        let health_thresholds = HealthThresholds::default();
        assert_eq!(health_thresholds.max_rtt, Duration::from_millis(500));
        assert_eq!(health_thresholds.optimal_rtt, Duration::from_millis(100));
        assert_eq!(health_thresholds.max_failed_checks, 3);
        assert_eq!(health_thresholds.min_connection_age, Duration::from_secs(30));
    }
    
    #[tokio::test]
    async fn test_load_balancing_strategies() {
        let config = PoolConfig::default();
        assert!(matches!(config.load_balancing_strategy, LoadBalancingStrategy::RoundRobin));
        assert!(matches!(config.reuse_strategy, ConnectionReuseStrategy::LeastUsed));
    }
    
    // TODO: Add integration tests with mock connections
    // #[tokio::test]
    // async fn test_pooled_connection_creation() {
    //     // This test would require a mock Connection
    //     // For now, we'll test the basic structure
    // }
    
    // #[tokio::test]
    // async fn test_health_status_transitions() {
    //     // Test health transitions with mock connection
    // }
}