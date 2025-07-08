use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use tokio::sync::RwLock;

use crate::quic::QuicConfig;
use crate::ndn_quic::NdnQuicConfig;
use crate::ndn_optimizations::NdnOptimizationConfig;
use crate::ndn_forwarding::ForwardingConfig;

/// Performance tuning configuration for NDN-over-QUIC workloads
#[derive(Debug, Clone)]
pub struct NdnPerformanceConfig {
    /// Workload profile
    pub workload_profile: WorkloadProfile,
    /// QUIC transport tuning
    pub quic_tuning: QuicTuningConfig,
    /// NDN-specific tuning
    pub ndn_tuning: NdnTuningConfig,
    /// Memory management tuning
    pub memory_tuning: MemoryTuningConfig,
    /// Network tuning parameters
    pub network_tuning: NetworkTuningConfig,
    /// Monitoring and metrics configuration
    pub monitoring: MonitoringConfig,
}

/// Workload profile for optimizing transport behavior
#[derive(Debug, Clone, PartialEq)]
pub enum WorkloadProfile {
    /// High-frequency, small Interest/Data exchanges
    HighFrequencyLowLatency,
    /// Large content distribution (video, files)
    BulkDataTransfer,
    /// Mixed workload with varying packet sizes
    Mixed,
    /// IoT/sensor data with periodic small updates
    IoTSensorData,
    /// Real-time streaming applications
    RealTimeStreaming,
    /// Custom profile with specific parameters
    Custom(CustomWorkloadParams),
}

/// Custom workload parameters
#[derive(Debug, Clone)]
pub struct CustomWorkloadParams {
    /// Expected Interests per second
    pub interests_per_second: u32,
    /// Average Interest size in bytes
    pub avg_interest_size: usize,
    /// Average Data size in bytes
    pub avg_data_size: usize,
    /// Expected Interest/Data ratio
    pub interest_data_ratio: f64,
    /// Latency sensitivity (0.0 = not sensitive, 1.0 = very sensitive)
    pub latency_sensitivity: f64,
    /// Bandwidth requirement in Mbps
    pub bandwidth_requirement: f64,
}

impl PartialEq for CustomWorkloadParams {
    fn eq(&self, other: &Self) -> bool {
        self.interests_per_second == other.interests_per_second
            && self.avg_interest_size == other.avg_interest_size
            && self.avg_data_size == other.avg_data_size
            && (self.interest_data_ratio - other.interest_data_ratio).abs() < f64::EPSILON
            && (self.latency_sensitivity - other.latency_sensitivity).abs() < f64::EPSILON
            && (self.bandwidth_requirement - other.bandwidth_requirement).abs() < f64::EPSILON
    }
}

/// QUIC transport tuning configuration
#[derive(Debug, Clone)]
pub struct QuicTuningConfig {
    /// Maximum concurrent streams
    pub max_concurrent_streams: u32,
    /// Stream bandwidth limit per stream
    pub max_stream_bandwidth: u32,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Initial congestion window size
    pub initial_window_size: u32,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Enable 0-RTT connection establishment
    pub enable_0rtt: bool,
    /// Connection migration enabled
    pub enable_migration: bool,
}

/// NDN-specific tuning configuration
#[derive(Debug, Clone)]
pub struct NdnTuningConfig {
    /// Interest aggregation window
    pub aggregation_window: Duration,
    /// Maximum Interests to aggregate
    pub max_aggregation_count: usize,
    /// Content store size
    pub content_store_size: usize,
    /// Content freshness period
    pub content_freshness: Duration,
    /// Interest timeout
    pub interest_timeout: Duration,
    /// Maximum retransmissions
    pub max_retransmissions: u32,
    /// Enable packet fragmentation
    pub enable_fragmentation: bool,
    /// Fragment size for large packets
    pub fragment_size: usize,
}

/// Memory management tuning
#[derive(Debug, Clone)]
pub struct MemoryTuningConfig {
    /// Buffer pool size for packet processing
    pub buffer_pool_size: usize,
    /// Individual buffer size
    pub buffer_size: usize,
    /// Memory pressure thresholds
    pub memory_pressure_thresholds: MemoryPressureThresholds,
    /// Garbage collection configuration
    pub gc_config: GcConfig,
}

/// Memory pressure thresholds
#[derive(Debug, Clone)]
pub struct MemoryPressureThresholds {
    /// Low pressure threshold (fraction of total memory)
    pub low_pressure: f64,
    /// Medium pressure threshold
    pub medium_pressure: f64,
    /// High pressure threshold
    pub high_pressure: f64,
}

/// Garbage collection configuration
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// Enable aggressive cleanup under memory pressure
    pub aggressive_cleanup: bool,
    /// Cleanup interval under normal conditions
    pub normal_cleanup_interval: Duration,
    /// Cleanup interval under memory pressure
    pub pressure_cleanup_interval: Duration,
}

/// Network tuning parameters
#[derive(Debug, Clone)]
pub struct NetworkTuningConfig {
    /// Socket buffer sizes
    pub socket_buffer_size: usize,
    /// Enable TCP_NODELAY equivalent for QUIC
    pub low_latency_mode: bool,
    /// Bandwidth delay product estimation
    pub bdp_estimation: bool,
    /// Congestion control algorithm preference
    pub congestion_control: CongestionControlAlgorithm,
    /// Path MTU discovery
    pub pmtu_discovery: bool,
}

/// Congestion control algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum CongestionControlAlgorithm {
    /// BBR (Bottleneck Bandwidth and RTT)
    BBR,
    /// CUBIC
    CUBIC,
    /// NewReno
    NewReno,
    /// Custom algorithm
    Custom(String),
}

/// Monitoring and metrics configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Enable detailed performance metrics
    pub enable_metrics: bool,
    /// Metrics collection interval
    pub metrics_interval: Duration,
    /// Enable RTT measurement
    pub enable_rtt_measurement: bool,
    /// Enable throughput measurement
    pub enable_throughput_measurement: bool,
    /// Enable packet loss tracking
    pub enable_packet_loss_tracking: bool,
    /// Metrics export configuration
    pub metrics_export: MetricsExportConfig,
}

/// Metrics export configuration
#[derive(Debug, Clone)]
pub struct MetricsExportConfig {
    /// Enable metrics export
    pub enabled: bool,
    /// Export format
    pub format: MetricsFormat,
    /// Export interval
    pub export_interval: Duration,
    /// Export destination
    pub destination: MetricsDestination,
}

/// Metrics export formats
#[derive(Debug, Clone, PartialEq)]
pub enum MetricsFormat {
    JSON,
    Prometheus,
    InfluxDB,
    Custom(String),
}

/// Metrics export destinations
#[derive(Debug, Clone)]
pub enum MetricsDestination {
    File(String),
    Http(String),
    UDP(SocketAddr),
    Custom(String),
}

impl Default for NdnPerformanceConfig {
    fn default() -> Self {
        Self::for_workload_profile(WorkloadProfile::Mixed)
    }
}

impl NdnPerformanceConfig {
    /// Create performance configuration for a specific workload profile
    pub fn for_workload_profile(profile: WorkloadProfile) -> Self {
        match profile {
            WorkloadProfile::HighFrequencyLowLatency => Self::high_frequency_low_latency(),
            WorkloadProfile::BulkDataTransfer => Self::bulk_data_transfer(),
            WorkloadProfile::Mixed => Self::mixed_workload(),
            WorkloadProfile::IoTSensorData => Self::iot_sensor_data(),
            WorkloadProfile::RealTimeStreaming => Self::real_time_streaming(),
            WorkloadProfile::Custom(params) => Self::custom_workload(params),
        }
    }
    
    /// High-frequency, low-latency configuration
    fn high_frequency_low_latency() -> Self {
        Self {
            workload_profile: WorkloadProfile::HighFrequencyLowLatency,
            quic_tuning: QuicTuningConfig {
                max_concurrent_streams: 1000,
                max_stream_bandwidth: 10 * 1024 * 1024, // 10 MB/s per stream
                idle_timeout: Duration::from_secs(5),
                keep_alive_interval: Duration::from_millis(500),
                initial_window_size: 32768,
                max_datagram_size: 1200,
                enable_0rtt: true,
                enable_migration: true,
            },
            ndn_tuning: NdnTuningConfig {
                aggregation_window: Duration::from_millis(1), // Very short aggregation
                max_aggregation_count: 5,
                content_store_size: 10000,
                content_freshness: Duration::from_secs(60),
                interest_timeout: Duration::from_millis(100), // Fast timeout
                max_retransmissions: 2,
                enable_fragmentation: false, // Avoid fragmentation overhead
                fragment_size: 1400,
            },
            memory_tuning: MemoryTuningConfig {
                buffer_pool_size: 1000,
                buffer_size: 2048,
                memory_pressure_thresholds: MemoryPressureThresholds {
                    low_pressure: 0.6,
                    medium_pressure: 0.8,
                    high_pressure: 0.95,
                },
                gc_config: GcConfig {
                    aggressive_cleanup: true,
                    normal_cleanup_interval: Duration::from_secs(1),
                    pressure_cleanup_interval: Duration::from_millis(100),
                },
            },
            network_tuning: NetworkTuningConfig {
                socket_buffer_size: 64 * 1024,
                low_latency_mode: true,
                bdp_estimation: true,
                congestion_control: CongestionControlAlgorithm::BBR,
                pmtu_discovery: true,
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_millis(100),
                enable_rtt_measurement: true,
                enable_throughput_measurement: true,
                enable_packet_loss_tracking: true,
                metrics_export: MetricsExportConfig {
                    enabled: false,
                    format: MetricsFormat::JSON,
                    export_interval: Duration::from_secs(5),
                    destination: MetricsDestination::File("/tmp/ndn_metrics.json".to_string()),
                },
            },
        }
    }
    
    /// Bulk data transfer configuration
    fn bulk_data_transfer() -> Self {
        Self {
            workload_profile: WorkloadProfile::BulkDataTransfer,
            quic_tuning: QuicTuningConfig {
                max_concurrent_streams: 100,
                max_stream_bandwidth: 100 * 1024 * 1024, // 100 MB/s per stream
                idle_timeout: Duration::from_secs(30),
                keep_alive_interval: Duration::from_secs(5),
                initial_window_size: 65536,
                max_datagram_size: 1400,
                enable_0rtt: false, // Prioritize reliability
                enable_migration: false,
            },
            ndn_tuning: NdnTuningConfig {
                aggregation_window: Duration::from_millis(50), // Longer aggregation
                max_aggregation_count: 20,
                content_store_size: 1000, // Smaller cache for large content
                content_freshness: Duration::from_secs(3600), // 1 hour
                interest_timeout: Duration::from_secs(10), // Longer timeout
                max_retransmissions: 5,
                enable_fragmentation: true,
                fragment_size: 8192, // Larger fragments
            },
            memory_tuning: MemoryTuningConfig {
                buffer_pool_size: 500,
                buffer_size: 64 * 1024, // Larger buffers
                memory_pressure_thresholds: MemoryPressureThresholds {
                    low_pressure: 0.5,
                    medium_pressure: 0.7,
                    high_pressure: 0.9,
                },
                gc_config: GcConfig {
                    aggressive_cleanup: false,
                    normal_cleanup_interval: Duration::from_secs(10),
                    pressure_cleanup_interval: Duration::from_secs(1),
                },
            },
            network_tuning: NetworkTuningConfig {
                socket_buffer_size: 1024 * 1024, // 1MB buffers
                low_latency_mode: false,
                bdp_estimation: true,
                congestion_control: CongestionControlAlgorithm::CUBIC,
                pmtu_discovery: true,
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_secs(1),
                enable_rtt_measurement: true,
                enable_throughput_measurement: true,
                enable_packet_loss_tracking: true,
                metrics_export: MetricsExportConfig {
                    enabled: true,
                    format: MetricsFormat::Prometheus,
                    export_interval: Duration::from_secs(30),
                    destination: MetricsDestination::Http("http://localhost:9090/metrics".to_string()),
                },
            },
        }
    }
    
    /// Mixed workload configuration (balanced)
    fn mixed_workload() -> Self {
        Self {
            workload_profile: WorkloadProfile::Mixed,
            quic_tuning: QuicTuningConfig {
                max_concurrent_streams: 200,
                max_stream_bandwidth: 50 * 1024 * 1024, // 50 MB/s per stream
                idle_timeout: Duration::from_secs(15),
                keep_alive_interval: Duration::from_secs(2),
                initial_window_size: 32768,
                max_datagram_size: 1400,
                enable_0rtt: true,
                enable_migration: true,
            },
            ndn_tuning: NdnTuningConfig {
                aggregation_window: Duration::from_millis(10),
                max_aggregation_count: 10,
                content_store_size: 5000,
                content_freshness: Duration::from_secs(300), // 5 minutes
                interest_timeout: Duration::from_secs(2),
                max_retransmissions: 3,
                enable_fragmentation: true,
                fragment_size: 4096,
            },
            memory_tuning: MemoryTuningConfig {
                buffer_pool_size: 750,
                buffer_size: 8192,
                memory_pressure_thresholds: MemoryPressureThresholds {
                    low_pressure: 0.6,
                    medium_pressure: 0.8,
                    high_pressure: 0.95,
                },
                gc_config: GcConfig {
                    aggressive_cleanup: false,
                    normal_cleanup_interval: Duration::from_secs(5),
                    pressure_cleanup_interval: Duration::from_millis(500),
                },
            },
            network_tuning: NetworkTuningConfig {
                socket_buffer_size: 256 * 1024,
                low_latency_mode: false,
                bdp_estimation: true,
                congestion_control: CongestionControlAlgorithm::BBR,
                pmtu_discovery: true,
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_millis(500),
                enable_rtt_measurement: true,
                enable_throughput_measurement: true,
                enable_packet_loss_tracking: true,
                metrics_export: MetricsExportConfig {
                    enabled: false,
                    format: MetricsFormat::JSON,
                    export_interval: Duration::from_secs(10),
                    destination: MetricsDestination::File("/tmp/ndn_metrics.json".to_string()),
                },
            },
        }
    }
    
    /// IoT sensor data configuration
    fn iot_sensor_data() -> Self {
        Self {
            workload_profile: WorkloadProfile::IoTSensorData,
            quic_tuning: QuicTuningConfig {
                max_concurrent_streams: 50,
                max_stream_bandwidth: 1024 * 1024, // 1 MB/s per stream
                idle_timeout: Duration::from_secs(60), // Longer idle for infrequent updates
                keep_alive_interval: Duration::from_secs(30),
                initial_window_size: 16384,
                max_datagram_size: 512, // Small packets
                enable_0rtt: true,
                enable_migration: true, // Good for mobile IoT devices
            },
            ndn_tuning: NdnTuningConfig {
                aggregation_window: Duration::from_millis(100), // Longer aggregation for efficiency
                max_aggregation_count: 50,
                content_store_size: 1000,
                content_freshness: Duration::from_secs(30), // Short freshness for sensor data
                interest_timeout: Duration::from_secs(5),
                max_retransmissions: 3,
                enable_fragmentation: false, // Small packets don't need fragmentation
                fragment_size: 1400,
            },
            memory_tuning: MemoryTuningConfig {
                buffer_pool_size: 200,
                buffer_size: 1024, // Small buffers
                memory_pressure_thresholds: MemoryPressureThresholds {
                    low_pressure: 0.7,
                    medium_pressure: 0.85,
                    high_pressure: 0.95,
                },
                gc_config: GcConfig {
                    aggressive_cleanup: true, // Important for resource-constrained devices
                    normal_cleanup_interval: Duration::from_secs(30),
                    pressure_cleanup_interval: Duration::from_secs(5),
                },
            },
            network_tuning: NetworkTuningConfig {
                socket_buffer_size: 32 * 1024,
                low_latency_mode: false,
                bdp_estimation: false, // Not critical for low-bandwidth IoT
                congestion_control: CongestionControlAlgorithm::NewReno, // Simple and reliable
                pmtu_discovery: false,
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_secs(10), // Less frequent monitoring
                enable_rtt_measurement: false,
                enable_throughput_measurement: true,
                enable_packet_loss_tracking: true,
                metrics_export: MetricsExportConfig {
                    enabled: false,
                    format: MetricsFormat::JSON,
                    export_interval: Duration::from_secs(60),
                    destination: MetricsDestination::File("/tmp/iot_metrics.json".to_string()),
                },
            },
        }
    }
    
    /// Real-time streaming configuration
    fn real_time_streaming() -> Self {
        Self {
            workload_profile: WorkloadProfile::RealTimeStreaming,
            quic_tuning: QuicTuningConfig {
                max_concurrent_streams: 20, // Few high-bandwidth streams
                max_stream_bandwidth: 500 * 1024 * 1024, // 500 MB/s per stream
                idle_timeout: Duration::from_secs(5),
                keep_alive_interval: Duration::from_millis(100), // Frequent keep-alives
                initial_window_size: 131072, // Large initial window
                max_datagram_size: 1400,
                enable_0rtt: true,
                enable_migration: false, // Stability over mobility
            },
            ndn_tuning: NdnTuningConfig {
                aggregation_window: Duration::from_millis(1), // Minimal aggregation
                max_aggregation_count: 2,
                content_store_size: 100, // Small cache to avoid stale content
                content_freshness: Duration::from_secs(1), // Very fresh content
                interest_timeout: Duration::from_millis(50), // Very fast timeout
                max_retransmissions: 1, // Minimal retransmissions
                enable_fragmentation: true,
                fragment_size: 1400, // MTU-sized fragments
            },
            memory_tuning: MemoryTuningConfig {
                buffer_pool_size: 100,
                buffer_size: 128 * 1024, // Large buffers for streaming
                memory_pressure_thresholds: MemoryPressureThresholds {
                    low_pressure: 0.5,
                    medium_pressure: 0.7,
                    high_pressure: 0.9,
                },
                gc_config: GcConfig {
                    aggressive_cleanup: true, // Prioritize real-time performance
                    normal_cleanup_interval: Duration::from_millis(500),
                    pressure_cleanup_interval: Duration::from_millis(50),
                },
            },
            network_tuning: NetworkTuningConfig {
                socket_buffer_size: 2 * 1024 * 1024, // 2MB buffers
                low_latency_mode: true,
                bdp_estimation: true,
                congestion_control: CongestionControlAlgorithm::BBR, // Best for high-bandwidth
                pmtu_discovery: true,
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_millis(10), // High-frequency monitoring
                enable_rtt_measurement: true,
                enable_throughput_measurement: true,
                enable_packet_loss_tracking: true,
                metrics_export: MetricsExportConfig {
                    enabled: true,
                    format: MetricsFormat::InfluxDB,
                    export_interval: Duration::from_millis(100),
                    destination: MetricsDestination::Http("http://localhost:8086/write".to_string()),
                },
            },
        }
    }
    
    /// Custom workload configuration
    fn custom_workload(params: CustomWorkloadParams) -> Self {
        // Base configuration on closest standard profile
        let base_profile = if params.latency_sensitivity > 0.8 {
            WorkloadProfile::HighFrequencyLowLatency
        } else if params.avg_data_size > 64 * 1024 {
            WorkloadProfile::BulkDataTransfer
        } else if params.bandwidth_requirement < 1.0 {
            WorkloadProfile::IoTSensorData
        } else {
            WorkloadProfile::Mixed
        };
        
        let mut config = Self::for_workload_profile(base_profile);
        config.workload_profile = WorkloadProfile::Custom(params.clone());
        
        // Adjust configuration based on custom parameters
        config.quic_tuning.max_concurrent_streams = (params.interests_per_second / 10).max(10).min(1000);
        config.ndn_tuning.content_store_size = (params.interests_per_second as usize * 10).max(100).min(50000);
        
        if params.latency_sensitivity > 0.5 {
            config.ndn_tuning.aggregation_window = Duration::from_millis(1);
            config.ndn_tuning.interest_timeout = Duration::from_millis(100);
        }
        
        config
    }
    
    /// Convert to QUIC configuration
    pub fn to_quic_config(&self) -> QuicConfig {
        QuicConfig {
            max_idle_timeout: self.quic_tuning.idle_timeout,
            max_concurrent_streams: self.quic_tuning.max_concurrent_streams,
            max_stream_bandwidth: self.quic_tuning.max_stream_bandwidth,
            keep_alive_interval: self.quic_tuning.keep_alive_interval,
            tls_config: crate::quic::TlsSecurityConfig::default(), // Use default TLS config
        }
    }
    
    /// Convert to NDN QUIC configuration
    pub fn to_ndn_quic_config(&self) -> NdnQuicConfig {
        NdnQuicConfig {
            max_interest_lifetime: self.ndn_tuning.interest_timeout.as_millis() as u64,
            max_data_freshness: self.ndn_tuning.content_freshness.as_millis() as u64,
            interest_aggregation: self.ndn_tuning.aggregation_window > Duration::from_millis(0),
            content_store: self.ndn_tuning.content_store_size > 0,
            max_packet_size: if self.ndn_tuning.enable_fragmentation {
                self.ndn_tuning.fragment_size
            } else {
                64 * 1024
            },
            compression: false, // Can be added based on workload
            interest_timeout: self.ndn_tuning.interest_timeout,
            max_retransmissions: self.ndn_tuning.max_retransmissions,
            backoff_multiplier: 2.0,
            max_backoff: std::time::Duration::from_secs(10),
            adaptive_timeout: true,
            cleanup_interval: std::time::Duration::from_millis(500),
            rtt_timeout_weight: 0.3,
            proactive_timeout_management: true,
            min_timeout: std::time::Duration::from_millis(100),
            enable_stream_multiplexing: true,
            stream_multiplexer_config: crate::stream_multiplexer::StreamMultiplexerConfig::default(),
        }
    }
    
    /// Convert to NDN optimization configuration
    pub fn to_ndn_optimization_config(&self) -> NdnOptimizationConfig {
        NdnOptimizationConfig {
            enable_aggregation: self.ndn_tuning.aggregation_window > Duration::from_millis(0),
            aggregation_window: self.ndn_tuning.aggregation_window,
            max_aggregation_count: self.ndn_tuning.max_aggregation_count,
            enable_content_store: self.ndn_tuning.content_store_size > 0,
            max_cache_size: self.ndn_tuning.content_store_size,
            max_cache_freshness: self.ndn_tuning.content_freshness,
            enable_flow_optimization: true, // Always enable for performance
            max_concurrent_streams: self.quic_tuning.max_concurrent_streams as u64,
        }
    }
    
    /// Convert to forwarding configuration
    pub fn to_forwarding_config(&self) -> ForwardingConfig {
        ForwardingConfig {
            enable_loop_detection: true, // Always enable for correctness
            enable_pit_aggregation: self.ndn_tuning.aggregation_window > Duration::from_millis(0),
            enable_content_store: self.ndn_tuning.content_store_size > 0,
            max_interest_lifetime: self.ndn_tuning.interest_timeout,
            enable_metrics: self.monitoring.enable_metrics,
            cleanup_interval: self.memory_tuning.gc_config.normal_cleanup_interval,
        }
    }
}

/// Performance monitoring and metrics collector
#[derive(Debug)]
pub struct NdnPerformanceMonitor {
    /// Configuration
    config: MonitoringConfig,
    /// Performance metrics
    metrics: Arc<RwLock<PerformanceMetrics>>,
    /// Start time for monitoring
    start_time: Instant,
}

/// Performance metrics data
#[derive(Debug, Default, Clone)]
pub struct PerformanceMetrics {
    /// Total Interests processed
    pub total_interests: u64,
    /// Total Data packets processed
    pub total_data: u64,
    /// Average Interest processing time
    pub avg_interest_time: Duration,
    /// Average Data processing time
    pub avg_data_time: Duration,
    /// Current throughput (packets per second)
    pub current_throughput: f64,
    /// Peak throughput
    pub peak_throughput: f64,
    /// Average round-trip time
    pub avg_rtt: Duration,
    /// Packet loss rate
    pub packet_loss_rate: f64,
    /// Memory usage statistics
    pub memory_usage: MemoryUsageStats,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Interest aggregation ratio
    pub aggregation_ratio: f64,
}

/// Memory usage statistics
#[derive(Debug, Default, Clone)]
pub struct MemoryUsageStats {
    /// Total allocated memory in bytes
    pub total_allocated: usize,
    /// Currently used memory in bytes
    pub used_memory: usize,
    /// Peak memory usage
    pub peak_memory: usize,
    /// Number of garbage collections performed
    pub gc_count: u64,
}

impl NdnPerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: MonitoringConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            start_time: Instant::now(),
        }
    }
    
    /// Record Interest processing
    pub async fn record_interest_processing(&self, processing_time: Duration) {
        if !self.config.enable_metrics {
            return;
        }
        
        let mut metrics = self.metrics.write().await;
        metrics.total_interests += 1;
        
        // Update average processing time using exponential moving average
        let alpha = 0.1;
        let old_avg = metrics.avg_interest_time.as_nanos() as f64;
        let new_time = processing_time.as_nanos() as f64;
        let new_avg = old_avg * (1.0 - alpha) + new_time * alpha;
        metrics.avg_interest_time = Duration::from_nanos(new_avg as u64);
    }
    
    /// Record Data processing
    pub async fn record_data_processing(&self, processing_time: Duration) {
        if !self.config.enable_metrics {
            return;
        }
        
        let mut metrics = self.metrics.write().await;
        metrics.total_data += 1;
        
        // Update average processing time
        let alpha = 0.1;
        let old_avg = metrics.avg_data_time.as_nanos() as f64;
        let new_time = processing_time.as_nanos() as f64;
        let new_avg = old_avg * (1.0 - alpha) + new_time * alpha;
        metrics.avg_data_time = Duration::from_nanos(new_avg as u64);
    }
    
    /// Update throughput measurement
    pub async fn update_throughput(&self, packets_in_interval: u64, interval: Duration) {
        if !self.config.enable_throughput_measurement {
            return;
        }
        
        let mut metrics = self.metrics.write().await;
        let throughput = packets_in_interval as f64 / interval.as_secs_f64();
        metrics.current_throughput = throughput;
        metrics.peak_throughput = metrics.peak_throughput.max(throughput);
    }
    
    /// Update RTT measurement
    pub async fn update_rtt(&self, rtt: Duration) {
        if !self.config.enable_rtt_measurement {
            return;
        }
        
        let mut metrics = self.metrics.write().await;
        
        // Update average RTT using exponential moving average
        let alpha = 0.1;
        let old_avg = metrics.avg_rtt.as_nanos() as f64;
        let new_rtt = rtt.as_nanos() as f64;
        let new_avg = old_avg * (1.0 - alpha) + new_rtt * alpha;
        metrics.avg_rtt = Duration::from_nanos(new_avg as u64);
    }
    
    /// Update packet loss rate
    pub async fn update_packet_loss(&self, lost_packets: u64, total_packets: u64) {
        if !self.config.enable_packet_loss_tracking {
            return;
        }
        
        let mut metrics = self.metrics.write().await;
        if total_packets > 0 {
            metrics.packet_loss_rate = lost_packets as f64 / total_packets as f64;
        }
    }
    
    /// Update cache statistics
    pub async fn update_cache_stats(&self, hits: u64, total_lookups: u64) {
        let mut metrics = self.metrics.write().await;
        if total_lookups > 0 {
            metrics.cache_hit_ratio = hits as f64 / total_lookups as f64;
        }
    }
    
    /// Update Interest aggregation statistics
    pub async fn update_aggregation_stats(&self, aggregated: u64, total: u64) {
        let mut metrics = self.metrics.write().await;
        if total > 0 {
            metrics.aggregation_ratio = aggregated as f64 / total as f64;
        }
    }
    
    /// Get current performance metrics
    pub async fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Generate performance report
    pub async fn generate_report(&self) -> String {
        let metrics = self.get_metrics().await;
        let uptime = self.start_time.elapsed();
        
        format!(
            "NDN-over-QUIC Performance Report\n\
             ================================\n\
             Uptime: {:.2?}\n\
             Total Interests: {}\n\
             Total Data: {}\n\
             Avg Interest Processing: {:.2?}\n\
             Avg Data Processing: {:.2?}\n\
             Current Throughput: {:.2} pps\n\
             Peak Throughput: {:.2} pps\n\
             Average RTT: {:.2?}\n\
             Packet Loss Rate: {:.2}%\n\
             Cache Hit Ratio: {:.2}%\n\
             Interest Aggregation Ratio: {:.2}%\n\
             Memory Usage: {} / {} bytes\n\
             Peak Memory: {} bytes\n\
             GC Count: {}",
            uptime,
            metrics.total_interests,
            metrics.total_data,
            metrics.avg_interest_time,
            metrics.avg_data_time,
            metrics.current_throughput,
            metrics.peak_throughput,
            metrics.avg_rtt,
            metrics.packet_loss_rate * 100.0,
            metrics.cache_hit_ratio * 100.0,
            metrics.aggregation_ratio * 100.0,
            metrics.memory_usage.used_memory,
            metrics.memory_usage.total_allocated,
            metrics.memory_usage.peak_memory,
            metrics.memory_usage.gc_count
        )
    }
}

/// Utility functions for performance tuning
pub mod utils {
    use super::*;
    
    /// Estimate optimal configuration based on system resources
    pub fn estimate_optimal_config() -> NdnPerformanceConfig {
        // This is a simplified estimation - in practice, you'd probe system resources
        let available_memory = 1024 * 1024 * 1024; // 1GB assumption
        let cpu_cores = 4; // 4 cores assumption
        
        let profile = if available_memory > 2_147_483_648u64 {
            // High-memory system
            WorkloadProfile::BulkDataTransfer
        } else if cpu_cores > 8 {
            // High-CPU system
            WorkloadProfile::HighFrequencyLowLatency
        } else {
            WorkloadProfile::Mixed
        };
        
        NdnPerformanceConfig::for_workload_profile(profile)
    }
    
    /// Benchmark different configurations
    pub async fn benchmark_configurations(
        configs: Vec<NdnPerformanceConfig>,
        _test_duration: Duration,
    ) -> Result<Vec<(NdnPerformanceConfig, PerformanceMetrics)>> {
        // This would run actual benchmarks - simplified for now
        let mut results = Vec::new();
        
        for config in configs {
            // Create a mock performance result
            let metrics = PerformanceMetrics {
                total_interests: 1000,
                total_data: 900,
                avg_interest_time: Duration::from_micros(100),
                avg_data_time: Duration::from_micros(150),
                current_throughput: 500.0,
                peak_throughput: 800.0,
                avg_rtt: Duration::from_millis(50),
                packet_loss_rate: 0.01,
                memory_usage: MemoryUsageStats {
                    total_allocated: 64 * 1024 * 1024,
                    used_memory: 32 * 1024 * 1024,
                    peak_memory: 48 * 1024 * 1024,
                    gc_count: 10,
                },
                cache_hit_ratio: 0.75,
                aggregation_ratio: 0.3,
            };
            
            results.push((config, metrics));
        }
        
        Ok(results)
    }
    
    /// Auto-tune configuration based on observed performance
    pub fn auto_tune_config(
        current_config: NdnPerformanceConfig,
        metrics: &PerformanceMetrics,
    ) -> NdnPerformanceConfig {
        let mut tuned_config = current_config;
        
        // Adjust based on performance metrics
        if metrics.packet_loss_rate > 0.05 {
            // High packet loss - increase timeouts and retransmissions
            tuned_config.ndn_tuning.interest_timeout *= 2;
            tuned_config.ndn_tuning.max_retransmissions += 1;
        }
        
        if metrics.cache_hit_ratio < 0.3 {
            // Low cache hit ratio - increase cache size
            tuned_config.ndn_tuning.content_store_size *= 2;
        }
        
        if metrics.aggregation_ratio > 0.8 {
            // High aggregation - might be able to increase aggregation window
            tuned_config.ndn_tuning.aggregation_window = 
                (tuned_config.ndn_tuning.aggregation_window * 2).min(Duration::from_millis(100));
        }
        
        tuned_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_workload_profile_configs() {
        let low_latency_config = NdnPerformanceConfig::for_workload_profile(
            WorkloadProfile::HighFrequencyLowLatency
        );
        assert!(low_latency_config.ndn_tuning.interest_timeout < Duration::from_secs(1));
        assert!(low_latency_config.quic_tuning.enable_0rtt);
        
        let bulk_transfer_config = NdnPerformanceConfig::for_workload_profile(
            WorkloadProfile::BulkDataTransfer
        );
        assert!(bulk_transfer_config.ndn_tuning.enable_fragmentation);
        assert!(bulk_transfer_config.memory_tuning.buffer_size > 8192);
        
        let iot_config = NdnPerformanceConfig::for_workload_profile(
            WorkloadProfile::IoTSensorData
        );
        assert!(iot_config.quic_tuning.idle_timeout > Duration::from_secs(30));
        assert!(iot_config.memory_tuning.buffer_size < 2048);
    }
    
    #[test]
    fn test_config_conversion() {
        let perf_config = NdnPerformanceConfig::default();
        
        let quic_config = perf_config.to_quic_config();
        assert_eq!(quic_config.max_concurrent_streams, perf_config.quic_tuning.max_concurrent_streams);
        
        let ndn_config = perf_config.to_ndn_quic_config();
        assert_eq!(ndn_config.interest_timeout, perf_config.ndn_tuning.interest_timeout);
        
        let optimization_config = perf_config.to_ndn_optimization_config();
        assert_eq!(optimization_config.max_cache_size, perf_config.ndn_tuning.content_store_size);
    }
    
    #[tokio::test]
    async fn test_performance_monitor() {
        let monitor_config = MonitoringConfig {
            enable_metrics: true,
            metrics_interval: Duration::from_millis(100),
            enable_rtt_measurement: true,
            enable_throughput_measurement: true,
            enable_packet_loss_tracking: true,
            metrics_export: MetricsExportConfig {
                enabled: false,
                format: MetricsFormat::JSON,
                export_interval: Duration::from_secs(1),
                destination: MetricsDestination::File("/tmp/test.json".to_string()),
            },
        };
        
        let monitor = NdnPerformanceMonitor::new(monitor_config);
        
        monitor.record_interest_processing(Duration::from_micros(100)).await;
        monitor.record_data_processing(Duration::from_micros(150)).await;
        monitor.update_rtt(Duration::from_millis(50)).await;
        
        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.total_interests, 1);
        assert_eq!(metrics.total_data, 1);
        assert!(metrics.avg_rtt > Duration::from_millis(0));
    }
}