use log::info;

pub mod tcp;
pub mod udp;
pub mod unix;
pub mod quic;
pub mod quic_pool;
pub mod ndn_quic;
pub mod ndn_optimizations;
pub mod ndn_forwarding;
pub mod ndn_performance;
pub mod data_response_handler;
pub mod framing;
pub mod stream_multiplexer;
pub mod file_chunking;
pub mod data_publisher;
pub mod concurrent_server;
pub mod progress_tracker;
pub mod file_interest_generator;
pub mod data_reception_handler;
pub mod file_reassembly;
pub mod file_integrity;
pub mod pipeline_coordinator;
pub mod packet_fragmentation;
pub mod packet_reassembly;
pub mod fragmented_transport;
pub mod concurrent_transport;

pub use tcp::*;
pub use udp::*;
pub use unix::*;
pub use quic::*;
// Re-export quinn types
pub use quinn::Connection;
pub use quic_pool::*;

// NDN-specific exports
pub use ndn_quic::{NdnQuicTransport, NdnQuicConfig, NdnFrame, NdnFrameType, NdnFrameHeader, NdnQuicStreamHandler, utils as ndn_quic_utils};
pub use ndn_optimizations::*;
pub use ndn_forwarding::{NdnForwardingEngine, ForwardingInformationBase, PendingInterestTable as NdnPendingInterestTable, ForwardingConfig, ForwardingDecision, ForwardingStats};
pub use ndn_performance::*;
pub use data_response_handler::{DataResponseHandler, DataResponseConfig, DataVerificationStatus, ContentStore, ContentStoreEntry, DataResponseStats};

// Framing exports
pub use framing::{FramingLayer, FramingError, LengthPrefixFramer, DatagramFramer, PacketBuffer, boundary_detection};

// Stream multiplexing exports
pub use stream_multiplexer::{StreamMultiplexer, StreamMultiplexerConfig, StreamId, StreamType, StreamPriority, StreamState, StreamEntry, StreamPool, StreamStats};

// File chunking exports
pub use file_chunking::{FileChunker, ChunkingConfig, FileMetadata, ChunkInfo, FileChunk, ChunkingError, FileChunkIterator};

// Data publisher exports
pub use data_publisher::{DataPacketPublisher, PublisherConfig, PublishStats, PublishedPacket, PublishingError};

// Concurrent server exports
pub use concurrent_server::{ConcurrentServer, ConcurrentServerConfig, ServerStats, RequestResponse, ConcurrentServerError};

// File reassembly exports
pub use file_reassembly::{FileReassemblyEngine, ReassemblyConfig, ReassemblyStatus, ReassemblyProgress, ReassemblyStats};

// File integrity exports
pub use file_integrity::{FileIntegrityEngine, IntegrityConfig, IntegrityStatus, IntegrityResult, ChecksumResult, SignatureResult, ChecksumAlgorithm, SignatureAlgorithm, IntegrityError, IntegrityStats};

// Packet fragmentation exports
pub use packet_fragmentation::{PacketFragmenter, FragmentationConfig, Fragment, FragmentHeader, FragmentationError, DEFAULT_MTU, MIN_FRAGMENT_SIZE};

// Packet reassembly exports
pub use packet_reassembly::{PacketReassembler, ReassemblyConfig as PacketReassemblyConfig, ReassemblyStats as PacketReassemblyStats, ReassemblyError};

// Fragmented transport exports
pub use fragmented_transport::{FragmentedTransport, FragmentedTransportError};

// Concurrent transport exports
pub use concurrent_transport::{ConcurrentTransportWrapper, ConcurrentTransportConfig, ConcurrentOperationPool};

/// Synchronous transport trait for backward compatibility
pub trait Transport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn close(&self) -> Result<(), Box<dyn std::error::Error>>;
}

/// Async transport trait with thread-safety for concurrent operations
#[async_trait::async_trait]
pub trait AsyncTransport: Send + Sync {
    /// Send data asynchronously
    async fn send_async(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Receive data asynchronously
    async fn receive_async(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
    /// Close the transport asynchronously
    async fn close_async(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Send data to a specific destination
    async fn send_to_async(&self, data: &[u8], addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Receive data with timeout
    async fn receive_timeout_async(&self, timeout: std::time::Duration) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Thread-safe transport trait combining sync and async capabilities
pub trait ConcurrentTransport: Transport + AsyncTransport + Send + Sync + Clone {
    /// Get transport statistics
    fn get_stats(&self) -> TransportStats;
    /// Reset transport statistics
    fn reset_stats(&self);
}

/// Transport performance and usage statistics
#[derive(Debug, Clone)]
pub struct TransportStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub send_errors: u64,
    pub receive_errors: u64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub last_activity: Option<std::time::Instant>,
    pub created_at: std::time::Instant,
}

impl Default for TransportStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            send_errors: 0,
            receive_errors: 0,
            active_connections: 0,
            total_connections: 0,
            last_activity: None,
            created_at: std::time::Instant::now(),
        }
    }
}

impl TransportStats {
    pub fn throughput_bps(&self) -> f64 {
        let elapsed = self.created_at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (self.bytes_sent + self.bytes_received) as f64 / elapsed
        } else {
            0.0
        }
    }
    
    pub fn error_rate(&self) -> f64 {
        let total_ops = self.packets_sent + self.packets_received;
        if total_ops > 0 {
            (self.send_errors + self.receive_errors) as f64 / total_ops as f64
        } else {
            0.0
        }
    }
}

pub fn init() {
    info!("UDCN Transport initialized");
}
