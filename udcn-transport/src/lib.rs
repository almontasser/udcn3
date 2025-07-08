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

pub use tcp::*;
pub use udp::*;
pub use unix::*;
pub use quic::*;
pub use quic_pool::*;

// NDN-specific exports
pub use ndn_quic::{NdnQuicTransport, NdnQuicConfig, NdnFrame, NdnFrameType, NdnFrameHeader, NdnQuicStreamHandler, utils as ndn_quic_utils};
pub use ndn_optimizations::*;
pub use ndn_forwarding::{NdnForwardingEngine, ForwardingInformationBase, PendingInterestTable as NdnPendingInterestTable, ForwardingConfig, ForwardingDecision, ForwardingStats};
pub use ndn_performance::*;
pub use data_response_handler::{DataResponseHandler, DataResponseConfig, DataVerificationStatus, ContentStore, ContentStoreEntry, DataResponseStats};

// Framing exports
pub use framing::{FramingLayer, FramingError, LengthPrefixFramer, DatagramFramer, PacketBuffer, boundary_detection};

pub trait Transport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn close(&self) -> Result<(), Box<dyn std::error::Error>>;
}

pub fn init() {
    info!("UDCN Transport initialized");
}
