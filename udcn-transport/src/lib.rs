use log::info;

pub mod tcp;
pub mod udp;
pub mod unix;
pub mod quic;

pub use tcp::*;
pub use udp::*;
pub use unix::*;
pub use quic::*;

pub trait Transport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn close(&self) -> Result<(), Box<dyn std::error::Error>>;
}

pub fn init() {
    info!("UDCN Transport initialized");
}
