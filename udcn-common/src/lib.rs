#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

/// Maximum length for UDCN names
pub const MAX_NAME_LENGTH: usize = 256;

/// Maximum number of name components
pub const MAX_NAME_COMPONENTS: usize = 32;

/// Maximum payload size for UDCN packets
pub const MAX_PAYLOAD_SIZE: usize = 65536;

/// eBPF map key size
pub const MAP_KEY_SIZE: usize = 32;

/// XDP action codes used by UDCN
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpAction {
    /// Pass the packet to the network stack
    Pass = 2,
    /// Drop the packet
    Drop = 1,
    /// Redirect the packet to another interface
    Redirect = 4,
    /// Transmit the packet back out the same interface
    Tx = 3,
    /// Abort processing (error state)
    Aborted = 0,
}

/// UDCN packet types
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Interest packet requesting content
    Interest = 0x01,
    /// Data packet containing content
    Data = 0x02,
    /// Nack packet indicating failure
    Nack = 0x03,
    /// Control packet for network management
    Control = 0x04,
}

/// Statistics structure for packet processing
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketStats {
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub packets_redirected: u64,
    pub bytes_processed: u64,
    pub processing_time_ns: u64,
    pub interest_packets: u64,
    pub data_packets: u64,
    pub nack_packets: u64,
    pub control_packets: u64,
    pub parse_errors: u64,
    pub memory_errors: u64,
}

impl PacketStats {
    pub const fn new() -> Self {
        Self {
            packets_processed: 0,
            packets_dropped: 0,
            packets_passed: 0,
            packets_redirected: 0,
            bytes_processed: 0,
            processing_time_ns: 0,
            interest_packets: 0,
            data_packets: 0,
            nack_packets: 0,
            control_packets: 0,
            parse_errors: 0,
            memory_errors: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for PacketStats {}

/// Packet metadata structure shared between kernel and userspace
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketMetadata {
    /// Source MAC address
    pub src_mac: [u8; 6],
    /// Destination MAC address  
    pub dst_mac: [u8; 6],
    /// Ethernet type
    pub eth_type: u16,
    /// IP version (4 or 6)
    pub ip_version: u8,
    /// IP protocol
    pub ip_protocol: u8,
    /// Source IP address (IPv4 or IPv6)
    pub src_ip: [u8; 16],
    /// Destination IP address (IPv4 or IPv6)
    pub dst_ip: [u8; 16],
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Packet length
    pub packet_len: u32,
    /// UDCN packet type
    pub packet_type: PacketType,
    /// Processing timestamp
    pub timestamp: u64,
    /// Interface index
    pub ifindex: u32,
    /// Padding for alignment
    pub _padding: [u8; 3],
}

impl PacketMetadata {
    pub const fn new() -> Self {
        Self {
            src_mac: [0; 6],
            dst_mac: [0; 6],
            eth_type: 0,
            ip_version: 0,
            ip_protocol: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            packet_len: 0,
            packet_type: PacketType::Interest,
            timestamp: 0,
            ifindex: 0,
            _padding: [0; 3],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for PacketMetadata {}

/// Configuration structure for UDCN eBPF programs
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UdcnConfig {
    /// Enable debug logging
    pub debug_enabled: u8,
    /// Maximum number of concurrent flows
    pub max_flows: u32,
    /// Flow timeout in seconds
    pub flow_timeout: u32,
    /// Enable packet statistics collection
    pub stats_enabled: u8,
    /// Enable packet filtering
    pub filter_enabled: u8,
    /// Enable packet redirection
    pub redirect_enabled: u8,
    /// Target interface for redirection
    pub redirect_ifindex: u32,
    /// Padding for alignment
    pub _padding: [u8; 4],
}

impl UdcnConfig {
    pub const fn new() -> Self {
        Self {
            debug_enabled: 0,
            max_flows: 1000,
            flow_timeout: 30,
            stats_enabled: 1,
            filter_enabled: 1,
            redirect_enabled: 0,
            redirect_ifindex: 0,
            _padding: [0; 4],
        }
    }
}

/// Flow table entry for connection tracking
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowEntry {
    /// Source IP address
    pub src_ip: [u8; 16],
    /// Destination IP address
    pub dst_ip: [u8; 16],
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// IP protocol
    pub protocol: u8,
    /// Flow state
    pub state: u8,
    /// Packet count
    pub packet_count: u64,
    /// Byte count
    pub byte_count: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Creation timestamp
    pub created: u64,
}

impl FlowEntry {
    pub const fn new() -> Self {
        Self {
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            state: 0,
            packet_count: 0,
            byte_count: 0,
            last_seen: 0,
            created: 0,
        }
    }
}

/// UDCN name structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UdcnName {
    /// Name components
    pub components: [u8; MAX_NAME_LENGTH],
    /// Number of components
    pub component_count: u32,
    /// Total name length
    pub total_length: u32,
}

impl UdcnName {
    pub const fn new() -> Self {
        Self {
            components: [0; MAX_NAME_LENGTH],
            component_count: 0,
            total_length: 0,
        }
    }
}

/// Error codes for UDCN operations
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdcnError {
    /// Success
    Success = 0,
    /// Invalid packet format
    InvalidPacket = 1,
    /// Packet too short
    PacketTooShort = 2,
    /// Unsupported protocol
    UnsupportedProtocol = 3,
    /// Memory allocation error
    MemoryError = 4,
    /// Map operation failed
    MapError = 5,
    /// Flow table full
    FlowTableFull = 6,
    /// Invalid configuration
    InvalidConfig = 7,
    /// Feature not supported
    NotSupported = 8,
}
