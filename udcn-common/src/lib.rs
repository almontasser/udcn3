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

/// Maximum PIT entries
pub const MAX_PIT_ENTRIES: usize = 8192;

/// PIT entry timeout in nanoseconds (10 seconds)
pub const PIT_ENTRY_TIMEOUT_NS: u64 = 10_000_000_000;

/// PIT cleanup interval in nanoseconds (1 second)
pub const PIT_CLEANUP_INTERVAL_NS: u64 = 1_000_000_000;

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

/// PIT entry structure for tracking pending Interests
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PitEntry {
    /// Interest name hash for fast lookup
    pub name_hash: u64,
    /// Primary incoming face identifier
    pub incoming_face: u32,
    /// Primary Interest nonce for deduplication
    pub nonce: u32,
    /// Expiration timestamp (in nanoseconds since boot)
    pub expiry_time: u64,
    /// Creation timestamp
    pub created_time: u64,
    /// Number of times this Interest has been seen
    pub interest_count: u32,
    /// PIT entry state flags
    pub state: u8,
    /// Number of additional faces (for aggregation)
    pub additional_faces_count: u8,
    /// Padding for alignment
    pub _padding: [u8; 2],
}

/// Maximum number of additional faces that can be tracked per PIT entry
pub const MAX_ADDITIONAL_FACES: usize = 4;

/// PIT face entry for tracking additional faces in aggregation
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PitFaceEntry {
    /// Face identifier
    pub face_id: u32,
    /// Nonce for this face
    pub nonce: u32,
    /// Timestamp when this face was added
    pub timestamp: u64,
}

impl PitEntry {
    pub const fn new() -> Self {
        Self {
            name_hash: 0,
            incoming_face: 0,
            nonce: 0,
            expiry_time: 0,
            created_time: 0,
            interest_count: 0,
            state: 0,
            additional_faces_count: 0,
            _padding: [0; 2],
        }
    }
}

impl PitFaceEntry {
    pub const fn new() -> Self {
        Self {
            face_id: 0,
            nonce: 0,
            timestamp: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for PitEntry {}

#[cfg(feature = "user")]
unsafe impl Pod for PitFaceEntry {}

/// PIT entry state flags
pub const PIT_STATE_ACTIVE: u8 = 0x01;
pub const PIT_STATE_SATISFIED: u8 = 0x02;
pub const PIT_STATE_EXPIRED: u8 = 0x04;
pub const PIT_STATE_AGGREGATED: u8 = 0x08;

/// PIT statistics structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PitStats {
    /// Total number of PIT entries created
    pub entries_created: u64,
    /// Total number of PIT entries satisfied
    pub entries_satisfied: u64,
    /// Total number of PIT entries expired
    pub entries_expired: u64,
    /// Total number of Interest aggregations
    pub interests_aggregated: u64,
    /// Current number of active PIT entries
    pub active_entries: u64,
    /// Maximum number of entries reached
    pub max_entries_reached: u64,
    /// PIT lookup operations
    pub lookups: u64,
    /// PIT insertion operations
    pub insertions: u64,
    /// PIT deletion operations
    pub deletions: u64,
    /// PIT cleanup operations
    pub cleanups: u64,
}

impl PitStats {
    pub const fn new() -> Self {
        Self {
            entries_created: 0,
            entries_satisfied: 0,
            entries_expired: 0,
            interests_aggregated: 0,
            active_entries: 0,
            max_entries_reached: 0,
            lookups: 0,
            insertions: 0,
            deletions: 0,
            cleanups: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for PitStats {}

/// Face information structure for PIT entries
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FaceInfo {
    /// Face identifier
    pub face_id: u32,
    /// Face type (ethernet, ip, etc.)
    pub face_type: u8,
    /// Face state flags
    pub state: u8,
    /// Interface index
    pub ifindex: u32,
    /// MAC address for ethernet faces
    pub mac_addr: [u8; 6],
    /// IP address for IP faces
    pub ip_addr: [u8; 16],
    /// Port for UDP/TCP faces
    pub port: u16,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Statistics
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Padding for alignment
    pub _padding: [u8; 6],
}

impl FaceInfo {
    pub const fn new() -> Self {
        Self {
            face_id: 0,
            face_type: 0,
            state: 0,
            ifindex: 0,
            mac_addr: [0; 6],
            ip_addr: [0; 16],
            port: 0,
            last_activity: 0,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            _padding: [0; 6],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for FaceInfo {}

/// Face type constants
pub const FACE_TYPE_ETHERNET: u8 = 0x01;
pub const FACE_TYPE_IP: u8 = 0x02;
pub const FACE_TYPE_UDP: u8 = 0x03;
pub const FACE_TYPE_TCP: u8 = 0x04;

/// Face state constants
pub const FACE_STATE_UP: u8 = 0x01;
pub const FACE_STATE_DOWN: u8 = 0x02;
pub const FACE_STATE_CONGESTED: u8 = 0x04;

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
    /// PIT entry not found
    PitEntryNotFound = 9,
    /// PIT table full
    PitTableFull = 10,
    /// Interest expired
    InterestExpired = 11,
    /// Face not found
    FaceNotFound = 12,
}
