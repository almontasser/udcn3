use std::fmt;

/// Unified framing interface for all NDN transport protocols
pub trait FramingLayer {
    /// Frame a packet for transmission over the transport
    fn frame_packet(&self, packet: &[u8]) -> Result<Vec<u8>, FramingError>;
    
    /// Extract complete packets from a streaming buffer
    fn extract_packets(&self, buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, FramingError>;
    
    /// Check if the buffer contains at least one complete packet
    fn has_complete_packet(&self, buffer: &[u8]) -> bool;
    
    /// Get the expected packet length from buffer (if determinable)
    fn get_packet_length(&self, buffer: &[u8]) -> Option<usize>;
}

/// Framing errors that can occur during packet processing
#[derive(Debug)]
pub enum FramingError {
    InsufficientBuffer,
    InvalidHeader(String),
    PacketTooLarge { size: usize, max: usize },
    InvalidLength(usize),
    FragmentationNotSupported,
    BufferOverflow,
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FramingError::InsufficientBuffer => write!(f, "Buffer too small for frame header"),
            FramingError::InvalidHeader(msg) => write!(f, "Invalid frame header: {}", msg),
            FramingError::PacketTooLarge { size, max } => write!(f, "Packet too large: {} bytes (max: {})", size, max),
            FramingError::InvalidLength(len) => write!(f, "Invalid packet length: {}", len),
            FramingError::FragmentationNotSupported => write!(f, "Fragmentation not supported by this transport"),
            FramingError::BufferOverflow => write!(f, "Buffer overflow"),
        }
    }
}

impl std::error::Error for FramingError {}

/// Length-prefix framing for stream-based transports (TCP, Unix sockets)
pub struct LengthPrefixFramer {
    max_packet_size: usize,
    enable_fragmentation: bool,
    fragment_size: usize,
}

impl LengthPrefixFramer {
    pub fn new(max_packet_size: usize) -> Self {
        Self {
            max_packet_size,
            enable_fragmentation: false,
            fragment_size: 1400, // Default MTU-safe fragment size
        }
    }
    
    /// Create framer with fragmentation support
    pub fn with_fragmentation(max_packet_size: usize, fragment_size: usize) -> Self {
        Self {
            max_packet_size,
            enable_fragmentation: true,
            fragment_size,
        }
    }
    
    /// Default framer with 64KB max packet size
    pub fn default() -> Self {
        Self::new(65536)
    }
}

impl FramingLayer for LengthPrefixFramer {
    fn frame_packet(&self, packet: &[u8]) -> Result<Vec<u8>, FramingError> {
        if packet.len() > self.max_packet_size {
            return Err(FramingError::PacketTooLarge {
                size: packet.len(),
                max: self.max_packet_size,
            });
        }
        
        let length = packet.len() as u32;
        let mut framed = Vec::with_capacity(4 + packet.len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(packet);
        
        Ok(framed)
    }
    
    fn extract_packets(&self, buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, FramingError> {
        let mut packets = Vec::new();
        
        while buffer.len() >= 4 {
            let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
            
            if length > self.max_packet_size {
                return Err(FramingError::PacketTooLarge {
                    size: length,
                    max: self.max_packet_size,
                });
            }
            
            if buffer.len() < 4 + length {
                // Not enough data for complete packet
                break;
            }
            
            // Extract packet (skip 4-byte length prefix)
            let packet = buffer[4..4 + length].to_vec();
            packets.push(packet);
            
            // Remove processed bytes from buffer
            buffer.drain(0..4 + length);
        }
        
        Ok(packets)
    }
    
    fn has_complete_packet(&self, buffer: &[u8]) -> bool {
        if buffer.len() < 4 {
            return false;
        }
        
        let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        buffer.len() >= 4 + length
    }
    
    fn get_packet_length(&self, buffer: &[u8]) -> Option<usize> {
        if buffer.len() < 4 {
            return None;
        }
        
        let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        Some(4 + length) // Include 4-byte length prefix
    }
}

/// No-op framing for datagram-based transports (UDP)
pub struct DatagramFramer;

impl FramingLayer for DatagramFramer {
    fn frame_packet(&self, packet: &[u8]) -> Result<Vec<u8>, FramingError> {
        // UDP provides natural packet boundaries
        Ok(packet.to_vec())
    }
    
    fn extract_packets(&self, buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, FramingError> {
        if buffer.is_empty() {
            return Ok(Vec::new());
        }
        
        // Each UDP receive operation provides one complete packet
        let packet = buffer.clone();
        buffer.clear();
        Ok(vec![packet])
    }
    
    fn has_complete_packet(&self, buffer: &[u8]) -> bool {
        !buffer.is_empty()
    }
    
    fn get_packet_length(&self, buffer: &[u8]) -> Option<usize> {
        if buffer.is_empty() {
            None
        } else {
            Some(buffer.len())
        }
    }
}

/// Streaming packet buffer for handling partial packet reception
pub struct PacketBuffer {
    buffer: Vec<u8>,
    framer: Box<dyn FramingLayer + Send + Sync>,
    max_buffer_size: usize,
}

impl PacketBuffer {
    pub fn new(framer: Box<dyn FramingLayer + Send + Sync>, max_buffer_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            framer,
            max_buffer_size,
        }
    }
    
    /// Add incoming data to the buffer
    pub fn add_data(&mut self, data: &[u8]) -> Result<(), FramingError> {
        if self.buffer.len() + data.len() > self.max_buffer_size {
            return Err(FramingError::BufferOverflow);
        }
        
        self.buffer.extend_from_slice(data);
        Ok(())
    }
    
    /// Extract all complete packets from the buffer
    pub fn extract_packets(&mut self) -> Result<Vec<Vec<u8>>, FramingError> {
        self.framer.extract_packets(&mut self.buffer)
    }
    
    /// Check if buffer has at least one complete packet
    pub fn has_complete_packet(&self) -> bool {
        self.framer.has_complete_packet(&self.buffer)
    }
    
    /// Get current buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
    
    /// Clear the buffer (for error recovery)
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Packet boundary detection utilities
pub mod boundary_detection {
    use super::*;
    
    /// Validate NDN TLV packet structure
    pub fn validate_ndn_packet(data: &[u8]) -> Result<(), FramingError> {
        if data.len() < 2 {
            return Err(FramingError::InvalidHeader("Packet too short for TLV header".to_string()));
        }
        
        let packet_type = data[0];
        
        // Validate NDN packet types
        match packet_type {
            0x05 => {}, // Interest
            0x06 => {}, // Data
            0x64 => {}, // Network NACK
            _ => return Err(FramingError::InvalidHeader(format!("Invalid NDN packet type: {:#x}", packet_type))),
        }
        
        // Validate TLV length encoding
        let (length, _) = parse_tlv_length(&data[1..])?;
        
        if data.len() < 1 + length_encoding_size(&data[1..]) + length {
            return Err(FramingError::InvalidHeader("Packet length doesn't match TLV encoding".to_string()));
        }
        
        Ok(())
    }
    
    /// Parse TLV length from bytes
    fn parse_tlv_length(data: &[u8]) -> Result<(usize, usize), FramingError> {
        if data.is_empty() {
            return Err(FramingError::InsufficientBuffer);
        }
        
        let first_byte = data[0];
        
        if first_byte < 253 {
            Ok((first_byte as usize, 1))
        } else if first_byte == 253 {
            if data.len() < 3 {
                return Err(FramingError::InsufficientBuffer);
            }
            let length = u16::from_be_bytes([data[1], data[2]]) as usize;
            Ok((length, 3))
        } else if first_byte == 254 {
            if data.len() < 5 {
                return Err(FramingError::InsufficientBuffer);
            }
            let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            Ok((length, 5))
        } else {
            if data.len() < 9 {
                return Err(FramingError::InsufficientBuffer);
            }
            let length = u64::from_be_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8]
            ]) as usize;
            Ok((length, 9))
        }
    }
    
    /// Get the size of length encoding in bytes
    fn length_encoding_size(data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        
        let first_byte = data[0];
        match first_byte {
            0..=252 => 1,
            253 => 3,
            254 => 5,
            255 => 9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_length_prefix_framing() {
        let framer = LengthPrefixFramer::new(1024);
        let packet = b"Hello, NDN!";
        
        // Test framing
        let framed = framer.frame_packet(packet).unwrap();
        assert_eq!(framed.len(), 4 + packet.len());
        assert_eq!(&framed[0..4], &(packet.len() as u32).to_be_bytes());
        assert_eq!(&framed[4..], packet);
        
        // Test extraction
        let mut buffer = framed;
        let packets = framer.extract_packets(&mut buffer).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
        assert!(buffer.is_empty());
    }
    
    #[test]
    fn test_partial_packet_reception() {
        let framer = LengthPrefixFramer::new(1024);
        let packet = b"Hello, NDN!";
        let framed = framer.frame_packet(packet).unwrap();
        
        let mut buffer = Vec::new();
        
        // Add partial data
        buffer.extend_from_slice(&framed[0..6]);
        let packets = framer.extract_packets(&mut buffer).unwrap();
        assert!(packets.is_empty());
        
        // Add remaining data
        buffer.extend_from_slice(&framed[6..]);
        let packets = framer.extract_packets(&mut buffer).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
    }
    
    #[test]
    fn test_datagram_framing() {
        let framer = DatagramFramer;
        let packet = b"Hello, NDN!";
        
        // Test framing (should be no-op)
        let framed = framer.frame_packet(packet).unwrap();
        assert_eq!(framed, packet);
        
        // Test extraction
        let mut buffer = packet.to_vec();
        let packets = framer.extract_packets(&mut buffer).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
        assert!(buffer.is_empty());
    }
    
    #[test]
    fn test_packet_buffer() {
        let framer = Box::new(LengthPrefixFramer::new(1024));
        let mut packet_buffer = PacketBuffer::new(framer, 4096);
        
        let packet = b"Hello, NDN!";
        let length_prefix_framer = LengthPrefixFramer::new(1024);
        let framed = length_prefix_framer.frame_packet(packet).unwrap();
        
        // Add data in chunks
        packet_buffer.add_data(&framed[0..6]).unwrap();
        assert!(!packet_buffer.has_complete_packet());
        
        packet_buffer.add_data(&framed[6..]).unwrap();
        assert!(packet_buffer.has_complete_packet());
        
        let packets = packet_buffer.extract_packets().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], packet);
    }
}