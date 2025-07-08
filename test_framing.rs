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
}

impl LengthPrefixFramer {
    pub fn new(max_packet_size: usize) -> Self {
        Self { max_packet_size }
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

fn main() {
    // Test 1: Basic framing and extraction
    println!("Test 1: Basic framing and extraction");
    let framer = LengthPrefixFramer::new(1024);
    let packet = b"Hello, NDN!";
    
    // Test framing
    let framed = framer.frame_packet(packet).unwrap();
    println!("Original packet: {:?}", std::str::from_utf8(packet).unwrap());
    println!("Framed length: {} bytes", framed.len());
    assert_eq!(framed.len(), 4 + packet.len());
    assert_eq!(&framed[0..4], &(packet.len() as u32).to_be_bytes());
    assert_eq!(&framed[4..], packet);
    
    // Test extraction
    let mut buffer = framed;
    let packets = framer.extract_packets(&mut buffer).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0], packet);
    assert!(buffer.is_empty());
    println!("✓ Basic framing works");
    
    // Test 2: Partial packet reception
    println!("\nTest 2: Partial packet reception");
    let packet2 = b"Another NDN packet";
    let framed2 = framer.frame_packet(packet2).unwrap();
    
    let mut buffer = Vec::new();
    
    // Add partial data
    buffer.extend_from_slice(&framed2[0..6]);
    let packets = framer.extract_packets(&mut buffer).unwrap();
    assert!(packets.is_empty());
    println!("✓ Partial packet correctly not extracted");
    
    // Add remaining data
    buffer.extend_from_slice(&framed2[6..]);
    let packets = framer.extract_packets(&mut buffer).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0], packet2);
    println!("✓ Complete packet extracted after receiving all data");
    
    // Test 3: Multiple packets in buffer
    println!("\nTest 3: Multiple packets in buffer");
    let packet3 = b"Packet 1";
    let packet4 = b"Packet 2 with more data";
    let framed3 = framer.frame_packet(packet3).unwrap();
    let framed4 = framer.frame_packet(packet4).unwrap();
    
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&framed3);
    buffer.extend_from_slice(&framed4);
    
    let packets = framer.extract_packets(&mut buffer).unwrap();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], packet3);
    assert_eq!(packets[1], packet4);
    assert!(buffer.is_empty());
    println!("✓ Multiple packets extracted correctly");
    
    // Test 4: Packet boundary detection
    println!("\nTest 4: Packet boundary detection");
    let test_packet = b"Test packet for boundary detection";
    let framed_test = framer.frame_packet(test_packet).unwrap();
    
    // Test with complete packet
    assert!(framer.has_complete_packet(&framed_test));
    println!("✓ Complete packet detected");
    
    // Test with partial packet
    assert!(!framer.has_complete_packet(&framed_test[0..6]));
    println!("✓ Partial packet correctly detected as incomplete");
    
    // Test with empty buffer
    assert!(!framer.has_complete_packet(&[]));
    println!("✓ Empty buffer correctly detected as incomplete");
    
    println!("\n🎉 All packet framing tests passed successfully!");
    
    // Test 5: Wire format validation (basic NDN packet structure)
    println!("\nTest 5: Wire format validation");
    
    // Create a simple Interest packet (Type 0x05)
    let ndn_interest = vec![
        0x05, // Interest type
        0x0B, // Length (11 bytes)
        0x07, 0x09, // Name TLV (type 0x07, length 9)
        0x08, 0x04, b't', b'e', b's', b't', // Name component "test"
        0x08, 0x01, b'a' // Name component "a"
    ];
    
    println!("Testing NDN Interest packet validation...");
    match validate_ndn_packet(&ndn_interest) {
        Ok(()) => println!("✓ Valid NDN Interest packet structure"),
        Err(e) => println!("✗ NDN packet validation failed: {}", e),
    }
    
    // Test invalid packet type
    let invalid_packet = vec![0xFF, 0x05]; // Invalid type
    match validate_ndn_packet(&invalid_packet) {
        Ok(()) => println!("✗ Should have failed for invalid packet type"),
        Err(_) => println!("✓ Invalid packet type correctly rejected"),
    }
    
    println!("\n🚀 Packet framing system implementation complete!");
}

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
    let (length, length_bytes) = parse_tlv_length(&data[1..])?;
    
    if data.len() < 1 + length_bytes + length {
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