use std::io::{self, Read, Write};
use std::convert::TryInto;

/// TLV (Type-Length-Value) codec for binary data serialization
/// 
/// Wire format:
/// - Type: 1 byte (0-255)
/// - Length: variable length encoding (1-5 bytes)
/// - Value: variable length data
#[derive(Debug, Clone, PartialEq)]
pub struct TlvElement {
    pub type_: u8,
    pub value: Vec<u8>,
}

/// Errors that can occur during TLV encoding/decoding
#[derive(Debug, thiserror::Error)]
pub enum TlvError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid length encoding")]
    InvalidLength,
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid TLV type: {0}")]
    InvalidType(u8),
    #[error("Value length mismatch: expected {expected}, got {actual}")]
    ValueLengthMismatch { expected: usize, actual: usize },
}

impl TlvElement {
    /// Create a new TLV element
    pub fn new(type_: u8, value: Vec<u8>) -> Self {
        Self { type_, value }
    }

    /// Get the total encoded length of this TLV element
    pub fn encoded_length(&self) -> usize {
        1 + encode_length_size(self.value.len()) + self.value.len()
    }

    /// Encode this TLV element to bytes
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut buffer = Vec::with_capacity(self.encoded_length());
        self.encode_to(&mut buffer)?;
        Ok(buffer)
    }

    /// Encode this TLV element to a writer
    pub fn encode_to<W: Write>(&self, writer: &mut W) -> Result<(), TlvError> {
        // Write type
        writer.write_all(&[self.type_])?;
        
        // Write length
        encode_length(self.value.len(), writer)?;
        
        // Write value
        writer.write_all(&self.value)?;
        
        Ok(())
    }

    /// Decode a TLV element from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TlvError> {
        if data.is_empty() {
            return Err(TlvError::BufferTooShort);
        }

        let mut offset = 0;
        
        // Read type
        let type_ = data[offset];
        offset += 1;

        // Read length
        let (length, length_bytes) = decode_length(&data[offset..])?;
        offset += length_bytes;

        // Check if we have enough bytes for the value
        if data.len() < offset + length {
            return Err(TlvError::BufferTooShort);
        }

        // Read value
        let value = data[offset..offset + length].to_vec();
        offset += length;

        Ok((TlvElement::new(type_, value), offset))
    }

    /// Decode a TLV element from a reader
    pub fn decode_from<R: Read>(reader: &mut R) -> Result<Self, TlvError> {
        // Read type
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)?;
        let type_ = type_buf[0];

        // Read length
        let length = decode_length_from(reader)?;

        // Read value
        let mut value = vec![0u8; length];
        reader.read_exact(&mut value)?;

        Ok(TlvElement::new(type_, value))
    }
}

/// Encode length using variable-length encoding
/// 
/// Format:
/// - If length < 253: 1 byte
/// - If length < 65536: 0xFD + 2 bytes (little-endian)
/// - If length < 4294967296: 0xFE + 4 bytes (little-endian)
/// - Otherwise: 0xFF + 8 bytes (little-endian)
fn encode_length<W: Write>(length: usize, writer: &mut W) -> Result<(), TlvError> {
    if length < 253 {
        writer.write_all(&[length as u8])?;
    } else if length < 65536 {
        writer.write_all(&[0xFD])?;
        writer.write_all(&(length as u16).to_le_bytes())?;
    } else if length < 4294967296 {
        writer.write_all(&[0xFE])?;
        writer.write_all(&(length as u32).to_le_bytes())?;
    } else {
        writer.write_all(&[0xFF])?;
        writer.write_all(&(length as u64).to_le_bytes())?;
    }
    Ok(())
}

/// Get the size needed to encode a length value
fn encode_length_size(length: usize) -> usize {
    if length < 253 {
        1
    } else if length < 65536 {
        3
    } else if length < 4294967296 {
        5
    } else {
        9
    }
}

/// Decode length from bytes
fn decode_length(data: &[u8]) -> Result<(usize, usize), TlvError> {
    if data.is_empty() {
        return Err(TlvError::BufferTooShort);
    }

    let first_byte = data[0];
    
    if first_byte < 253 {
        Ok((first_byte as usize, 1))
    } else if first_byte == 0xFD {
        if data.len() < 3 {
            return Err(TlvError::BufferTooShort);
        }
        let length = u16::from_le_bytes(data[1..3].try_into().unwrap()) as usize;
        Ok((length, 3))
    } else if first_byte == 0xFE {
        if data.len() < 5 {
            return Err(TlvError::BufferTooShort);
        }
        let length = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
        Ok((length, 5))
    } else if first_byte == 0xFF {
        if data.len() < 9 {
            return Err(TlvError::BufferTooShort);
        }
        let length = u64::from_le_bytes(data[1..9].try_into().unwrap()) as usize;
        Ok((length, 9))
    } else {
        Err(TlvError::InvalidLength)
    }
}

/// Decode length from a reader
fn decode_length_from<R: Read>(reader: &mut R) -> Result<usize, TlvError> {
    let mut first_byte = [0u8; 1];
    reader.read_exact(&mut first_byte)?;
    let first_byte = first_byte[0];
    
    if first_byte < 253 {
        Ok(first_byte as usize)
    } else if first_byte == 0xFD {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf) as usize)
    } else if first_byte == 0xFE {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf) as usize)
    } else if first_byte == 0xFF {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf) as usize)
    } else {
        Err(TlvError::InvalidLength)
    }
}

/// Encode multiple TLV elements into a single buffer
pub fn encode_tlv_sequence(elements: &[TlvElement]) -> Result<Vec<u8>, TlvError> {
    let total_size = elements.iter().map(|e| e.encoded_length()).sum();
    let mut buffer = Vec::with_capacity(total_size);
    
    for element in elements {
        element.encode_to(&mut buffer)?;
    }
    
    Ok(buffer)
}

/// Decode multiple TLV elements from a buffer
pub fn decode_tlv_sequence(data: &[u8]) -> Result<Vec<TlvElement>, TlvError> {
    let mut elements = Vec::new();
    let mut offset = 0;
    
    while offset < data.len() {
        let (element, consumed) = TlvElement::decode(&data[offset..])?;
        elements.push(element);
        offset += consumed;
    }
    
    Ok(elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tlv_encoding() {
        let element = TlvElement::new(1, vec![0x01, 0x02, 0x03]);
        let encoded = element.encode().unwrap();
        
        // Type (1) + Length (3) + Value (3 bytes)
        assert_eq!(encoded, vec![1, 3, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_basic_tlv_decoding() {
        let data = vec![1, 3, 0x01, 0x02, 0x03];
        let (element, consumed) = TlvElement::decode(&data).unwrap();
        
        assert_eq!(element.type_, 1);
        assert_eq!(element.value, vec![0x01, 0x02, 0x03]);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_empty_value() {
        let element = TlvElement::new(42, vec![]);
        let encoded = element.encode().unwrap();
        assert_eq!(encoded, vec![42, 0]);
        
        let (decoded, consumed) = TlvElement::decode(&encoded).unwrap();
        assert_eq!(decoded, element);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_large_value() {
        let large_value = vec![0xAA; 300];
        let element = TlvElement::new(100, large_value.clone());
        let encoded = element.encode().unwrap();
        
        // Should use 3-byte length encoding (0xFD + 2 bytes)
        assert_eq!(encoded[0], 100); // Type
        assert_eq!(encoded[1], 0xFD); // Length marker
        assert_eq!(u16::from_le_bytes([encoded[2], encoded[3]]), 300); // Length
        assert_eq!(encoded[4..], large_value); // Value
        
        let (decoded, _) = TlvElement::decode(&encoded).unwrap();
        assert_eq!(decoded, element);
    }

    #[test]
    fn test_round_trip() {
        let original = TlvElement::new(255, vec![1, 2, 3, 4, 5]);
        let encoded = original.encode().unwrap();
        let (decoded, _) = TlvElement::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_sequence_encoding() {
        let elements = vec![
            TlvElement::new(1, vec![0x01]),
            TlvElement::new(2, vec![0x02, 0x03]),
            TlvElement::new(3, vec![]),
        ];
        
        let encoded = encode_tlv_sequence(&elements).unwrap();
        let decoded = decode_tlv_sequence(&encoded).unwrap();
        
        assert_eq!(decoded, elements);
    }

    #[test]
    fn test_buffer_too_short() {
        let data = vec![1, 5, 0x01, 0x02]; // Says length 5 but only has 2 bytes
        assert!(matches!(TlvElement::decode(&data), Err(TlvError::BufferTooShort)));
    }

    #[test]
    fn test_length_encoding_variants() {
        // Test different length encodings
        let test_cases = vec![
            (0, vec![0]),
            (252, vec![252]),
            (253, vec![0xFD, 253, 0]),
            (65535, vec![0xFD, 255, 255]),
            (65536, vec![0xFE, 0, 0, 1, 0]),
        ];
        
        for (length, expected_encoding) in test_cases {
            let element = TlvElement::new(1, vec![0; length]);
            let encoded = element.encode().unwrap();
            
            // Check that length is encoded correctly
            assert_eq!(encoded[0], 1); // Type
            assert_eq!(&encoded[1..1 + expected_encoding.len()], &expected_encoding);
            
            // Verify round-trip
            let (decoded, _) = TlvElement::decode(&encoded).unwrap();
            assert_eq!(decoded.value.len(), length);
        }
    }
}