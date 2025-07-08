use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
};

use crate::{Transport, FramingLayer, LengthPrefixFramer, PacketBuffer, FramingError};

pub struct TcpTransport {
    stream: Option<TcpStream>,
    framer: LengthPrefixFramer,
    receive_buffer: Arc<Mutex<PacketBuffer>>,
}

impl TcpTransport {
    pub fn new() -> Self {
        let framer = LengthPrefixFramer::new(65536); // 64KB max packet size
        let packet_buffer = PacketBuffer::new(
            Box::new(LengthPrefixFramer::new(65536)),
            1024 * 1024, // 1MB buffer size
        );
        
        Self {
            stream: None,
            framer,
            receive_buffer: Arc::new(Mutex::new(packet_buffer)),
        }
    }
    
    pub fn new_with_max_packet_size(max_packet_size: usize) -> Self {
        let framer = LengthPrefixFramer::new(max_packet_size);
        let packet_buffer = PacketBuffer::new(
            Box::new(LengthPrefixFramer::new(max_packet_size)),
            max_packet_size * 16, // Buffer 16x max packet size
        );
        
        Self {
            stream: None,
            framer,
            receive_buffer: Arc::new(Mutex::new(packet_buffer)),
        }
    }

    pub fn connect(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr)?;
        self.stream = Some(stream);
        Ok(())
    }
    
    /// Receive multiple packets if available in buffer
    pub fn receive_all(&self) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        if let Some(ref stream) = self.stream.as_ref() {
            let mut stream = stream.try_clone()?;
            let mut temp_buffer = vec![0; 4096];
            
            // Read incoming data
            let bytes_read = stream.read(&mut temp_buffer)?;
            if bytes_read == 0 {
                return Ok(Vec::new());
            }
            
            temp_buffer.truncate(bytes_read);
            
            // Add to packet buffer
            let mut packet_buffer = self.receive_buffer.lock().unwrap();
            packet_buffer.add_data(&temp_buffer)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            
            // Extract all complete packets
            let packets = packet_buffer.extract_packets()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            
            Ok(packets)
        } else {
            Err("Not connected".into())
        }
    }
    
    /// Check if there are complete packets available in buffer
    pub fn has_packets_ready(&self) -> bool {
        if let Ok(packet_buffer) = self.receive_buffer.lock() {
            packet_buffer.has_complete_packet()
        } else {
            false
        }
    }
    
    /// Get current receive buffer size
    pub fn receive_buffer_size(&self) -> usize {
        if let Ok(packet_buffer) = self.receive_buffer.lock() {
            packet_buffer.buffer_size()
        } else {
            0
        }
    }
    
    /// Clear receive buffer (for error recovery)
    pub fn clear_receive_buffer(&self) {
        if let Ok(mut packet_buffer) = self.receive_buffer.lock() {
            packet_buffer.clear();
        }
    }
}

impl Transport for TcpTransport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref stream) = self.stream.as_ref() {
            let mut stream = stream.try_clone()?;
            
            // Frame the packet with length prefix
            let framed_data = self.framer.frame_packet(data)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            
            stream.write_all(&framed_data)?;
            Ok(())
        } else {
            Err("Not connected".into())
        }
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(ref stream) = self.stream.as_ref() {
            let mut stream = stream.try_clone()?;
            let mut temp_buffer = vec![0; 4096];
            
            // Read incoming data
            let bytes_read = stream.read(&mut temp_buffer)?;
            if bytes_read == 0 {
                return Err("Connection closed".into());
            }
            
            temp_buffer.truncate(bytes_read);
            
            // Add to packet buffer
            let mut packet_buffer = self.receive_buffer.lock().unwrap();
            packet_buffer.add_data(&temp_buffer)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            
            // Extract complete packets
            let packets = packet_buffer.extract_packets()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            
            if let Some(packet) = packets.into_iter().next() {
                Ok(packet)
            } else {
                Err("No complete packet available".into())
            }
        } else {
            Err("Not connected".into())
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}
