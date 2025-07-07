use std::net::UdpSocket;
use crate::Transport;

pub struct UdpTransport {
    socket: Option<UdpSocket>,
    peer_addr: Option<String>,
}

impl UdpTransport {
    pub fn new() -> Self {
        Self { 
            socket: None,
            peer_addr: None,
        }
    }

    pub fn bind(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr)?;
        self.socket = Some(socket);
        Ok(())
    }

    pub fn connect(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.peer_addr = Some(addr.to_string());
        Ok(())
    }
}

impl Transport for UdpTransport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if let (Some(ref socket), Some(ref addr)) = (&self.socket, &self.peer_addr) {
            socket.send_to(data, addr)?;
            Ok(())
        } else {
            Err("Not connected".into())
        }
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(ref socket) = self.socket {
            let mut buffer = vec![0; 1024];
            let (bytes_read, _) = socket.recv_from(&mut buffer)?;
            buffer.truncate(bytes_read);
            Ok(buffer)
        } else {
            Err("Not bound".into())
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

impl Default for UdpTransport {
    fn default() -> Self {
        Self::new()
    }
}