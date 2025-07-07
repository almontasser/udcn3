use std::os::unix::net::UnixStream;
use std::io::{Read, Write};
use crate::Transport;

pub struct UnixTransport {
    stream: Option<UnixStream>,
}

impl UnixTransport {
    pub fn new() -> Self {
        Self { stream: None }
    }

    pub fn connect(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let stream = UnixStream::connect(path)?;
        self.stream = Some(stream);
        Ok(())
    }
}

impl Transport for UnixTransport {
    fn send(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref stream) = self.stream.as_ref() {
            let mut stream = stream.try_clone()?;
            stream.write_all(data)?;
            Ok(())
        } else {
            Err("Not connected".into())
        }
    }

    fn receive(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(ref stream) = self.stream.as_ref() {
            let mut stream = stream.try_clone()?;
            let mut buffer = vec![0; 1024];
            let bytes_read = stream.read(&mut buffer)?;
            buffer.truncate(bytes_read);
            Ok(buffer)
        } else {
            Err("Not connected".into())
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

impl Default for UnixTransport {
    fn default() -> Self {
        Self::new()
    }
}