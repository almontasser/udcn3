use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub payload: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Data,
    Control,
    Heartbeat,
    Discovery,
}

pub trait Protocol {
    fn encode(&self, message: &Message) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn decode(&self, data: &[u8]) -> Result<Message, Box<dyn std::error::Error>>;
}
