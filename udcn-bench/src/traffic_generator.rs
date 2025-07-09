use std::time::{Duration, Instant};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::time::sleep;
use serde::{Deserialize, Serialize};
use log::{debug, info, warn};

use udcn_core::{Interest, Data, Packet};
use udcn_core::packets::Name;
use udcn_transport::{TcpTransport, UdpTransport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPattern {
    pub name: String,
    pub packet_rate: f64,
    pub burst_size: Option<usize>,
    pub burst_interval: Option<Duration>,
    pub payload_size_bytes: usize,
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficProfile {
    pub name: String,
    pub patterns: Vec<TrafficPattern>,
    pub concurrent_flows: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficGenerationResult {
    pub pattern_name: String,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub duration: Duration,
    pub actual_rate: f64,
    pub errors: u64,
    pub latency_samples: Vec<Duration>,
}

#[derive(Debug)]
pub struct TrafficGenerator {
    profiles: HashMap<String, TrafficProfile>,
    active_flows: Arc<Mutex<HashMap<String, bool>>>,
}

impl TrafficGenerator {
    pub fn new() -> Self {
        let mut generator = Self {
            profiles: HashMap::new(),
            active_flows: Arc::new(Mutex::new(HashMap::new())),
        };
        
        // Initialize with default profiles
        generator.add_default_profiles();
        generator
    }

    pub fn add_profile(&mut self, profile: TrafficProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    pub fn get_profile(&self, name: &str) -> Option<&TrafficProfile> {
        self.profiles.get(name)
    }

    pub fn list_profiles(&self) -> Vec<&String> {
        self.profiles.keys().collect()
    }

    fn add_default_profiles(&mut self) {
        // NDN Interest/Data pattern
        let ndn_pattern = TrafficProfile {
            name: "ndn_interest_data".to_string(),
            patterns: vec![
                TrafficPattern {
                    name: "interest_requests".to_string(),
                    packet_rate: 1000.0,
                    burst_size: None,
                    burst_interval: None,
                    payload_size_bytes: 256,
                    duration: Duration::from_secs(10),
                },
                TrafficPattern {
                    name: "data_responses".to_string(),
                    packet_rate: 1000.0,
                    burst_size: None,
                    burst_interval: None,
                    payload_size_bytes: 1024,
                    duration: Duration::from_secs(10),
                },
            ],
            concurrent_flows: 10,
        };
        
        // HTTP-like pattern
        let http_pattern = TrafficProfile {
            name: "http_like".to_string(),
            patterns: vec![
                TrafficPattern {
                    name: "http_requests".to_string(),
                    packet_rate: 100.0,
                    burst_size: Some(10),
                    burst_interval: Some(Duration::from_millis(100)),
                    payload_size_bytes: 512,
                    duration: Duration::from_secs(30),
                },
            ],
            concurrent_flows: 5,
        };
        
        // High-throughput pattern
        let high_throughput_pattern = TrafficProfile {
            name: "high_throughput".to_string(),
            patterns: vec![
                TrafficPattern {
                    name: "bulk_transfer".to_string(),
                    packet_rate: 10000.0,
                    burst_size: Some(100),
                    burst_interval: Some(Duration::from_millis(10)),
                    payload_size_bytes: 4096,
                    duration: Duration::from_secs(60),
                },
            ],
            concurrent_flows: 20,
        };
        
        self.add_profile(ndn_pattern);
        self.add_profile(http_pattern);
        self.add_profile(high_throughput_pattern);
    }

    pub async fn generate_ndn_interest_traffic(
        &self,
        pattern: &TrafficPattern,
        name_prefix: &str,
    ) -> Result<TrafficGenerationResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut bytes_sent = 0u64;
        let mut errors = 0u64;
        let mut latency_samples = Vec::new();
        
        let packet_interval = Duration::from_secs_f64(1.0 / pattern.packet_rate);
        let mut next_packet_time = start_time;
        
        info!("Starting NDN Interest traffic generation: {}", pattern.name);
        
        while start_time.elapsed() < pattern.duration {
            let packet_start = Instant::now();
            
            // Create Interest packet
            let name = Name::from_str(&format!("{}/chunk/{}", name_prefix, packets_sent));
            let interest = Interest::new(name);
            let packet = Packet::Interest(interest);
            
            // Simulate network transmission
            match self.send_ndn_packet(&packet).await {
                Ok(response_size) => {
                    packets_sent += 1;
                    bytes_sent += response_size as u64;
                    
                    let latency = packet_start.elapsed();
                    latency_samples.push(latency);
                    
                    if packets_sent % 1000 == 0 {
                        debug!("Sent {} Interest packets", packets_sent);
                    }
                },
                Err(e) => {
                    errors += 1;
                    warn!("Failed to send Interest packet: {}", e);
                }
            }
            
            // Handle burst traffic
            if let Some(burst_size) = pattern.burst_size {
                if packets_sent % burst_size as u64 == 0 {
                    if let Some(burst_interval) = pattern.burst_interval {
                        sleep(burst_interval).await;
                    }
                }
            }
            
            // Wait for next packet time
            next_packet_time += packet_interval;
            let now = Instant::now();
            if next_packet_time > now {
                sleep(next_packet_time - now).await;
            }
        }
        
        let total_duration = start_time.elapsed();
        let actual_rate = packets_sent as f64 / total_duration.as_secs_f64();
        
        info!("Completed NDN Interest traffic generation. Packets: {}, Rate: {:.2}/s, Errors: {}", 
              packets_sent, actual_rate, errors);
        
        Ok(TrafficGenerationResult {
            pattern_name: pattern.name.clone(),
            packets_sent,
            bytes_sent,
            duration: total_duration,
            actual_rate,
            errors,
            latency_samples,
        })
    }

    pub async fn generate_ndn_data_traffic(
        &self,
        pattern: &TrafficPattern,
        name_prefix: &str,
    ) -> Result<TrafficGenerationResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut bytes_sent = 0u64;
        let mut errors = 0u64;
        let mut latency_samples = Vec::new();
        
        let packet_interval = Duration::from_secs_f64(1.0 / pattern.packet_rate);
        let mut next_packet_time = start_time;
        
        info!("Starting NDN Data traffic generation: {}", pattern.name);
        
        while start_time.elapsed() < pattern.duration {
            let packet_start = Instant::now();
            
            // Create Data packet
            let name = Name::from_str(&format!("{}/data/{}", name_prefix, packets_sent));
            let content = vec![0u8; pattern.payload_size_bytes];
            let data = Data::new(name, content);
            let packet = Packet::Data(data);
            
            // Simulate network transmission
            match self.send_ndn_packet(&packet).await {
                Ok(response_size) => {
                    packets_sent += 1;
                    bytes_sent += response_size as u64;
                    
                    let latency = packet_start.elapsed();
                    latency_samples.push(latency);
                    
                    if packets_sent % 1000 == 0 {
                        debug!("Sent {} Data packets", packets_sent);
                    }
                },
                Err(e) => {
                    errors += 1;
                    warn!("Failed to send Data packet: {}", e);
                }
            }
            
            // Handle burst traffic
            if let Some(burst_size) = pattern.burst_size {
                if packets_sent % burst_size as u64 == 0 {
                    if let Some(burst_interval) = pattern.burst_interval {
                        sleep(burst_interval).await;
                    }
                }
            }
            
            // Wait for next packet time
            next_packet_time += packet_interval;
            let now = Instant::now();
            if next_packet_time > now {
                sleep(next_packet_time - now).await;
            }
        }
        
        let total_duration = start_time.elapsed();
        let actual_rate = packets_sent as f64 / total_duration.as_secs_f64();
        
        info!("Completed NDN Data traffic generation. Packets: {}, Rate: {:.2}/s, Errors: {}", 
              packets_sent, actual_rate, errors);
        
        Ok(TrafficGenerationResult {
            pattern_name: pattern.name.clone(),
            packets_sent,
            bytes_sent,
            duration: total_duration,
            actual_rate,
            errors,
            latency_samples,
        })
    }

    pub async fn generate_tcp_traffic(
        &self,
        pattern: &TrafficPattern,
        target_addr: &str,
    ) -> Result<TrafficGenerationResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut bytes_sent = 0u64;
        let mut errors = 0u64;
        let mut latency_samples = Vec::new();
        
        let packet_interval = Duration::from_secs_f64(1.0 / pattern.packet_rate);
        let mut next_packet_time = start_time;
        
        info!("Starting TCP traffic generation: {}", pattern.name);
        
        // Create TCP transport
        let transport = TcpTransport::new();
        
        while start_time.elapsed() < pattern.duration {
            let packet_start = Instant::now();
            
            // Create payload
            let payload = vec![0u8; pattern.payload_size_bytes];
            
            // Simulate TCP send
            match self.send_tcp_data(&transport, target_addr, &payload).await {
                Ok(sent_bytes) => {
                    packets_sent += 1;
                    bytes_sent += sent_bytes as u64;
                    
                    let latency = packet_start.elapsed();
                    latency_samples.push(latency);
                    
                    if packets_sent % 1000 == 0 {
                        debug!("Sent {} TCP packets", packets_sent);
                    }
                },
                Err(e) => {
                    errors += 1;
                    warn!("Failed to send TCP packet: {}", e);
                }
            }
            
            // Handle burst traffic
            if let Some(burst_size) = pattern.burst_size {
                if packets_sent % burst_size as u64 == 0 {
                    if let Some(burst_interval) = pattern.burst_interval {
                        sleep(burst_interval).await;
                    }
                }
            }
            
            // Wait for next packet time
            next_packet_time += packet_interval;
            let now = Instant::now();
            if next_packet_time > now {
                sleep(next_packet_time - now).await;
            }
        }
        
        let total_duration = start_time.elapsed();
        let actual_rate = packets_sent as f64 / total_duration.as_secs_f64();
        
        info!("Completed TCP traffic generation. Packets: {}, Rate: {:.2}/s, Errors: {}", 
              packets_sent, actual_rate, errors);
        
        Ok(TrafficGenerationResult {
            pattern_name: pattern.name.clone(),
            packets_sent,
            bytes_sent,
            duration: total_duration,
            actual_rate,
            errors,
            latency_samples,
        })
    }

    pub async fn generate_udp_traffic(
        &self,
        pattern: &TrafficPattern,
        target_addr: &str,
    ) -> Result<TrafficGenerationResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut bytes_sent = 0u64;
        let mut errors = 0u64;
        let mut latency_samples = Vec::new();
        
        let packet_interval = Duration::from_secs_f64(1.0 / pattern.packet_rate);
        let mut next_packet_time = start_time;
        
        info!("Starting UDP traffic generation: {}", pattern.name);
        
        // Create UDP transport
        let transport = UdpTransport::new();
        
        while start_time.elapsed() < pattern.duration {
            let packet_start = Instant::now();
            
            // Create payload
            let payload = vec![0u8; pattern.payload_size_bytes];
            
            // Simulate UDP send
            match self.send_udp_data(&transport, target_addr, &payload).await {
                Ok(sent_bytes) => {
                    packets_sent += 1;
                    bytes_sent += sent_bytes as u64;
                    
                    let latency = packet_start.elapsed();
                    latency_samples.push(latency);
                    
                    if packets_sent % 1000 == 0 {
                        debug!("Sent {} UDP packets", packets_sent);
                    }
                },
                Err(e) => {
                    errors += 1;
                    warn!("Failed to send UDP packet: {}", e);
                }
            }
            
            // Handle burst traffic
            if let Some(burst_size) = pattern.burst_size {
                if packets_sent % burst_size as u64 == 0 {
                    if let Some(burst_interval) = pattern.burst_interval {
                        sleep(burst_interval).await;
                    }
                }
            }
            
            // Wait for next packet time
            next_packet_time += packet_interval;
            let now = Instant::now();
            if next_packet_time > now {
                sleep(next_packet_time - now).await;
            }
        }
        
        let total_duration = start_time.elapsed();
        let actual_rate = packets_sent as f64 / total_duration.as_secs_f64();
        
        info!("Completed UDP traffic generation. Packets: {}, Rate: {:.2}/s, Errors: {}", 
              packets_sent, actual_rate, errors);
        
        Ok(TrafficGenerationResult {
            pattern_name: pattern.name.clone(),
            packets_sent,
            bytes_sent,
            duration: total_duration,
            actual_rate,
            errors,
            latency_samples,
        })
    }

    async fn send_ndn_packet(&self, packet: &Packet) -> Result<usize, Box<dyn std::error::Error>> {
        // Simulate NDN packet transmission with realistic delay
        let base_delay = Duration::from_micros(100);
        let jitter = Duration::from_micros(fastrand::u64(0..50));
        sleep(base_delay + jitter).await;
        
        // Simulate response size based on packet type
        let response_size = match packet {
            Packet::Interest(_) => 64, // Interest acknowledgment
            Packet::Data(data) => data.content.len() + 128, // Data packet + headers
        };
        
        // Simulate occasional network errors
        if fastrand::f64() < 0.001 {
            return Err("Network timeout".into());
        }
        
        Ok(response_size)
    }

    async fn send_tcp_data(
        &self,
        _transport: &TcpTransport,
        _target_addr: &str,
        payload: &[u8],
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // Simulate TCP transmission with realistic delay
        let base_delay = Duration::from_micros(200);
        let jitter = Duration::from_micros(fastrand::u64(0..100));
        sleep(base_delay + jitter).await;
        
        // Simulate occasional network errors
        if fastrand::f64() < 0.002 {
            return Err("TCP connection error".into());
        }
        
        Ok(payload.len())
    }

    async fn send_udp_data(
        &self,
        _transport: &UdpTransport,
        _target_addr: &str,
        payload: &[u8],
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // Simulate UDP transmission with realistic delay
        let base_delay = Duration::from_micros(50);
        let jitter = Duration::from_micros(fastrand::u64(0..25));
        sleep(base_delay + jitter).await;
        
        // Simulate occasional packet loss
        if fastrand::f64() < 0.005 {
            return Err("UDP packet loss".into());
        }
        
        Ok(payload.len())
    }
}

impl Default for TrafficGenerator {
    fn default() -> Self {
        Self::new()
    }
}