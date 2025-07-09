use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use log::info;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{
    benchmarks::PerformanceMonitor,
    traffic_generator::{TrafficGenerator, TrafficPattern},
};

// Import transport types and NDN packet types
use udcn_transport::{TcpTransport, UdpTransport};
use udcn_core::{Interest, Data, Packet};
use udcn_core::packets::Name;

/// Represents different network topology types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TopologyType {
    /// Linear chain topology
    Linear,
    /// Tree topology with configurable branching factor
    Tree { branching_factor: usize },
    /// Full mesh topology
    Mesh,
    /// Ring topology
    Ring,
    /// Star topology with central hub
    Star,
    /// Custom topology defined by adjacency list
    Custom { adjacency: HashMap<NodeId, Vec<NodeId>> },
}

/// Unique identifier for network nodes
pub type NodeId = String;

/// Network characteristics between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLink {
    pub latency: Duration,
    pub bandwidth_mbps: f64,
    pub packet_loss_rate: f64,
    pub jitter: Duration,
}

impl Default for NetworkLink {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(10),
            bandwidth_mbps: 100.0,
            packet_loss_rate: 0.001,
            jitter: Duration::from_millis(2),
        }
    }
}

/// Represents a node in the network topology
#[derive(Debug, Clone)]
pub struct TopologyNode {
    pub id: NodeId,
    pub position: (f64, f64), // x, y coordinates for visualization
    pub processing_delay: Duration,
    pub cache_size: usize,
    pub links: HashMap<NodeId, NetworkLink>,
}

impl TopologyNode {
    pub fn new(id: NodeId, position: (f64, f64)) -> Self {
        Self {
            id,
            position,
            processing_delay: Duration::from_micros(100),
            cache_size: 1000,
            links: HashMap::new(),
        }
    }

    pub fn add_link(&mut self, target_id: NodeId, link: NetworkLink) {
        self.links.insert(target_id, link);
    }
}

/// Network topology simulation framework
#[derive(Debug)]
pub struct TopologySimulator {
    nodes: HashMap<NodeId, TopologyNode>,
    topology_type: TopologyType,
    traffic_generator: TrafficGenerator,
    performance_monitor: PerformanceMonitor,
    routing_table: HashMap<NodeId, HashMap<NodeId, Vec<NodeId>>>, // source -> dest -> path
}

/// Results from topology simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySimulationResult {
    pub topology_type: String,
    pub node_count: usize,
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub average_path_length: f64,
    pub network_wide_latency: Duration,
    pub network_wide_throughput: f64,
    pub packet_delivery_ratio: f64,
    pub node_metrics: HashMap<NodeId, NodeMetrics>,
    pub duration: Duration,
}

/// Per-node performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub packets_forwarded: u64,
    pub packets_generated: u64,
    pub packets_dropped: u64,
    pub cache_hit_rate: f64,
    pub average_processing_time: Duration,
    pub link_utilizations: HashMap<NodeId, f64>,
}

impl TopologySimulator {
    pub fn new(topology_type: TopologyType) -> Self {
        Self {
            nodes: HashMap::new(),
            topology_type,
            traffic_generator: TrafficGenerator::new(),
            performance_monitor: PerformanceMonitor::new(1000, Duration::from_secs(1)),
            routing_table: HashMap::new(),
        }
    }

    /// Generate topology based on the specified type
    pub fn generate_topology(&mut self, node_count: usize) -> Result<(), Box<dyn std::error::Error>> {
        self.nodes.clear();
        
        match &self.topology_type {
            TopologyType::Linear => self.generate_linear_topology(node_count)?,
            TopologyType::Tree { branching_factor } => self.generate_tree_topology(node_count, *branching_factor)?,
            TopologyType::Mesh => self.generate_mesh_topology(node_count)?,
            TopologyType::Ring => self.generate_ring_topology(node_count)?,
            TopologyType::Star => self.generate_star_topology(node_count)?,
            TopologyType::Custom { adjacency } => self.generate_custom_topology(adjacency.clone())?,
        }

        self.compute_routing_table()?;
        info!("Generated {} topology with {} nodes", 
              self.topology_type_name(), self.nodes.len());

        Ok(())
    }

    fn generate_linear_topology(&mut self, node_count: usize) -> Result<(), Box<dyn std::error::Error>> {
        for i in 0..node_count {
            let node_id = format!("node_{}", i);
            let position = (i as f64 * 100.0, 0.0);
            let mut node = TopologyNode::new(node_id.clone(), position);

            // Connect to previous and next nodes
            if i > 0 {
                let prev_id = format!("node_{}", i - 1);
                node.add_link(prev_id.clone(), NetworkLink::default());
            }
            if i < node_count - 1 {
                let next_id = format!("node_{}", i + 1);
                node.add_link(next_id.clone(), NetworkLink::default());
            }

            self.nodes.insert(node_id, node);
        }
        Ok(())
    }

    fn generate_tree_topology(&mut self, node_count: usize, branching_factor: usize) -> Result<(), Box<dyn std::error::Error>> {
        if node_count == 0 {
            return Ok(());
        }

        // Create root node
        let root_id = "node_0".to_string();
        let root_node = TopologyNode::new(root_id.clone(), (0.0, 0.0));
        self.nodes.insert(root_id.clone(), root_node);

        let mut node_queue = VecDeque::new();
        node_queue.push_back((root_id, 0, 0)); // (node_id, level, index_in_level)

        let mut node_counter = 1;

        while !node_queue.is_empty() && node_counter < node_count {
            let (parent_id, level, _) = node_queue.pop_front().unwrap();

            for child_index in 0..branching_factor {
                if node_counter >= node_count {
                    break;
                }

                let child_id = format!("node_{}", node_counter);
                let position = (
                    (child_index as f64 - (branching_factor as f64 - 1.0) / 2.0) * 100.0,
                    (level + 1) as f64 * 100.0,
                );
                
                let mut child_node = TopologyNode::new(child_id.clone(), position);
                child_node.add_link(parent_id.clone(), NetworkLink::default());

                // Add link from parent to child
                if let Some(parent_node) = self.nodes.get_mut(&parent_id) {
                    parent_node.add_link(child_id.clone(), NetworkLink::default());
                }

                node_queue.push_back((child_id.clone(), level + 1, child_index));
                self.nodes.insert(child_id, child_node);
                node_counter += 1;
            }
        }

        Ok(())
    }

    fn generate_mesh_topology(&mut self, node_count: usize) -> Result<(), Box<dyn std::error::Error>> {
        // Create nodes in a grid pattern
        let grid_size = (node_count as f64).sqrt().ceil() as usize;
        
        for i in 0..node_count {
            let node_id = format!("node_{}", i);
            let x = (i % grid_size) as f64 * 100.0;
            let y = (i / grid_size) as f64 * 100.0;
            let position = (x, y);
            
            let node = TopologyNode::new(node_id.clone(), position);
            self.nodes.insert(node_id, node);
        }

        // Connect every node to every other node
        let node_ids: Vec<NodeId> = self.nodes.keys().cloned().collect();
        for i in 0..node_ids.len() {
            for j in 0..node_ids.len() {
                if i != j {
                    let link = NetworkLink::default();
                    if let Some(node) = self.nodes.get_mut(&node_ids[i]) {
                        node.add_link(node_ids[j].clone(), link);
                    }
                }
            }
        }

        Ok(())
    }

    fn generate_ring_topology(&mut self, node_count: usize) -> Result<(), Box<dyn std::error::Error>> {
        let radius = 200.0;
        
        for i in 0..node_count {
            let node_id = format!("node_{}", i);
            let angle = 2.0 * std::f64::consts::PI * i as f64 / node_count as f64;
            let x = radius * angle.cos();
            let y = radius * angle.sin();
            let position = (x, y);
            
            let mut node = TopologyNode::new(node_id.clone(), position);

            // Connect to next and previous nodes in ring
            let prev_id = format!("node_{}", (i + node_count - 1) % node_count);
            let next_id = format!("node_{}", (i + 1) % node_count);
            
            node.add_link(prev_id, NetworkLink::default());
            node.add_link(next_id, NetworkLink::default());

            self.nodes.insert(node_id, node);
        }

        Ok(())
    }

    fn generate_star_topology(&mut self, node_count: usize) -> Result<(), Box<dyn std::error::Error>> {
        if node_count == 0 {
            return Ok(());
        }

        // Create central hub
        let hub_id = "hub".to_string();
        let mut hub_node = TopologyNode::new(hub_id.clone(), (0.0, 0.0));
        
        // Create spoke nodes
        for i in 1..node_count {
            let spoke_id = format!("node_{}", i);
            let angle = 2.0 * std::f64::consts::PI * (i - 1) as f64 / (node_count - 1) as f64;
            let radius = 200.0;
            let x = radius * angle.cos();
            let y = radius * angle.sin();
            let position = (x, y);
            
            let mut spoke_node = TopologyNode::new(spoke_id.clone(), position);
            spoke_node.add_link(hub_id.clone(), NetworkLink::default());
            hub_node.add_link(spoke_id.clone(), NetworkLink::default());
            
            self.nodes.insert(spoke_id, spoke_node);
        }

        self.nodes.insert(hub_id, hub_node);
        Ok(())
    }

    fn generate_custom_topology(&mut self, adjacency: HashMap<NodeId, Vec<NodeId>>) -> Result<(), Box<dyn std::error::Error>> {
        // Create all nodes first
        for node_id in adjacency.keys() {
            let position = (fastrand::f64() * 500.0, fastrand::f64() * 500.0); // Random positions
            let node = TopologyNode::new(node_id.clone(), position);
            self.nodes.insert(node_id.clone(), node);
        }

        // Add links based on adjacency list
        for (node_id, neighbors) in adjacency {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                for neighbor in neighbors {
                    node.add_link(neighbor, NetworkLink::default());
                }
            }
        }

        Ok(())
    }

    fn compute_routing_table(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.routing_table.clear();
        
        // Use Floyd-Warshall algorithm to compute shortest paths
        let node_ids: Vec<NodeId> = self.nodes.keys().cloned().collect();
        let n = node_ids.len();
        
        // Initialize distance and next hop matrices
        let mut dist = vec![vec![f64::INFINITY; n]; n];
        let mut next = vec![vec![None; n]; n];
        
        // Initialize distances
        for i in 0..n {
            dist[i][i] = 0.0;
            for j in 0..n {
                if i != j {
                    if let Some(node) = self.nodes.get(&node_ids[i]) {
                        if node.links.contains_key(&node_ids[j]) {
                            dist[i][j] = 1.0; // Hop count as distance
                            next[i][j] = Some(j);
                        }
                    }
                }
            }
        }
        
        // Floyd-Warshall
        for k in 0..n {
            for i in 0..n {
                for j in 0..n {
                    if dist[i][k] + dist[k][j] < dist[i][j] {
                        dist[i][j] = dist[i][k] + dist[k][j];
                        next[i][j] = next[i][k];
                    }
                }
            }
        }
        
        // Build routing table
        for i in 0..n {
            let mut routes = HashMap::new();
            for j in 0..n {
                if i != j && dist[i][j] < f64::INFINITY {
                    let mut path = vec![node_ids[i].clone()];
                    let mut current = i;
                    while current != j {
                        if let Some(next_hop) = next[current][j] {
                            current = next_hop;
                            path.push(node_ids[current].clone());
                        } else {
                            break;
                        }
                    }
                    routes.insert(node_ids[j].clone(), path);
                }
            }
            self.routing_table.insert(node_ids[i].clone(), routes);
        }
        
        Ok(())
    }

    /// Run traffic simulation across the topology
    pub async fn simulate_traffic(
        &mut self,
        traffic_pattern: &str,
        duration: Duration,
        source_nodes: Option<Vec<NodeId>>,
        destination_nodes: Option<Vec<NodeId>>,
    ) -> Result<TopologySimulationResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut total_packets_sent = 0u64;
        let mut total_packets_received = 0u64;
        let mut node_metrics = HashMap::new();
        
        info!("Starting topology simulation with {} pattern for {:?}", 
              traffic_pattern, duration);

        // Get traffic profile
        let profile = self.traffic_generator.get_profile(traffic_pattern)
            .ok_or_else(|| format!("Traffic pattern '{}' not found", traffic_pattern))?;

        // Determine source and destination nodes
        let sources = source_nodes.unwrap_or_else(|| {
            self.nodes.keys().take(self.nodes.len() / 4).cloned().collect()
        });
        let destinations = destination_nodes.unwrap_or_else(|| {
            self.nodes.keys().skip(self.nodes.len() / 2).cloned().collect()
        });

        // Initialize node metrics
        for node_id in self.nodes.keys() {
            node_metrics.insert(node_id.clone(), NodeMetrics {
                packets_forwarded: 0,
                packets_generated: 0,
                packets_dropped: 0,
                cache_hit_rate: 0.0,
                average_processing_time: Duration::from_secs(0),
                link_utilizations: HashMap::new(),
            });
        }

        // Simulate traffic flows
        let simulation_end = start_time + duration;
        let mut path_lengths = Vec::new();

        while Instant::now() < simulation_end {
            for source in &sources {
                for destination in &destinations {
                    if source != destination {
                        // Find path from source to destination
                        if let Some(source_routes) = self.routing_table.get(source) {
                            if let Some(path) = source_routes.get(destination) {
                                // Simulate packet transmission along path
                                let packet_result = self.simulate_packet_transmission(
                                    source,
                                    destination,
                                    path,
                                    &profile.patterns[0],
                                ).await;

                                match packet_result {
                                    Ok(delivered) => {
                                        total_packets_sent += 1;
                                        if delivered {
                                            total_packets_received += 1;
                                        }
                                        path_lengths.push(path.len() as f64);

                                        // Update node metrics along path
                                        for (i, node_id) in path.iter().enumerate() {
                                            if let Some(metrics) = node_metrics.get_mut(node_id) {
                                                if i == 0 {
                                                    metrics.packets_generated += 1;
                                                } else if i == path.len() - 1 {
                                                    // Destination node
                                                } else {
                                                    metrics.packets_forwarded += 1;
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        total_packets_sent += 1;
                                        // Update dropped packets for nodes in path
                                        for node_id in path {
                                            if let Some(metrics) = node_metrics.get_mut(node_id) {
                                                metrics.packets_dropped += 1;
                                                break; // Only count as dropped once
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Small delay to prevent overwhelming the simulation
            sleep(Duration::from_millis(1)).await;
        }

        let simulation_duration = start_time.elapsed();
        let average_path_length = if !path_lengths.is_empty() {
            path_lengths.iter().sum::<f64>() / path_lengths.len() as f64
        } else {
            0.0
        };

        let packet_delivery_ratio = if total_packets_sent > 0 {
            total_packets_received as f64 / total_packets_sent as f64
        } else {
            0.0
        };

        let network_wide_throughput = total_packets_received as f64 / simulation_duration.as_secs_f64();

        // Calculate network-wide latency (simplified)
        let network_wide_latency = Duration::from_millis(
            (average_path_length * 10.0) as u64 // 10ms per hop as approximation
        );

        info!("Simulation completed. Sent: {}, Received: {}, PDR: {:.2}%",
              total_packets_sent, total_packets_received, packet_delivery_ratio * 100.0);

        Ok(TopologySimulationResult {
            topology_type: self.topology_type_name(),
            node_count: self.nodes.len(),
            total_packets_sent,
            total_packets_received,
            average_path_length,
            network_wide_latency,
            network_wide_throughput,
            packet_delivery_ratio,
            node_metrics,
            duration: simulation_duration,
        })
    }

    async fn simulate_packet_transmission(
        &self,
        _source: &NodeId,
        _destination: &NodeId,
        path: &[NodeId],
        pattern: &TrafficPattern,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Simulate transmission delay along the path
        let mut total_delay = Duration::from_secs(0);

        for i in 0..path.len() - 1 {
            let current_node = &path[i];
            let next_node = &path[i + 1];

            if let Some(node) = self.nodes.get(current_node) {
                if let Some(link) = node.links.get(next_node) {
                    // Add processing delay
                    total_delay += node.processing_delay;
                    
                    // Add network delay
                    total_delay += link.latency;
                    
                    // Add jitter
                    total_delay += link.jitter;
                    
                    // Check for packet loss
                    if fastrand::f64() < link.packet_loss_rate {
                        return Ok(false); // Packet lost
                    }
                }
            }
        }

        // Simulate transmission time based on packet size and bandwidth
        let transmission_time = Duration::from_micros(
            (pattern.payload_size_bytes as f64 * 8.0 / 1_000_000.0 * 1_000_000.0) as u64
        );

        total_delay += transmission_time;

        // Simulate the actual delay
        sleep(Duration::from_micros(total_delay.as_micros() as u64 / 1000)).await;

        Ok(true) // Packet delivered successfully
    }

    fn topology_type_name(&self) -> String {
        match &self.topology_type {
            TopologyType::Linear => "Linear".to_string(),
            TopologyType::Tree { branching_factor } => format!("Tree({})", branching_factor),
            TopologyType::Mesh => "Mesh".to_string(),
            TopologyType::Ring => "Ring".to_string(),
            TopologyType::Star => "Star".to_string(),
            TopologyType::Custom { .. } => "Custom".to_string(),
        }
    }

    pub fn get_topology_stats(&self) -> (usize, usize) {
        let node_count = self.nodes.len();
        let edge_count: usize = self.nodes.values().map(|node| node.links.len()).sum();
        (node_count, edge_count / 2) // Divide by 2 for undirected edges
    }

    pub fn export_topology_dot(&self) -> String {
        let mut dot = String::from("graph topology {\n");
        dot.push_str("  node [shape=circle];\n");
        
        for (node_id, node) in &self.nodes {
            dot.push_str(&format!("  \"{}\" [pos=\"{},{}\"];\n", 
                                  node_id, node.position.0, node.position.1));
        }
        
        let mut edges = std::collections::HashSet::new();
        for (node_id, node) in &self.nodes {
            for neighbor_id in node.links.keys() {
                let edge = if node_id < neighbor_id {
                    (node_id.clone(), neighbor_id.clone())
                } else {
                    (neighbor_id.clone(), node_id.clone())
                };
                edges.insert(edge);
            }
        }
        
        for (node1, node2) in edges {
            dot.push_str(&format!("  \"{}\" -- \"{}\";\n", node1, node2));
        }
        
        dot.push_str("}\n");
        dot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_linear_topology_generation() {
        let mut simulator = TopologySimulator::new(TopologyType::Linear);
        simulator.generate_topology(5).unwrap();
        
        let (node_count, edge_count) = simulator.get_topology_stats();
        assert_eq!(node_count, 5);
        assert_eq!(edge_count, 4); // Linear topology has n-1 edges
    }

    #[tokio::test]
    async fn test_star_topology_generation() {
        let mut simulator = TopologySimulator::new(TopologyType::Star);
        simulator.generate_topology(6).unwrap();
        
        let (node_count, edge_count) = simulator.get_topology_stats();
        assert_eq!(node_count, 6);
        assert_eq!(edge_count, 5); // Star topology has n-1 edges
    }

    #[tokio::test]
    async fn test_traffic_simulation() {
        let mut simulator = TopologySimulator::new(TopologyType::Linear);
        simulator.generate_topology(3).unwrap();
        
        let result = simulator.simulate_traffic(
            "ndn_interest_data",
            Duration::from_millis(100),
            Some(vec!["node_0".to_string()]),
            Some(vec!["node_2".to_string()]),
        ).await.unwrap();
        
        assert!(result.total_packets_sent > 0);
        assert_eq!(result.node_count, 3);
    }
}