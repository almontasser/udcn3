use std::{collections::HashMap, net::SocketAddr};

pub struct NetworkNode {
    pub id: String,
    pub address: SocketAddr,
    pub capabilities: Vec<String>,
}

pub struct NetworkManager {
    nodes: HashMap<String, NetworkNode>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: NetworkNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn get_node(&self, id: &str) -> Option<&NetworkNode> {
        self.nodes.get(id)
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}
