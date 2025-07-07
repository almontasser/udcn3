use std::collections::HashMap;

pub struct SecurityContext {
    pub node_id: String,
    pub keys: HashMap<String, Vec<u8>>,
    pub permissions: Vec<String>,
}

impl SecurityContext {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            keys: HashMap::new(),
            permissions: Vec::new(),
        }
    }

    pub fn add_key(&mut self, key_id: String, key_data: Vec<u8>) {
        self.keys.insert(key_id, key_data);
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}