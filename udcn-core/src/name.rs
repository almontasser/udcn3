use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComponentType {
    Generic,
    ImplicitSha256DigestComponent,
    ParametersSha256DigestComponent,
    KeywordNameComponent,
    SegmentNameComponent,
    ByteOffsetNameComponent,
    VersionNameComponent,
    TimestampNameComponent,
    SequenceNumNameComponent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameComponent {
    pub value: Vec<u8>,
    pub component_type: ComponentType,
    pub metadata: HashMap<String, String>,
}

impl NameComponent {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value,
            component_type: ComponentType::Generic,
            metadata: HashMap::new(),
        }
    }

    pub fn with_type(value: Vec<u8>, component_type: ComponentType) -> Self {
        Self {
            value,
            component_type,
            metadata: HashMap::new(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }

    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.value)
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    pub fn is_type(&self, component_type: &ComponentType) -> bool {
        &self.component_type == component_type
    }
}

impl fmt::Display for NameComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "{:?}", self.value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Name {
    pub components: Vec<NameComponent>,
}

impl Name {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn from_str(name: &str) -> Result<Self, NameParseError> {
        let mut components = Vec::new();
        
        if name.is_empty() {
            return Ok(Self::new());
        }

        let parts: Vec<&str> = if name.starts_with('/') {
            name[1..].split('/').collect()
        } else {
            name.split('/').collect()
        };

        for part in parts {
            if !part.is_empty() {
                components.push(NameComponent::from_str(part));
            }
        }

        Ok(Self { components })
    }

    pub fn push(&mut self, component: NameComponent) {
        self.components.push(component);
    }

    pub fn append(&mut self, name: &str) -> Result<(), NameParseError> {
        let name_to_append = Name::from_str(name)?;
        self.components.extend(name_to_append.components);
        Ok(())
    }

    pub fn append_component(&mut self, component: NameComponent) {
        self.components.push(component);
    }

    pub fn get_component(&self, index: usize) -> Option<&NameComponent> {
        self.components.get(index)
    }

    pub fn get_component_mut(&mut self, index: usize) -> Option<&mut NameComponent> {
        self.components.get_mut(index)
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    pub fn clear(&mut self) {
        self.components.clear();
    }

    pub fn pop(&mut self) -> Option<NameComponent> {
        self.components.pop()
    }

    pub fn get_prefix(&self, length: usize) -> Name {
        let end = std::cmp::min(length, self.components.len());
        Self {
            components: self.components[..end].to_vec(),
        }
    }

    pub fn get_suffix(&self, start: usize) -> Name {
        let start = std::cmp::min(start, self.components.len());
        Self {
            components: self.components[start..].to_vec(),
        }
    }

    pub fn to_uri(&self) -> String {
        if self.components.is_empty() {
            return "/".to_string();
        }

        let mut uri = String::new();
        for component in &self.components {
            uri.push('/');
            uri.push_str(&component.to_string());
        }
        uri
    }

    pub fn split_name(&self) -> NameComponents {
        NameComponents::from_name(self)
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

#[derive(Debug, Clone)]
pub struct NameComponents {
    pub first: Option<NameComponent>,
    pub middle: Vec<NameComponent>,
    pub last: Option<NameComponent>,
    pub prefix: Option<NameComponent>,
    pub suffix: Option<NameComponent>,
}

impl NameComponents {
    pub fn new() -> Self {
        Self {
            first: None,
            middle: Vec::new(),
            last: None,
            prefix: None,
            suffix: None,
        }
    }

    pub fn from_name(name: &Name) -> Self {
        let mut components = Self::new();
        
        if name.components.is_empty() {
            return components;
        }

        let len = name.components.len();
        
        if len == 1 {
            components.first = Some(name.components[0].clone());
        } else if len == 2 {
            components.first = Some(name.components[0].clone());
            components.last = Some(name.components[1].clone());
        } else {
            components.first = Some(name.components[0].clone());
            components.middle = name.components[1..len-1].to_vec();
            components.last = Some(name.components[len-1].clone());
        }

        components
    }

    pub fn reconstruct(&self) -> Name {
        let mut name = Name::new();
        
        if let Some(ref first) = self.first {
            name.push(first.clone());
        }
        
        for component in &self.middle {
            name.push(component.clone());
        }
        
        if let Some(ref last) = self.last {
            name.push(last.clone());
        }
        
        name
    }
}

impl Default for NameComponents {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameParseError {
    InvalidFormat,
    InvalidComponent,
    EncodingError,
}

impl fmt::Display for NameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameParseError::InvalidFormat => write!(f, "Invalid name format"),
            NameParseError::InvalidComponent => write!(f, "Invalid name component"),
            NameParseError::EncodingError => write!(f, "Name encoding error"),
        }
    }
}

impl std::error::Error for NameParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_component_creation() {
        let component = NameComponent::from_str("test");
        assert_eq!(component.as_str().unwrap(), "test");
        assert_eq!(component.component_type, ComponentType::Generic);
    }

    #[test]
    fn test_name_creation() {
        let name = Name::from_str("/hello/world/test").unwrap();
        assert_eq!(name.len(), 3);
        assert_eq!(name.get_component(0).unwrap().as_str().unwrap(), "hello");
        assert_eq!(name.get_component(1).unwrap().as_str().unwrap(), "world");
        assert_eq!(name.get_component(2).unwrap().as_str().unwrap(), "test");
    }

    #[test]
    fn test_name_to_uri() {
        let name = Name::from_str("/hello/world/test").unwrap();
        assert_eq!(name.to_uri(), "/hello/world/test");
    }

    #[test]
    fn test_name_prefix() {
        let name = Name::from_str("/hello/world/test").unwrap();
        let prefix = name.get_prefix(2);
        assert_eq!(prefix.len(), 2);
        assert_eq!(prefix.to_uri(), "/hello/world");
    }

    #[test]
    fn test_name_suffix() {
        let name = Name::from_str("/hello/world/test").unwrap();
        let suffix = name.get_suffix(1);
        assert_eq!(suffix.len(), 2);
        assert_eq!(suffix.to_uri(), "/world/test");
    }

    #[test]
    fn test_name_components_split() {
        let name = Name::from_str("/hello/world/test").unwrap();
        let components = name.split_name();
        assert_eq!(components.first.as_ref().unwrap().as_str().unwrap(), "hello");
        assert_eq!(components.middle.len(), 1);
        assert_eq!(components.middle[0].as_str().unwrap(), "world");
        assert_eq!(components.last.as_ref().unwrap().as_str().unwrap(), "test");
    }

    #[test]
    fn test_name_components_reconstruct() {
        let original = Name::from_str("/hello/world/test").unwrap();
        let components = original.split_name();
        let reconstructed = components.reconstruct();
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_empty_name() {
        let name = Name::from_str("").unwrap();
        assert!(name.is_empty());
        assert_eq!(name.to_uri(), "/");
    }

    #[test]
    fn test_single_component_name() {
        let name = Name::from_str("/hello").unwrap();
        assert_eq!(name.len(), 1);
        assert_eq!(name.to_uri(), "/hello");
    }
}