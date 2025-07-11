use crate::tlv::{TlvElement, TlvError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// TLV Type constants for NDN packets
pub mod tlv_types {
    pub const INTEREST: u8 = 0x05;
    pub const DATA: u8 = 0x06;
    pub const NAME: u8 = 0x07;
    pub const NAME_COMPONENT: u8 = 0x08;
    pub const IMPLICIT_SHA256_DIGEST_COMPONENT: u8 = 0x01;
    pub const PARAMETERS_SHA256_DIGEST_COMPONENT: u8 = 0x02;
    pub const SELECTORS: u8 = 0x09;
    pub const NONCE: u8 = 0x0A;
    pub const INTEREST_LIFETIME: u8 = 0x0C;
    pub const MIN_SUFFIX_COMPONENTS: u8 = 0x0D;
    pub const MAX_SUFFIX_COMPONENTS: u8 = 0x0E;
    pub const PUBLISHER_PUBLIC_KEY_LOCATOR: u8 = 0x0F;
    pub const EXCLUDE: u8 = 0x10;
    pub const CHILD_SELECTOR: u8 = 0x11;
    pub const MUST_BE_FRESH: u8 = 0x12;
    pub const ANY: u8 = 0x13;
    pub const META_INFO: u8 = 0x14;
    pub const CONTENT: u8 = 0x15;
    pub const SIGNATURE_INFO: u8 = 0x16;
    pub const SIGNATURE_VALUE: u8 = 0x17;
    pub const CONTENT_TYPE: u8 = 0x18;
    pub const FRESHNESS_PERIOD: u8 = 0x19;
    pub const FINAL_BLOCK_ID: u8 = 0x1A;
    pub const SIGNATURE_TYPE: u8 = 0x1B;
    pub const KEY_LOCATOR: u8 = 0x1C;
    pub const KEY_DIGEST: u8 = 0x1D;
    pub const HOP_LIMIT: u8 = 0x22;
    pub const APPLICATION_PARAMETERS: u8 = 0x24;
}

/// Represents a hierarchical name in the NDN network
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Name {
    pub components: Vec<Vec<u8>>,
}

impl Name {
    /// Create a new empty name
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Create a name from a string path (e.g., "/hello/world")
    pub fn from_str(path: &str) -> Self {
        let mut name = Name::new();
        if path.starts_with('/') && path.len() > 1 {
            for component in path[1..].split('/') {
                if !component.is_empty() {
                    name.components.push(component.as_bytes().to_vec());
                }
            }
        }
        name
    }

    /// Append a component to the name
    pub fn append(&mut self, component: Vec<u8>) -> &mut Self {
        self.components.push(component);
        self
    }

    /// Append a string component to the name
    pub fn append_str(&mut self, component: &str) -> &mut Self {
        self.components.push(component.as_bytes().to_vec());
        self
    }

    /// Prepend a component to the name
    pub fn prepend(&mut self, component: Vec<u8>) -> &mut Self {
        self.components.insert(0, component);
        self
    }

    /// Get the number of components
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// Check if the name is empty
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Get a component by index
    pub fn get(&self, index: usize) -> Option<&Vec<u8>> {
        self.components.get(index)
    }

    /// Check if this name is a prefix of another name
    pub fn is_prefix_of(&self, other: &Name) -> bool {
        if self.len() > other.len() {
            return false;
        }
        self.components.iter().zip(other.components.iter()).all(|(a, b)| a == b)
    }

    /// Get a prefix of this name with the specified number of components
    pub fn get_prefix(&self, length: usize) -> Name {
        Name {
            components: self.components.iter().take(length).cloned().collect(),
        }
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        if self.is_empty() {
            return "/".to_string();
        }
        let mut result = String::new();
        for component in &self.components {
            result.push('/');
            // Simple UTF-8 conversion for display - in a real implementation,
            // this would handle percent-encoding for non-printable bytes
            result.push_str(&String::from_utf8_lossy(component));
        }
        result
    }

    /// Encode name to TLV format
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut components_tlv = Vec::new();
        
        for component in &self.components {
            let comp_element = TlvElement::new(tlv_types::NAME_COMPONENT, component.clone());
            comp_element.encode_to(&mut components_tlv)?;
        }
        
        let name_element = TlvElement::new(tlv_types::NAME, components_tlv);
        name_element.encode()
    }

    /// Decode name from TLV format
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TlvError> {
        let (name_element, consumed) = TlvElement::decode(data)?;
        
        if name_element.type_ != tlv_types::NAME {
            return Err(TlvError::InvalidType(name_element.type_));
        }
        
        let mut name = Name::new();
        let mut offset = 0;
        
        while offset < name_element.value.len() {
            let (comp_element, comp_consumed) = TlvElement::decode(&name_element.value[offset..])?;
            if !matches!(comp_element.type_, tlv_types::NAME_COMPONENT | tlv_types::IMPLICIT_SHA256_DIGEST_COMPONENT | tlv_types::PARAMETERS_SHA256_DIGEST_COMPONENT) {
                return Err(TlvError::InvalidType(comp_element.type_));
            }
            name.components.push(comp_element.value);
            offset += comp_consumed;
        }
        
        Ok((name, consumed))
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Selectors for Interest packets
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Selectors {
    pub min_suffix_components: Option<u32>,
    pub max_suffix_components: Option<u32>,
    pub publisher_public_key_locator: Option<KeyLocator>,
    pub exclude: Option<Exclude>,
    pub child_selector: Option<u8>,
    pub must_be_fresh: bool,
}

impl Default for Selectors {
    fn default() -> Self {
        Self {
            min_suffix_components: None,
            max_suffix_components: None,
            publisher_public_key_locator: None,
            exclude: None,
            child_selector: None,
            must_be_fresh: false,
        }
    }
}

/// Exclude filter for Interest packets
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exclude {
    pub components: Vec<Vec<u8>>,
}

/// Key locator for signatures
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyLocator {
    Name(Name),
    KeyDigest(Vec<u8>),
}

/// Interest packet structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Interest {
    pub name: Name,
    pub selectors: Option<Selectors>,
    pub nonce: Option<u32>,
    pub interest_lifetime: Option<Duration>,
    pub hop_limit: Option<u8>,
    pub application_parameters: Option<Vec<u8>>,
}

impl Interest {
    /// Create a new Interest with the given name
    pub fn new(name: Name) -> Self {
        Self {
            name,
            selectors: None,
            nonce: None,
            interest_lifetime: None,
            hop_limit: None,
            application_parameters: None,
        }
    }

    /// Set the nonce for this Interest
    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the interest lifetime
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.interest_lifetime = Some(lifetime);
        self
    }

    /// Set the hop limit
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = Some(hop_limit);
        self
    }

    /// Set the must_be_fresh flag
    pub fn with_must_be_fresh(mut self, must_be_fresh: bool) -> Self {
        if must_be_fresh {
            self.selectors.get_or_insert_with(Default::default).must_be_fresh = true;
        }
        self
    }

    /// Set application parameters
    pub fn with_application_parameters(mut self, params: Vec<u8>) -> Self {
        self.application_parameters = Some(params);
        self
    }

    /// Generate a random nonce if none is set
    pub fn ensure_nonce(&mut self) {
        if self.nonce.is_none() {
            // Simple random nonce generation - in production, use a proper RNG
            self.nonce = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u32
            );
        }
    }

    /// Check if the Interest can be satisfied by a Data packet with the given name
    pub fn matches_data(&self, data_name: &Name) -> bool {
        // Basic prefix matching - in a full implementation, this would consider selectors
        self.name.is_prefix_of(data_name)
    }

    /// Encode Interest packet to TLV wire format
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut elements = Vec::new();
        
        // Add Name
        let name_encoded = self.name.encode()?;
        elements.push(TlvElement::decode(&name_encoded)?.0);
        
        // Add Selectors if present
        if let Some(selectors) = &self.selectors {
            let selectors_encoded = encode_selectors(selectors)?;
            elements.push(TlvElement::new(tlv_types::SELECTORS, selectors_encoded));
        }
        
        // Add Nonce if present
        if let Some(nonce) = self.nonce {
            elements.push(TlvElement::new(tlv_types::NONCE, nonce.to_be_bytes().to_vec()));
        }
        
        // Add Interest Lifetime if present
        if let Some(lifetime) = self.interest_lifetime {
            let lifetime_ms = lifetime.as_millis() as u64;
            elements.push(TlvElement::new(tlv_types::INTEREST_LIFETIME, lifetime_ms.to_be_bytes().to_vec()));
        }
        
        // Add Hop Limit if present
        if let Some(hop_limit) = self.hop_limit {
            elements.push(TlvElement::new(tlv_types::HOP_LIMIT, vec![hop_limit]));
        }
        
        // Add Application Parameters if present
        if let Some(params) = &self.application_parameters {
            elements.push(TlvElement::new(tlv_types::APPLICATION_PARAMETERS, params.clone()));
        }
        
        // Wrap in Interest TLV
        let interest_content = crate::tlv::encode_tlv_sequence(&elements)?;
        let interest_element = TlvElement::new(tlv_types::INTEREST, interest_content);
        interest_element.encode()
    }

    /// Decode Interest packet from TLV wire format
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TlvError> {
        let (interest_element, consumed) = TlvElement::decode(data)?;
        
        if interest_element.type_ != tlv_types::INTEREST {
            return Err(TlvError::InvalidType(interest_element.type_));
        }
        
        let inner_elements = crate::tlv::decode_tlv_sequence(&interest_element.value)?;
        
        let mut name = None;
        let mut selectors = None;
        let mut nonce = None;
        let mut interest_lifetime = None;
        let mut hop_limit = None;
        let mut application_parameters = None;
        
        for element in inner_elements {
            match element.type_ {
                tlv_types::NAME => {
                    let name_data = element.encode()?;
                    name = Some(Name::decode(&name_data)?.0);
                }
                tlv_types::SELECTORS => {
                    selectors = Some(decode_selectors(&element.value)?);
                }
                tlv_types::NONCE => {
                    if element.value.len() == 4 {
                        nonce = Some(u32::from_be_bytes([
                            element.value[0], element.value[1], 
                            element.value[2], element.value[3]
                        ]));
                    }
                }
                tlv_types::INTEREST_LIFETIME => {
                    if element.value.len() == 8 {
                        let lifetime_ms = u64::from_be_bytes([
                            element.value[0], element.value[1], element.value[2], element.value[3],
                            element.value[4], element.value[5], element.value[6], element.value[7]
                        ]);
                        interest_lifetime = Some(Duration::from_millis(lifetime_ms));
                    }
                }
                tlv_types::HOP_LIMIT => {
                    if !element.value.is_empty() {
                        hop_limit = Some(element.value[0]);
                    }
                }
                tlv_types::APPLICATION_PARAMETERS => {
                    application_parameters = Some(element.value);
                }
                _ => {} // Ignore unknown elements
            }
        }
        
        let name = name.ok_or(TlvError::InvalidType(tlv_types::NAME))?;
        
        Ok((Interest {
            name,
            selectors,
            nonce,
            interest_lifetime,
            hop_limit,
            application_parameters,
        }, consumed))
    }
}

/// Content type for Data packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    Blob = 0,
    Link = 1,
    Key = 2,
    Nack = 3,
}

impl Default for ContentType {
    fn default() -> Self {
        ContentType::Blob
    }
}

/// MetaInfo for Data packets
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaInfo {
    pub content_type: ContentType,
    pub freshness_period: Option<Duration>,
    pub final_block_id: Option<Vec<u8>>,
    pub other_fields: HashMap<u8, Vec<u8>>,
}

impl Default for MetaInfo {
    fn default() -> Self {
        Self {
            content_type: ContentType::default(),
            freshness_period: None,
            final_block_id: None,
            other_fields: HashMap::new(),
        }
    }
}

/// Signature information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub signature_type: u8,
    pub key_locator: Option<KeyLocator>,
    pub other_fields: HashMap<u8, Vec<u8>>,
}

impl SignatureInfo {
    pub fn new(signature_type: u8) -> Self {
        Self {
            signature_type,
            key_locator: None,
            other_fields: HashMap::new(),
        }
    }

    pub fn with_key_locator(mut self, key_locator: KeyLocator) -> Self {
        self.key_locator = Some(key_locator);
        self
    }
}

/// Data packet structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Data {
    pub name: Name,
    pub meta_info: Option<MetaInfo>,
    pub content: Vec<u8>,
    pub signature_info: Option<SignatureInfo>,
    pub signature_value: Option<Vec<u8>>,
}

impl Data {
    /// Create a new Data packet with the given name and content
    pub fn new(name: Name, content: Vec<u8>) -> Self {
        Self {
            name,
            meta_info: None,
            content,
            signature_info: None,
            signature_value: None,
        }
    }

    /// Set the MetaInfo for this Data packet
    pub fn with_meta_info(mut self, meta_info: MetaInfo) -> Self {
        self.meta_info = Some(meta_info);
        self
    }

    /// Set the content type
    pub fn with_content_type(mut self, content_type: ContentType) -> Self {
        self.meta_info.get_or_insert_with(Default::default).content_type = content_type;
        self
    }

    /// Set the freshness period
    pub fn with_freshness_period(mut self, freshness_period: Duration) -> Self {
        self.meta_info.get_or_insert_with(Default::default).freshness_period = Some(freshness_period);
        self
    }

    /// Set the signature info
    pub fn with_signature_info(mut self, signature_info: SignatureInfo) -> Self {
        self.signature_info = Some(signature_info);
        self
    }

    /// Set the signature value
    pub fn with_signature_value(mut self, signature_value: Vec<u8>) -> Self {
        self.signature_value = Some(signature_value);
        self
    }

    /// Check if this Data packet matches the given Interest
    pub fn matches_interest(&self, interest: &Interest) -> bool {
        interest.matches_data(&self.name)
    }

    /// Check if the Data packet is fresh based on its freshness period
    pub fn is_fresh(&self) -> bool {
        if let Some(meta_info) = &self.meta_info {
            if let Some(freshness_period) = meta_info.freshness_period {
                // In a real implementation, this would check against the creation time
                // For now, we'll assume it's fresh if it has a freshness period
                return freshness_period > Duration::from_secs(0);
            }
        }
        false
    }

    /// Encode Data packet to TLV wire format
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut elements = Vec::new();
        
        // Add Name
        let name_encoded = self.name.encode()?;
        elements.push(TlvElement::decode(&name_encoded)?.0);
        
        // Add MetaInfo if present
        if let Some(meta_info) = &self.meta_info {
            let meta_info_encoded = encode_meta_info(meta_info)?;
            elements.push(TlvElement::new(tlv_types::META_INFO, meta_info_encoded));
        }
        
        // Add Content
        elements.push(TlvElement::new(tlv_types::CONTENT, self.content.clone()));
        
        // Add SignatureInfo if present
        if let Some(sig_info) = &self.signature_info {
            let sig_info_encoded = encode_signature_info(sig_info)?;
            elements.push(TlvElement::new(tlv_types::SIGNATURE_INFO, sig_info_encoded));
        }
        
        // Add SignatureValue if present
        if let Some(sig_value) = &self.signature_value {
            elements.push(TlvElement::new(tlv_types::SIGNATURE_VALUE, sig_value.clone()));
        }
        
        // Wrap in Data TLV
        let data_content = crate::tlv::encode_tlv_sequence(&elements)?;
        let data_element = TlvElement::new(tlv_types::DATA, data_content);
        data_element.encode()
    }

    /// Decode Data packet from TLV wire format
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TlvError> {
        let (data_element, consumed) = TlvElement::decode(data)?;
        
        if data_element.type_ != tlv_types::DATA {
            return Err(TlvError::InvalidType(data_element.type_));
        }
        
        let inner_elements = crate::tlv::decode_tlv_sequence(&data_element.value)?;
        
        let mut name = None;
        let mut meta_info = None;
        let mut content = None;
        let mut signature_info = None;
        let mut signature_value = None;
        
        for element in inner_elements {
            match element.type_ {
                tlv_types::NAME => {
                    let name_data = element.encode()?;
                    name = Some(Name::decode(&name_data)?.0);
                }
                tlv_types::META_INFO => {
                    meta_info = Some(decode_meta_info(&element.value)?);
                }
                tlv_types::CONTENT => {
                    content = Some(element.value);
                }
                tlv_types::SIGNATURE_INFO => {
                    signature_info = Some(decode_signature_info(&element.value)?);
                }
                tlv_types::SIGNATURE_VALUE => {
                    signature_value = Some(element.value);
                }
                _ => {} // Ignore unknown elements
            }
        }
        
        let name = name.ok_or(TlvError::InvalidType(tlv_types::NAME))?;
        let content = content.unwrap_or_default();
        
        Ok((Data {
            name,
            meta_info,
            content,
            signature_info,
            signature_value,
        }, consumed))
    }
}

/// Packet types that can be sent over the network
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Packet {
    Interest(Interest),
    Data(Data),
}

impl Packet {
    /// Get the name of the packet
    pub fn name(&self) -> &Name {
        match self {
            Packet::Interest(interest) => &interest.name,
            Packet::Data(data) => &data.name,
        }
    }

    /// Check if this is an Interest packet
    pub fn is_interest(&self) -> bool {
        matches!(self, Packet::Interest(_))
    }

    /// Check if this is a Data packet
    pub fn is_data(&self) -> bool {
        matches!(self, Packet::Data(_))
    }
}

impl From<Interest> for Packet {
    fn from(interest: Interest) -> Self {
        Packet::Interest(interest)
    }
}

impl From<Data> for Packet {
    fn from(data: Data) -> Self {
        Packet::Data(data)
    }
}

// Helper functions for encoding/decoding complex structures

/// Encode Selectors to TLV format
fn encode_selectors(selectors: &Selectors) -> Result<Vec<u8>, TlvError> {
    let mut elements = Vec::new();
    
    if let Some(min_suffix) = selectors.min_suffix_components {
        elements.push(TlvElement::new(tlv_types::MIN_SUFFIX_COMPONENTS, min_suffix.to_be_bytes().to_vec()));
    }
    
    if let Some(max_suffix) = selectors.max_suffix_components {
        elements.push(TlvElement::new(tlv_types::MAX_SUFFIX_COMPONENTS, max_suffix.to_be_bytes().to_vec()));
    }
    
    if let Some(key_locator) = &selectors.publisher_public_key_locator {
        let key_locator_encoded = encode_key_locator(key_locator)?;
        elements.push(TlvElement::new(tlv_types::PUBLISHER_PUBLIC_KEY_LOCATOR, key_locator_encoded));
    }
    
    if let Some(exclude) = &selectors.exclude {
        let exclude_encoded = encode_exclude(exclude)?;
        elements.push(TlvElement::new(tlv_types::EXCLUDE, exclude_encoded));
    }
    
    if let Some(child_selector) = selectors.child_selector {
        elements.push(TlvElement::new(tlv_types::CHILD_SELECTOR, vec![child_selector]));
    }
    
    if selectors.must_be_fresh {
        elements.push(TlvElement::new(tlv_types::MUST_BE_FRESH, vec![]));
    }
    
    crate::tlv::encode_tlv_sequence(&elements)
}

/// Decode Selectors from TLV format
fn decode_selectors(data: &[u8]) -> Result<Selectors, TlvError> {
    let elements = crate::tlv::decode_tlv_sequence(data)?;
    
    let mut selectors = Selectors::default();
    
    for element in elements {
        match element.type_ {
            tlv_types::MIN_SUFFIX_COMPONENTS => {
                if element.value.len() == 4 {
                    selectors.min_suffix_components = Some(u32::from_be_bytes([
                        element.value[0], element.value[1], element.value[2], element.value[3]
                    ]));
                }
            }
            tlv_types::MAX_SUFFIX_COMPONENTS => {
                if element.value.len() == 4 {
                    selectors.max_suffix_components = Some(u32::from_be_bytes([
                        element.value[0], element.value[1], element.value[2], element.value[3]
                    ]));
                }
            }
            tlv_types::PUBLISHER_PUBLIC_KEY_LOCATOR => {
                selectors.publisher_public_key_locator = Some(decode_key_locator(&element.value)?);
            }
            tlv_types::EXCLUDE => {
                selectors.exclude = Some(decode_exclude(&element.value)?);
            }
            tlv_types::CHILD_SELECTOR => {
                if !element.value.is_empty() {
                    selectors.child_selector = Some(element.value[0]);
                }
            }
            tlv_types::MUST_BE_FRESH => {
                selectors.must_be_fresh = true;
            }
            _ => {} // Ignore unknown elements
        }
    }
    
    Ok(selectors)
}

/// Encode MetaInfo to TLV format
fn encode_meta_info(meta_info: &MetaInfo) -> Result<Vec<u8>, TlvError> {
    let mut elements = Vec::new();
    
    if meta_info.content_type != ContentType::default() {
        elements.push(TlvElement::new(tlv_types::CONTENT_TYPE, vec![meta_info.content_type as u8]));
    }
    
    if let Some(freshness_period) = meta_info.freshness_period {
        let freshness_ms = freshness_period.as_millis() as u64;
        elements.push(TlvElement::new(tlv_types::FRESHNESS_PERIOD, freshness_ms.to_be_bytes().to_vec()));
    }
    
    if let Some(final_block_id) = &meta_info.final_block_id {
        elements.push(TlvElement::new(tlv_types::FINAL_BLOCK_ID, final_block_id.clone()));
    }
    
    for (type_, value) in &meta_info.other_fields {
        elements.push(TlvElement::new(*type_, value.clone()));
    }
    
    crate::tlv::encode_tlv_sequence(&elements)
}

/// Decode MetaInfo from TLV format
fn decode_meta_info(data: &[u8]) -> Result<MetaInfo, TlvError> {
    let elements = crate::tlv::decode_tlv_sequence(data)?;
    
    let mut meta_info = MetaInfo::default();
    
    for element in elements {
        match element.type_ {
            tlv_types::CONTENT_TYPE => {
                if !element.value.is_empty() {
                    meta_info.content_type = match element.value[0] {
                        0 => ContentType::Blob,
                        1 => ContentType::Link,
                        2 => ContentType::Key,
                        3 => ContentType::Nack,
                        _ => ContentType::Blob,
                    };
                }
            }
            tlv_types::FRESHNESS_PERIOD => {
                if element.value.len() == 8 {
                    let freshness_ms = u64::from_be_bytes([
                        element.value[0], element.value[1], element.value[2], element.value[3],
                        element.value[4], element.value[5], element.value[6], element.value[7]
                    ]);
                    meta_info.freshness_period = Some(Duration::from_millis(freshness_ms));
                }
            }
            tlv_types::FINAL_BLOCK_ID => {
                meta_info.final_block_id = Some(element.value);
            }
            _ => {
                meta_info.other_fields.insert(element.type_, element.value);
            }
        }
    }
    
    Ok(meta_info)
}

/// Encode SignatureInfo to TLV format
fn encode_signature_info(sig_info: &SignatureInfo) -> Result<Vec<u8>, TlvError> {
    let mut elements = Vec::new();
    
    elements.push(TlvElement::new(tlv_types::SIGNATURE_TYPE, vec![sig_info.signature_type]));
    
    if let Some(key_locator) = &sig_info.key_locator {
        let key_locator_encoded = encode_key_locator(key_locator)?;
        elements.push(TlvElement::new(tlv_types::KEY_LOCATOR, key_locator_encoded));
    }
    
    for (type_, value) in &sig_info.other_fields {
        elements.push(TlvElement::new(*type_, value.clone()));
    }
    
    crate::tlv::encode_tlv_sequence(&elements)
}

/// Decode SignatureInfo from TLV format
fn decode_signature_info(data: &[u8]) -> Result<SignatureInfo, TlvError> {
    let elements = crate::tlv::decode_tlv_sequence(data)?;
    
    let mut signature_type = 0;
    let mut key_locator = None;
    let mut other_fields = HashMap::new();
    
    for element in elements {
        match element.type_ {
            tlv_types::SIGNATURE_TYPE => {
                if !element.value.is_empty() {
                    signature_type = element.value[0];
                }
            }
            tlv_types::KEY_LOCATOR => {
                key_locator = Some(decode_key_locator(&element.value)?);
            }
            _ => {
                other_fields.insert(element.type_, element.value);
            }
        }
    }
    
    Ok(SignatureInfo {
        signature_type,
        key_locator,
        other_fields,
    })
}

/// Encode KeyLocator to TLV format
fn encode_key_locator(key_locator: &KeyLocator) -> Result<Vec<u8>, TlvError> {
    match key_locator {
        KeyLocator::Name(name) => {
            name.encode()
        }
        KeyLocator::KeyDigest(digest) => {
            let element = TlvElement::new(tlv_types::KEY_DIGEST, digest.clone());
            element.encode()
        }
    }
}

/// Decode KeyLocator from TLV format
fn decode_key_locator(data: &[u8]) -> Result<KeyLocator, TlvError> {
    let (element, _) = TlvElement::decode(data)?;
    
    match element.type_ {
        tlv_types::NAME => {
            let name_data = element.encode()?;
            let (name, _) = Name::decode(&name_data)?;
            Ok(KeyLocator::Name(name))
        }
        tlv_types::KEY_DIGEST => {
            Ok(KeyLocator::KeyDigest(element.value))
        }
        _ => Err(TlvError::InvalidType(element.type_))
    }
}

/// Encode Exclude to TLV format
fn encode_exclude(exclude: &Exclude) -> Result<Vec<u8>, TlvError> {
    let mut elements = Vec::new();
    
    for component in &exclude.components {
        elements.push(TlvElement::new(tlv_types::NAME_COMPONENT, component.clone()));
    }
    
    crate::tlv::encode_tlv_sequence(&elements)
}

/// Decode Exclude from TLV format
fn decode_exclude(data: &[u8]) -> Result<Exclude, TlvError> {
    let elements = crate::tlv::decode_tlv_sequence(data)?;
    
    let mut components = Vec::new();
    
    for element in elements {
        if element.type_ == tlv_types::NAME_COMPONENT {
            components.push(element.value);
        }
    }
    
    Ok(Exclude { components })
}

// Validation functions for packet integrity

/// Validation errors for packets
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Empty name is not allowed")]
    EmptyName,
    #[error("Invalid name component: {0}")]
    InvalidNameComponent(String),
    #[error("Interest lifetime must be positive")]
    InvalidInterestLifetime,
    #[error("Hop limit must be positive")]
    InvalidHopLimit,
    #[error("Nonce is required for Interest packets")]
    MissingNonce,
    #[error("Name is required")]
    MissingName,
    #[error("Content type is invalid: {0}")]
    InvalidContentType(u8),
    #[error("Freshness period must be positive")]
    InvalidFreshnessPeriod,
    #[error("Signature is incomplete")]
    IncompleteSignature,
    #[error("Name component too large: {size} bytes (max: {max})")]
    NameComponentTooLarge { size: usize, max: usize },
    #[error("Name too deep: {depth} components (max: {max})")]
    NameTooDeep { depth: usize, max: usize },
}

/// Validation configuration
pub struct ValidationConfig {
    pub max_name_components: usize,
    pub max_component_size: usize,
    pub require_nonce_for_interest: bool,
    pub require_signature_for_data: bool,
    pub max_content_size: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_name_components: 32,        // Reasonable default
            max_component_size: 8192,       // 8KB per component
            require_nonce_for_interest: true,
            require_signature_for_data: false, // Allow unsigned data for testing
            max_content_size: 8388608,      // 8MB max content size
        }
    }
}

impl Name {
    /// Validate the name structure
    pub fn validate(&self, config: &ValidationConfig) -> Result<(), ValidationError> {
        // Check if name is empty
        if self.is_empty() {
            return Err(ValidationError::EmptyName);
        }

        // Check maximum number of components
        if self.len() > config.max_name_components {
            return Err(ValidationError::NameTooDeep {
                depth: self.len(),
                max: config.max_name_components,
            });
        }

        // Check each component
        for (i, component) in self.components.iter().enumerate() {
            // Check component size
            if component.len() > config.max_component_size {
                return Err(ValidationError::NameComponentTooLarge {
                    size: component.len(),
                    max: config.max_component_size,
                });
            }

            // Check for invalid characters (basic validation)
            // In a full implementation, this would be more sophisticated
            if component.is_empty() && i > 0 {
                return Err(ValidationError::InvalidNameComponent(
                    "Empty component not allowed except at end".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Check if the name is valid for use in packets
    pub fn is_valid(&self, config: &ValidationConfig) -> bool {
        self.validate(config).is_ok()
    }
}

impl Interest {
    /// Validate the Interest packet
    pub fn validate(&self, config: &ValidationConfig) -> Result<(), ValidationError> {
        // Validate name
        self.name.validate(config)?;

        // Check if nonce is required and present
        if config.require_nonce_for_interest && self.nonce.is_none() {
            return Err(ValidationError::MissingNonce);
        }

        // Validate interest lifetime
        if let Some(lifetime) = self.interest_lifetime {
            if lifetime.is_zero() {
                return Err(ValidationError::InvalidInterestLifetime);
            }
        }

        // Validate hop limit
        if let Some(hop_limit) = self.hop_limit {
            if hop_limit == 0 {
                return Err(ValidationError::InvalidHopLimit);
            }
        }

        // Validate selectors if present
        if let Some(selectors) = &self.selectors {
            validate_selectors(selectors)?;
        }

        Ok(())
    }

    /// Check if the Interest packet is valid
    pub fn is_valid(&self, config: &ValidationConfig) -> bool {
        self.validate(config).is_ok()
    }
}

impl Data {
    /// Validate the Data packet
    pub fn validate(&self, config: &ValidationConfig) -> Result<(), ValidationError> {
        // Validate name
        self.name.validate(config)?;

        // Check content size
        if self.content.len() > config.max_content_size {
            return Err(ValidationError::InvalidNameComponent(
                format!("Content too large: {} bytes", self.content.len())
            ));
        }

        // Validate MetaInfo if present
        if let Some(meta_info) = &self.meta_info {
            validate_meta_info(meta_info)?;
        }

        // Check signature consistency
        if config.require_signature_for_data {
            if self.signature_info.is_none() || self.signature_value.is_none() {
                return Err(ValidationError::IncompleteSignature);
            }
        }

        // If signature info is present, signature value should also be present
        if self.signature_info.is_some() && self.signature_value.is_none() {
            return Err(ValidationError::IncompleteSignature);
        }

        // Validate signature info if present
        if let Some(sig_info) = &self.signature_info {
            validate_signature_info(sig_info)?;
        }

        Ok(())
    }

    /// Check if the Data packet is valid
    pub fn is_valid(&self, config: &ValidationConfig) -> bool {
        self.validate(config).is_ok()
    }
}

impl Packet {
    /// Validate the packet
    pub fn validate(&self, config: &ValidationConfig) -> Result<(), ValidationError> {
        match self {
            Packet::Interest(interest) => interest.validate(config),
            Packet::Data(data) => data.validate(config),
        }
    }

    /// Check if the packet is valid
    pub fn is_valid(&self, config: &ValidationConfig) -> bool {
        self.validate(config).is_ok()
    }
}

/// Validate Selectors structure
fn validate_selectors(selectors: &Selectors) -> Result<(), ValidationError> {
    // Check min/max suffix components consistency
    if let (Some(min), Some(max)) = (selectors.min_suffix_components, selectors.max_suffix_components) {
        if min > max {
            return Err(ValidationError::InvalidNameComponent(
                "MinSuffixComponents cannot be greater than MaxSuffixComponents".to_string()
            ));
        }
    }

    // Validate key locator if present
    if let Some(key_locator) = &selectors.publisher_public_key_locator {
        validate_key_locator(key_locator)?;
    }

    Ok(())
}

/// Validate MetaInfo structure
fn validate_meta_info(meta_info: &MetaInfo) -> Result<(), ValidationError> {
    // Validate freshness period
    if let Some(freshness) = meta_info.freshness_period {
        if freshness.is_zero() {
            return Err(ValidationError::InvalidFreshnessPeriod);
        }
    }

    // Content type validation is inherent in the enum

    Ok(())
}

/// Validate SignatureInfo structure
fn validate_signature_info(sig_info: &SignatureInfo) -> Result<(), ValidationError> {
    // Validate key locator if present
    if let Some(key_locator) = &sig_info.key_locator {
        validate_key_locator(key_locator)?;
    }

    // Signature type validation - in a real implementation, 
    // this would check against known signature types
    Ok(())
}

/// Validate KeyLocator structure
fn validate_key_locator(key_locator: &KeyLocator) -> Result<(), ValidationError> {
    match key_locator {
        KeyLocator::Name(name) => {
            // Use default config for key locator name validation
            let config = ValidationConfig::default();
            name.validate(&config)
        }
        KeyLocator::KeyDigest(digest) => {
            // Basic digest validation - check minimum length
            if digest.len() < 4 {
                return Err(ValidationError::InvalidNameComponent(
                    "Key digest too short".to_string()
                ));
            }
            Ok(())
        }
    }
}

/// Validate TLV structure integrity
pub fn validate_tlv_structure(data: &[u8]) -> Result<(), TlvError> {
    // Try to parse the TLV structure to ensure it's well-formed
    let _elements = crate::tlv::decode_tlv_sequence(data)?;
    Ok(())
}

/// Validate that a buffer contains a valid Interest packet
pub fn validate_interest_buffer(data: &[u8], config: &ValidationConfig) -> Result<(), Box<dyn std::error::Error>> {
    // First validate TLV structure
    validate_tlv_structure(data)?;
    
    // Then decode and validate the Interest
    let (interest, _) = Interest::decode(data)?;
    interest.validate(config)?;
    
    Ok(())
}

/// Validate that a buffer contains a valid Data packet
pub fn validate_data_buffer(data: &[u8], config: &ValidationConfig) -> Result<(), Box<dyn std::error::Error>> {
    // First validate TLV structure
    validate_tlv_structure(data)?;
    
    // Then decode and validate the Data
    let (data_packet, _) = Data::decode(data)?;
    data_packet.validate(config)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_creation() {
        let name = Name::from_str("/hello/world");
        assert_eq!(name.len(), 2);
        assert_eq!(name.get(0), Some(&b"hello".to_vec()));
        assert_eq!(name.get(1), Some(&b"world".to_vec()));
        assert_eq!(name.to_string(), "/hello/world");
    }

    #[test]
    fn test_name_append() {
        let mut name = Name::new();
        name.append_str("hello").append_str("world");
        assert_eq!(name.to_string(), "/hello/world");
    }

    #[test]
    fn test_name_prefix() {
        let name = Name::from_str("/hello/world/test");
        let prefix = name.get_prefix(2);
        assert_eq!(prefix.to_string(), "/hello/world");
        assert!(prefix.is_prefix_of(&name));
    }

    #[test]
    fn test_name_encoding() {
        let name = Name::from_str("/hello/world");
        let encoded = name.encode().unwrap();
        let (decoded, _) = Name::decode(&encoded).unwrap();
        assert_eq!(name, decoded);
    }

    #[test]
    fn test_empty_name() {
        let name = Name::new();
        assert!(name.is_empty());
        assert_eq!(name.to_string(), "/");
    }

    #[test]
    fn test_interest_creation() {
        let name = Name::from_str("/test/interest");
        let interest = Interest::new(name.clone())
            .with_nonce(12345)
            .with_lifetime(Duration::from_secs(10))
            .with_hop_limit(64)
            .with_must_be_fresh(true);

        assert_eq!(interest.name, name);
        assert_eq!(interest.nonce, Some(12345));
        assert_eq!(interest.interest_lifetime, Some(Duration::from_secs(10)));
        assert_eq!(interest.hop_limit, Some(64));
        assert_eq!(interest.selectors.as_ref().unwrap().must_be_fresh, true);
    }

    #[test]
    fn test_data_creation() {
        let name = Name::from_str("/test/data");
        let content = b"Hello, world!".to_vec();
        let data = Data::new(name.clone(), content.clone())
            .with_content_type(ContentType::Blob)
            .with_freshness_period(Duration::from_secs(3600));

        assert_eq!(data.name, name);
        assert_eq!(data.content, content);
        assert_eq!(data.meta_info.as_ref().unwrap().content_type, ContentType::Blob);
        assert_eq!(data.meta_info.as_ref().unwrap().freshness_period, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_interest_data_matching() {
        let interest_name = Name::from_str("/test");
        let data_name = Name::from_str("/test/data");
        
        let interest = Interest::new(interest_name);
        let data = Data::new(data_name, b"content".to_vec());

        assert!(interest.matches_data(&data.name));
        assert!(data.matches_interest(&interest));
    }

    #[test]
    fn test_packet_enum() {
        let interest = Interest::new(Name::from_str("/test"));
        let data = Data::new(Name::from_str("/test"), b"content".to_vec());

        let interest_packet = Packet::from(interest);
        let data_packet = Packet::from(data);

        assert!(interest_packet.is_interest());
        assert!(!interest_packet.is_data());
        assert!(data_packet.is_data());
        assert!(!data_packet.is_interest());
    }

    #[test]
    fn test_signature_info() {
        let key_locator = KeyLocator::Name(Name::from_str("/test/key"));
        let sig_info = SignatureInfo::new(1)
            .with_key_locator(key_locator.clone());

        assert_eq!(sig_info.signature_type, 1);
        assert_eq!(sig_info.key_locator, Some(key_locator));
    }

    #[test]
    fn test_interest_encoding_roundtrip() {
        let interest = Interest::new(Name::from_str("/test/interest"))
            .with_nonce(12345)
            .with_lifetime(Duration::from_secs(10))
            .with_hop_limit(64)
            .with_must_be_fresh(true);

        let encoded = interest.encode().unwrap();
        let (decoded, _) = Interest::decode(&encoded).unwrap();

        assert_eq!(interest.name, decoded.name);
        assert_eq!(interest.nonce, decoded.nonce);
        assert_eq!(interest.interest_lifetime, decoded.interest_lifetime);
        assert_eq!(interest.hop_limit, decoded.hop_limit);
        assert_eq!(interest.selectors.as_ref().unwrap().must_be_fresh, 
                   decoded.selectors.as_ref().unwrap().must_be_fresh);
    }

    #[test]
    fn test_data_encoding_roundtrip() {
        let meta_info = MetaInfo {
            content_type: ContentType::Key,
            freshness_period: Some(Duration::from_secs(3600)),
            final_block_id: Some(b"final".to_vec()),
            other_fields: HashMap::new(),
        };

        let signature_info = SignatureInfo::new(1)
            .with_key_locator(KeyLocator::Name(Name::from_str("/test/key")));

        let data = Data::new(Name::from_str("/test/data"), b"Hello, world!".to_vec())
            .with_meta_info(meta_info)
            .with_signature_info(signature_info)
            .with_signature_value(b"signature".to_vec());

        let encoded = data.encode().unwrap();
        let (decoded, _) = Data::decode(&encoded).unwrap();

        assert_eq!(data.name, decoded.name);
        assert_eq!(data.content, decoded.content);
        assert_eq!(data.meta_info.as_ref().unwrap().content_type, 
                   decoded.meta_info.as_ref().unwrap().content_type);
        assert_eq!(data.meta_info.as_ref().unwrap().freshness_period, 
                   decoded.meta_info.as_ref().unwrap().freshness_period);
        assert_eq!(data.signature_info.as_ref().unwrap().signature_type, 
                   decoded.signature_info.as_ref().unwrap().signature_type);
        assert_eq!(data.signature_value, decoded.signature_value);
    }

    #[test]
    fn test_simple_interest_encoding() {
        let interest = Interest::new(Name::from_str("/hello"));
        let encoded = interest.encode().unwrap();
        let (decoded, _) = Interest::decode(&encoded).unwrap();
        assert_eq!(interest.name, decoded.name);
    }

    #[test]
    fn test_simple_data_encoding() {
        let data = Data::new(Name::from_str("/hello"), b"world".to_vec());
        let encoded = data.encode().unwrap();
        let (decoded, _) = Data::decode(&encoded).unwrap();
        assert_eq!(data.name, decoded.name);
        assert_eq!(data.content, decoded.content);
    }

    #[test]
    fn test_empty_content_data() {
        let data = Data::new(Name::from_str("/empty"), vec![]);
        let encoded = data.encode().unwrap();
        let (decoded, _) = Data::decode(&encoded).unwrap();
        assert_eq!(data.name, decoded.name);
        assert_eq!(data.content, decoded.content);
        assert!(decoded.content.is_empty());
    }

    #[test]
    fn test_key_locator_encoding() {
        let name_locator = KeyLocator::Name(Name::from_str("/key/name"));
        let digest_locator = KeyLocator::KeyDigest(b"digest".to_vec());

        let encoded_name = encode_key_locator(&name_locator).unwrap();
        let decoded_name = decode_key_locator(&encoded_name).unwrap();
        assert_eq!(name_locator, decoded_name);

        let encoded_digest = encode_key_locator(&digest_locator).unwrap();
        let decoded_digest = decode_key_locator(&encoded_digest).unwrap();
        assert_eq!(digest_locator, decoded_digest);
    }

    #[test]
    fn test_name_validation() {
        let config = ValidationConfig::default();
        
        // Valid name
        let valid_name = Name::from_str("/hello/world");
        assert!(valid_name.is_valid(&config));
        
        // Empty name (invalid)
        let empty_name = Name::new();
        assert!(!empty_name.is_valid(&config));
        
        // Name with too many components
        let mut deep_name = Name::new();
        for i in 0..50 {  // More than default max of 32
            deep_name.append_str(&format!("component{}", i));
        }
        assert!(!deep_name.is_valid(&config));
        
        // Name with oversized component
        let big_component = vec![0u8; 10000]; // Larger than default max of 8192
        let mut big_name = Name::new();
        big_name.append(big_component);
        assert!(!big_name.is_valid(&config));
    }

    #[test]
    fn test_interest_validation() {
        let config = ValidationConfig::default();
        
        // Valid interest
        let valid_interest = Interest::new(Name::from_str("/test"))
            .with_nonce(12345)
            .with_lifetime(Duration::from_secs(10));
        assert!(valid_interest.is_valid(&config));
        
        // Interest without nonce (invalid with default config)
        let no_nonce_interest = Interest::new(Name::from_str("/test"));
        assert!(!no_nonce_interest.is_valid(&config));
        
        // Interest with zero lifetime (invalid)
        let zero_lifetime_interest = Interest::new(Name::from_str("/test"))
            .with_nonce(12345)
            .with_lifetime(Duration::from_secs(0));
        assert!(!zero_lifetime_interest.is_valid(&config));
        
        // Interest with zero hop limit (invalid)
        let zero_hop_interest = Interest::new(Name::from_str("/test"))
            .with_nonce(12345)
            .with_hop_limit(0);
        assert!(!zero_hop_interest.is_valid(&config));
    }

    #[test]
    fn test_data_validation() {
        let config = ValidationConfig::default();
        
        // Valid data
        let valid_data = Data::new(Name::from_str("/test"), b"content".to_vec());
        assert!(valid_data.is_valid(&config));
        
        // Data with empty name (invalid)
        let empty_name_data = Data::new(Name::new(), b"content".to_vec());
        assert!(!empty_name_data.is_valid(&config));
        
        // Data with incomplete signature
        let incomplete_sig_data = Data::new(Name::from_str("/test"), b"content".to_vec())
            .with_signature_info(SignatureInfo::new(1));
            // Missing signature_value
        assert!(!incomplete_sig_data.is_valid(&config));
    }

    #[test]
    fn test_validation_config() {
        let mut config = ValidationConfig::default();
        config.require_nonce_for_interest = false;
        
        // Interest without nonce should be valid now
        let no_nonce_interest = Interest::new(Name::from_str("/test"));
        assert!(no_nonce_interest.is_valid(&config));
        
        config.require_signature_for_data = true;
        
        // Data without signature should be invalid now
        let unsigned_data = Data::new(Name::from_str("/test"), b"content".to_vec());
        assert!(!unsigned_data.is_valid(&config));
    }

    #[test]
    fn test_selectors_validation() {
        let config = ValidationConfig::default();
        
        // Valid selectors
        let mut valid_selectors = Selectors::default();
        valid_selectors.min_suffix_components = Some(1);
        valid_selectors.max_suffix_components = Some(5);
        
        let valid_interest = Interest::new(Name::from_str("/test"))
            .with_nonce(12345);
        let mut valid_interest_with_selectors = valid_interest.clone();
        valid_interest_with_selectors.selectors = Some(valid_selectors);
        
        assert!(valid_interest_with_selectors.is_valid(&config));
        
        // Invalid selectors (min > max)
        let mut invalid_selectors = Selectors::default();
        invalid_selectors.min_suffix_components = Some(10);
        invalid_selectors.max_suffix_components = Some(5);
        
        let mut invalid_interest = valid_interest;
        invalid_interest.selectors = Some(invalid_selectors);
        
        assert!(!invalid_interest.is_valid(&config));
    }

    #[test]
    fn test_meta_info_validation() {
        let config = ValidationConfig::default();
        
        // Valid meta info
        let valid_meta_info = MetaInfo {
            content_type: ContentType::Blob,
            freshness_period: Some(Duration::from_secs(3600)),
            final_block_id: None,
            other_fields: HashMap::new(),
        };
        
        let valid_data = Data::new(Name::from_str("/test"), b"content".to_vec())
            .with_meta_info(valid_meta_info);
        assert!(valid_data.is_valid(&config));
        
        // Invalid meta info (zero freshness period)
        let invalid_meta_info = MetaInfo {
            content_type: ContentType::Blob,
            freshness_period: Some(Duration::from_secs(0)),
            final_block_id: None,
            other_fields: HashMap::new(),
        };
        
        let invalid_data = Data::new(Name::from_str("/test"), b"content".to_vec())
            .with_meta_info(invalid_meta_info);
        assert!(!invalid_data.is_valid(&config));
    }

    #[test]
    fn test_buffer_validation() {
        let config = ValidationConfig::default();
        
        // Create valid Interest and Data packets
        let interest = Interest::new(Name::from_str("/test"))
            .with_nonce(12345);
        let data = Data::new(Name::from_str("/test"), b"content".to_vec());
        
        // Encode them
        let interest_encoded = interest.encode().unwrap();
        let data_encoded = data.encode().unwrap();
        
        // Validate buffers
        assert!(validate_interest_buffer(&interest_encoded, &config).is_ok());
        assert!(validate_data_buffer(&data_encoded, &config).is_ok());
        
        // Test with malformed buffer
        let malformed_buffer = vec![0xFF, 0xFF, 0xFF, 0xFF];
        assert!(validate_interest_buffer(&malformed_buffer, &config).is_err());
        assert!(validate_data_buffer(&malformed_buffer, &config).is_err());
    }

    #[test]
    fn test_key_locator_validation() {
        // Valid name-based key locator
        let name_locator = KeyLocator::Name(Name::from_str("/key/name"));
        assert!(validate_key_locator(&name_locator).is_ok());
        
        // Valid digest-based key locator
        let digest_locator = KeyLocator::KeyDigest(b"validdigest".to_vec());
        assert!(validate_key_locator(&digest_locator).is_ok());
        
        // Invalid digest (too short)
        let short_digest_locator = KeyLocator::KeyDigest(b"ab".to_vec());
        assert!(validate_key_locator(&short_digest_locator).is_err());
        
        // Invalid name (empty)
        let empty_name_locator = KeyLocator::Name(Name::new());
        assert!(validate_key_locator(&empty_name_locator).is_err());
    }
}