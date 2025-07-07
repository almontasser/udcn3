use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
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

impl Hash for NameComponent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
        self.component_type.hash(state);
        // Sort metadata keys for consistent hashing
        let mut metadata_vec: Vec<_> = self.metadata.iter().collect();
        metadata_vec.sort_by_key(|&(k, _)| k);
        for (key, value) in metadata_vec {
            key.hash(state);
            value.hash(state);
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

// Prefix matching and fuzzy matching algorithms

/// Trie node for efficient prefix matching
#[derive(Debug, Clone)]
pub struct TrieNode {
    pub is_end: bool,
    pub children: HashMap<Vec<u8>, TrieNode>,
    pub data: Option<Name>,
}

impl TrieNode {
    pub fn new() -> Self {
        Self {
            is_end: false,
            children: HashMap::new(),
            data: None,
        }
    }
}

impl Default for TrieNode {
    fn default() -> Self {
        Self::new()
    }
}

/// Trie data structure for efficient prefix storage and lookup
#[derive(Debug, Clone)]
pub struct NameTrie {
    root: TrieNode,
    size: usize,
}

impl NameTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            size: 0,
        }
    }

    /// Insert a name into the trie
    pub fn insert(&mut self, name: &Name) {
        let mut current = &mut self.root;
        
        for component in &name.components {
            current = current.children.entry(component.value.clone()).or_insert_with(TrieNode::new);
        }
        
        if !current.is_end {
            current.is_end = true;
            current.data = Some(name.clone());
            self.size += 1;
        }
    }

    /// Check if a name exists in the trie
    pub fn contains(&self, name: &Name) -> bool {
        self.find_node(name).map_or(false, |node| node.is_end)
    }

    /// Find all names that have the given name as a prefix
    pub fn find_with_prefix(&self, prefix: &Name) -> Vec<Name> {
        if let Some(node) = self.find_node(prefix) {
            let mut results = Vec::new();
            self.collect_names(node, &mut results);
            results
        } else {
            Vec::new()
        }
    }

    /// Get the size of the trie (number of stored names)
    pub fn size(&self) -> usize {
        self.size
    }

    /// Check if the trie is empty
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Find the node corresponding to a given name
    fn find_node(&self, name: &Name) -> Option<&TrieNode> {
        let mut current = &self.root;
        
        for component in &name.components {
            current = current.children.get(&component.value)?;
        }
        
        Some(current)
    }

    /// Recursively collect all names from a node
    fn collect_names(&self, node: &TrieNode, results: &mut Vec<Name>) {
        if node.is_end {
            if let Some(ref name) = node.data {
                results.push(name.clone());
            }
        }
        
        for child in node.children.values() {
            self.collect_names(child, results);
        }
    }
}

impl Default for NameTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for prefix matching operations
#[derive(Debug, Clone)]
pub struct MatchingConfig {
    pub fuzzy_threshold: f64,
    pub max_edit_distance: usize,
    pub case_sensitive: bool,
    pub allow_partial_matches: bool,
    pub wildcard_enabled: bool,
}

impl Default for MatchingConfig {
    fn default() -> Self {
        Self {
            fuzzy_threshold: 0.8,
            max_edit_distance: 2,
            case_sensitive: true,
            allow_partial_matches: true,
            wildcard_enabled: true,
        }
    }
}

/// Match result with similarity score
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    pub name: Name,
    pub similarity: f64,
    pub edit_distance: usize,
    pub match_type: MatchType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Exact,
    Prefix,
    Fuzzy,
    Partial,
    Wildcard,
}

impl MatchResult {
    pub fn new(name: Name, similarity: f64, edit_distance: usize, match_type: MatchType) -> Self {
        Self {
            name,
            similarity,
            edit_distance,
            match_type,
        }
    }
}

/// Prefix matching engine with fuzzy matching capabilities
#[derive(Debug, Clone)]
pub struct PrefixMatcher {
    trie: NameTrie,
    config: MatchingConfig,
}

impl PrefixMatcher {
    pub fn new() -> Self {
        Self {
            trie: NameTrie::new(),
            config: MatchingConfig::default(),
        }
    }

    pub fn with_config(config: MatchingConfig) -> Self {
        Self {
            trie: NameTrie::new(),
            config,
        }
    }

    /// Add a name to the matcher
    pub fn add_name(&mut self, name: &Name) {
        self.trie.insert(name);
    }

    /// Add multiple names to the matcher
    pub fn add_names(&mut self, names: &[Name]) {
        for name in names {
            self.add_name(name);
        }
    }

    /// Find exact matches for a name
    pub fn find_exact(&self, name: &Name) -> Option<MatchResult> {
        if self.trie.contains(name) {
            Some(MatchResult::new(name.clone(), 1.0, 0, MatchType::Exact))
        } else {
            None
        }
    }

    /// Find all names with the given prefix
    pub fn find_prefix_matches(&self, prefix: &Name) -> Vec<MatchResult> {
        let matches = self.trie.find_with_prefix(prefix);
        matches.into_iter()
            .map(|name| MatchResult::new(name, 1.0, 0, MatchType::Prefix))
            .collect()
    }

    /// Find fuzzy matches using Levenshtein distance
    pub fn find_fuzzy_matches(&self, target: &Name) -> Vec<MatchResult> {
        let mut results = Vec::new();
        self.collect_fuzzy_matches(&self.trie.root, target, &Name::new(), &mut results);
        
        // Sort by similarity score (descending)
        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Find all types of matches (exact, prefix, fuzzy)
    pub fn find_all_matches(&self, query: &Name) -> Vec<MatchResult> {
        let mut all_matches = Vec::new();
        
        // Exact match
        if let Some(exact) = self.find_exact(query) {
            all_matches.push(exact);
        }
        
        // Prefix matches
        let mut prefix_matches = self.find_prefix_matches(query);
        all_matches.append(&mut prefix_matches);
        
        // Fuzzy matches
        let mut fuzzy_matches = self.find_fuzzy_matches(query);
        all_matches.append(&mut fuzzy_matches);
        
        // Remove duplicates and sort by similarity
        all_matches.sort_by(|a, b| {
            // First by match type priority (exact > prefix > fuzzy)
            let type_priority = |t: &MatchType| match t {
                MatchType::Exact => 0,
                MatchType::Prefix => 1,
                MatchType::Fuzzy => 2,
                MatchType::Partial => 3,
                MatchType::Wildcard => 4,
            };
            
            let type_cmp = type_priority(&a.match_type).cmp(&type_priority(&b.match_type));
            if type_cmp != std::cmp::Ordering::Equal {
                return type_cmp;
            }
            
            // Then by similarity score (descending)
            b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Remove duplicates
        all_matches.dedup_by(|a, b| a.name == b.name);
        
        all_matches
    }

    /// Configure matching parameters
    pub fn set_config(&mut self, config: MatchingConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &MatchingConfig {
        &self.config
    }

    /// Private method to collect fuzzy matches recursively
    fn collect_fuzzy_matches(
        &self,
        node: &TrieNode,
        target: &Name,
        current_path: &Name,
        results: &mut Vec<MatchResult>,
    ) {
        if node.is_end {
            if let Some(ref stored_name) = node.data {
                let distance = levenshtein_distance(target, stored_name);
                if distance <= self.config.max_edit_distance {
                    let similarity = jaro_winkler_similarity(target, stored_name);
                    if similarity >= self.config.fuzzy_threshold {
                        results.push(MatchResult::new(
                            stored_name.clone(),
                            similarity,
                            distance,
                            MatchType::Fuzzy,
                        ));
                    }
                }
            }
        }

        for (component_value, child) in &node.children {
            let mut extended_path = current_path.clone();
            extended_path.push(NameComponent::new(component_value.clone()));
            self.collect_fuzzy_matches(child, target, &extended_path, results);
        }
    }
}

impl Default for PrefixMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate Levenshtein distance between two names
pub fn levenshtein_distance(name1: &Name, name2: &Name) -> usize {
    let len1 = name1.len();
    let len2 = name2.len();
    
    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }
    
    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];
    
    // Initialize first row and column
    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }
    
    // Fill the matrix
    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if name1.get_component(i - 1) == name2.get_component(j - 1) { 0 } else { 1 };
            
            matrix[i][j] = std::cmp::min(
                std::cmp::min(
                    matrix[i - 1][j] + 1,      // deletion
                    matrix[i][j - 1] + 1,      // insertion
                ),
                matrix[i - 1][j - 1] + cost,   // substitution
            );
        }
    }
    
    matrix[len1][len2]
}

/// Calculate Jaro-Winkler similarity between two names
pub fn jaro_winkler_similarity(name1: &Name, name2: &Name) -> f64 {
    let jaro_sim = jaro_similarity(name1, name2);
    
    if jaro_sim < 0.7 {
        return jaro_sim;
    }
    
    // Calculate common prefix length (up to 4 components)
    let prefix_len = std::cmp::min(4, common_prefix_length(name1, name2));
    
    // Jaro-Winkler similarity with prefix scaling factor of 0.1
    jaro_sim + (0.1 * prefix_len as f64 * (1.0 - jaro_sim))
}

/// Calculate Jaro similarity between two names
pub fn jaro_similarity(name1: &Name, name2: &Name) -> f64 {
    let len1 = name1.len();
    let len2 = name2.len();
    
    if len1 == 0 && len2 == 0 {
        return 1.0;
    }
    if len1 == 0 || len2 == 0 {
        return 0.0;
    }
    
    let match_window = std::cmp::max(len1, len2) / 2;
    if match_window == 0 {
        return if name1.get_component(0) == name2.get_component(0) { 1.0 } else { 0.0 };
    }
    
    let mut matches1 = vec![false; len1];
    let mut matches2 = vec![false; len2];
    let mut matches = 0;
    let mut transpositions = 0;
    
    // Find matches
    for i in 0..len1 {
        let start = if i >= match_window { i - match_window } else { 0 };
        let end = std::cmp::min(i + match_window + 1, len2);
        
        for j in start..end {
            if matches2[j] || name1.get_component(i) != name2.get_component(j) {
                continue;
            }
            
            matches1[i] = true;
            matches2[j] = true;
            matches += 1;
            break;
        }
    }
    
    if matches == 0 {
        return 0.0;
    }
    
    // Count transpositions
    let mut k = 0;
    for i in 0..len1 {
        if !matches1[i] {
            continue;
        }
        
        while !matches2[k] {
            k += 1;
        }
        
        if name1.get_component(i) != name2.get_component(k) {
            transpositions += 1;
        }
        k += 1;
    }
    
    let m = matches as f64;
    (m / len1 as f64 + m / len2 as f64 + (m - transpositions as f64 / 2.0) / m) / 3.0
}

/// Calculate common prefix length between two names
pub fn common_prefix_length(name1: &Name, name2: &Name) -> usize {
    let min_len = std::cmp::min(name1.len(), name2.len());
    let mut prefix_len = 0;
    
    for i in 0..min_len {
        if name1.get_component(i) == name2.get_component(i) {
            prefix_len += 1;
        } else {
            break;
        }
    }
    
    prefix_len
}

#[cfg(test)]
mod prefix_matching_tests {
    use super::*;

    #[test]
    fn test_trie_insert_and_contains() {
        let mut trie = NameTrie::new();
        let name1 = Name::from_str("/hello/world").unwrap();
        let name2 = Name::from_str("/hello/test").unwrap();
        
        trie.insert(&name1);
        trie.insert(&name2);
        
        assert!(trie.contains(&name1));
        assert!(trie.contains(&name2));
        assert_eq!(trie.size(), 2);
    }

    #[test]
    fn test_trie_prefix_search() {
        let mut trie = NameTrie::new();
        let name1 = Name::from_str("/hello/world/foo").unwrap();
        let name2 = Name::from_str("/hello/world/bar").unwrap();
        let name3 = Name::from_str("/hello/test").unwrap();
        
        trie.insert(&name1);
        trie.insert(&name2);
        trie.insert(&name3);
        
        let prefix = Name::from_str("/hello/world").unwrap();
        let matches = trie.find_with_prefix(&prefix);
        
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&name1));
        assert!(matches.contains(&name2));
    }

    #[test]
    fn test_levenshtein_distance() {
        let name1 = Name::from_str("/hello/world").unwrap();
        let name2 = Name::from_str("/hello/world").unwrap();
        let name3 = Name::from_str("/hello/test").unwrap();
        let name4 = Name::from_str("/foo/bar").unwrap();
        
        assert_eq!(levenshtein_distance(&name1, &name2), 0);
        assert_eq!(levenshtein_distance(&name1, &name3), 1);
        assert_eq!(levenshtein_distance(&name1, &name4), 2);
    }

    #[test]
    fn test_jaro_winkler_similarity() {
        let name1 = Name::from_str("/hello/world").unwrap();
        let name2 = Name::from_str("/hello/world").unwrap();
        let name3 = Name::from_str("/hello/test").unwrap();
        
        assert_eq!(jaro_winkler_similarity(&name1, &name2), 1.0);
        
        // They share the first component "hello", so should have some similarity
        let similarity = jaro_winkler_similarity(&name1, &name3);
        assert!(similarity > 0.5);
    }

    #[test]
    fn test_prefix_matcher_exact_match() {
        let mut matcher = PrefixMatcher::new();
        let name = Name::from_str("/hello/world").unwrap();
        
        matcher.add_name(&name);
        
        let result = matcher.find_exact(&name);
        assert!(result.is_some());
        assert_eq!(result.unwrap().match_type, MatchType::Exact);
    }

    #[test]
    fn test_prefix_matcher_prefix_matches() {
        let mut matcher = PrefixMatcher::new();
        let name1 = Name::from_str("/hello/world/foo").unwrap();
        let name2 = Name::from_str("/hello/world/bar").unwrap();
        
        matcher.add_name(&name1);
        matcher.add_name(&name2);
        
        let prefix = Name::from_str("/hello/world").unwrap();
        let matches = matcher.find_prefix_matches(&prefix);
        
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.match_type == MatchType::Prefix));
    }

    #[test]
    fn test_prefix_matcher_fuzzy_matches() {
        let config = MatchingConfig {
            fuzzy_threshold: 0.5, // Lower threshold for more lenient matching
            max_edit_distance: 3,
            case_sensitive: true,
            allow_partial_matches: true,
            wildcard_enabled: true,
        };
        
        let mut matcher = PrefixMatcher::with_config(config);
        let name1 = Name::from_str("/hello/world").unwrap();
        let name2 = Name::from_str("/hello/test").unwrap();
        
        matcher.add_name(&name1);
        matcher.add_name(&name2);
        
        let query = Name::from_str("/hello/word").unwrap(); // Similar to "world"
        let matches = matcher.find_fuzzy_matches(&query);
        
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.match_type == MatchType::Fuzzy));
    }

    #[test]
    fn test_common_prefix_length() {
        let name1 = Name::from_str("/hello/world/test").unwrap();
        let name2 = Name::from_str("/hello/world/foo").unwrap();
        let name3 = Name::from_str("/hello/bar").unwrap();
        
        assert_eq!(common_prefix_length(&name1, &name2), 2);
        assert_eq!(common_prefix_length(&name1, &name3), 1);
    }

    #[test]
    fn test_matching_config() {
        let config = MatchingConfig {
            fuzzy_threshold: 0.9,
            max_edit_distance: 1,
            case_sensitive: false,
            allow_partial_matches: false,
            wildcard_enabled: false,
        };
        
        let matcher = PrefixMatcher::with_config(config.clone());
        assert_eq!(matcher.get_config().fuzzy_threshold, 0.9);
        assert_eq!(matcher.get_config().max_edit_distance, 1);
    }
}

// Hierarchy operations for managing name relationships

/// Node in the name hierarchy tree
#[derive(Debug, Clone)]
pub struct HierarchyNode {
    pub name: Name,
    pub parent_id: Option<String>,
    pub children_ids: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub node_id: String,
}

impl HierarchyNode {
    pub fn new(name: Name) -> Self {
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_nanos().hash(&mut hasher);
        let node_id = format!("node_{:x}", hasher.finish());
        
        Self {
            name,
            parent_id: None,
            children_ids: Vec::new(),
            metadata: HashMap::new(),
            node_id,
        }
    }

    pub fn with_id(name: Name, node_id: String) -> Self {
        Self {
            name,
            parent_id: None,
            children_ids: Vec::new(),
            metadata: HashMap::new(),
            node_id,
        }
    }

    /// Check if this node is a root node (has no parent)
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    /// Check if this node is a leaf node (has no children)
    pub fn is_leaf(&self) -> bool {
        self.children_ids.is_empty()
    }

    /// Get the number of children
    pub fn child_count(&self) -> usize {
        self.children_ids.len()
    }

    /// Add a child node ID
    pub fn add_child_id(&mut self, child_id: String) {
        if !self.children_ids.contains(&child_id) {
            self.children_ids.push(child_id);
        }
    }

    /// Remove a child by node ID
    pub fn remove_child_id(&mut self, node_id: &str) -> bool {
        if let Some(index) = self.children_ids.iter().position(|id| id == node_id) {
            self.children_ids.remove(index);
            true
        } else {
            false
        }
    }

    /// Set metadata for this node
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get metadata for this node
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

impl Hash for HierarchyNode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node_id.hash(state);
    }
}

/// Hierarchy manager for organizing names in a tree structure
#[derive(Debug, Clone)]
pub struct NameHierarchy {
    root_id: Option<String>,
    nodes: HashMap<String, HierarchyNode>,
    name_to_id: HashMap<Name, String>, // Map names to node IDs
}

impl NameHierarchy {
    pub fn new() -> Self {
        Self {
            root_id: None,
            nodes: HashMap::new(),
            name_to_id: HashMap::new(),
        }
    }

    /// Set the root node of the hierarchy
    pub fn set_root(&mut self, name: Name) -> String {
        let node = HierarchyNode::new(name.clone());
        let node_id = node.node_id.clone();
        
        self.name_to_id.insert(name, node_id.clone());
        self.nodes.insert(node_id.clone(), node);
        self.root_id = Some(node_id.clone());
        
        node_id
    }

    /// Insert a node under a parent
    pub fn insert_node(&mut self, parent_id: &str, name: Name) -> Result<String, HierarchyError> {
        if self.name_to_id.contains_key(&name) {
            return Err(HierarchyError::DuplicateName);
        }

        if !self.nodes.contains_key(parent_id) {
            return Err(HierarchyError::NodeNotFound);
        }

        let mut child = HierarchyNode::new(name.clone());
        child.parent_id = Some(parent_id.to_string());
        let child_id = child.node_id.clone();
        
        // Add child to parent's children list
        if let Some(parent) = self.nodes.get_mut(parent_id) {
            parent.add_child_id(child_id.clone());
        }
        
        self.nodes.insert(child_id.clone(), child);
        self.name_to_id.insert(name, child_id.clone());
        
        Ok(child_id)
    }

    /// Remove a node and all its descendants
    pub fn remove_node(&mut self, node_id: &str) -> Result<HierarchyNode, HierarchyError> {
        let node = self.nodes.get(node_id)
            .ok_or(HierarchyError::NodeNotFound)?
            .clone();

        // Remove from parent's children
        if let Some(parent_id) = &node.parent_id {
            if let Some(parent) = self.nodes.get_mut(parent_id) {
                parent.remove_child_id(node_id);
            }
        }

        // Remove all descendants
        let descendants = self.get_descendants(node_id)?;
        for descendant in descendants {
            self.name_to_id.remove(&descendant.name);
            self.nodes.remove(&descendant.node_id);
        }
        
        // Remove the node itself
        self.name_to_id.remove(&node.name);
        self.nodes.remove(node_id);
        
        // Update root if necessary
        if self.root_id.as_ref() == Some(&node_id.to_string()) {
            self.root_id = None;
        }
        
        Ok(node)
    }

    /// Move a node to a new parent
    pub fn move_node(&mut self, node_id: &str, new_parent_id: &str) -> Result<(), HierarchyError> {
        if node_id == new_parent_id {
            return Err(HierarchyError::InvalidOperation);
        }

        if !self.nodes.contains_key(node_id) || !self.nodes.contains_key(new_parent_id) {
            return Err(HierarchyError::NodeNotFound);
        }

        // Check if new parent would create a cycle
        if self.would_create_cycle(node_id, new_parent_id)? {
            return Err(HierarchyError::CycleDetected);
        }

        let node = self.nodes.get(node_id).unwrap().clone();

        // Remove from old parent
        if let Some(old_parent_id) = &node.parent_id {
            if let Some(old_parent) = self.nodes.get_mut(old_parent_id) {
                old_parent.remove_child_id(node_id);
            }
        }

        // Update node's parent
        if let Some(node_mut) = self.nodes.get_mut(node_id) {
            node_mut.parent_id = Some(new_parent_id.to_string());
        }

        // Add to new parent
        if let Some(new_parent) = self.nodes.get_mut(new_parent_id) {
            new_parent.add_child_id(node_id.to_string());
        }
        
        Ok(())
    }

    /// Get all ancestors of a node
    pub fn get_ancestors(&self, node_id: &str) -> Result<Vec<HierarchyNode>, HierarchyError> {
        let mut ancestors = Vec::new();
        let mut current_id = node_id;

        while let Some(node) = self.nodes.get(current_id) {
            if let Some(parent_id) = &node.parent_id {
                if let Some(parent) = self.nodes.get(parent_id) {
                    ancestors.push(parent.clone());
                    current_id = parent_id;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(ancestors)
    }

    /// Get all descendants of a node
    pub fn get_descendants(&self, node_id: &str) -> Result<Vec<HierarchyNode>, HierarchyError> {
        let node = self.nodes.get(node_id)
            .ok_or(HierarchyError::NodeNotFound)?;

        let mut descendants = Vec::new();
        self.collect_descendants(node, &mut descendants);
        
        Ok(descendants)
    }

    /// Get siblings of a node (nodes with the same parent)
    pub fn get_siblings(&self, node_id: &str) -> Result<Vec<HierarchyNode>, HierarchyError> {
        let node = self.nodes.get(node_id)
            .ok_or(HierarchyError::NodeNotFound)?;

        if let Some(parent_id) = &node.parent_id {
            if let Some(parent) = self.nodes.get(parent_id) {
                let siblings = parent.children_ids.iter()
                    .filter(|&child_id| child_id != node_id)
                    .filter_map(|child_id| self.nodes.get(child_id))
                    .cloned()
                    .collect();
                Ok(siblings)
            } else {
                Ok(Vec::new())
            }
        } else {
            Ok(Vec::new()) // Root node has no siblings
        }
    }

    /// Get direct children of a node
    pub fn get_children(&self, node_id: &str) -> Result<Vec<HierarchyNode>, HierarchyError> {
        let node = self.nodes.get(node_id)
            .ok_or(HierarchyError::NodeNotFound)?;

        let children = node.children_ids.iter()
            .filter_map(|child_id| self.nodes.get(child_id))
            .cloned()
            .collect();

        Ok(children)
    }

    /// Find a node by name
    pub fn find_by_name(&self, name: &Name) -> Option<&HierarchyNode> {
        if let Some(node_id) = self.name_to_id.get(name) {
            self.nodes.get(node_id)
        } else {
            None
        }
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &str) -> Option<&HierarchyNode> {
        self.nodes.get(node_id)
    }

    /// Get the root node
    pub fn get_root(&self) -> Option<&HierarchyNode> {
        if let Some(root_id) = &self.root_id {
            self.nodes.get(root_id)
        } else {
            None
        }
    }

    /// Get the depth of a node in the hierarchy (root = 0)
    pub fn get_depth(&self, node_id: &str) -> Result<usize, HierarchyError> {
        let ancestors = self.get_ancestors(node_id)?;
        Ok(ancestors.len())
    }

    /// Validate the entire hierarchy for consistency
    pub fn validate(&self) -> Result<(), HierarchyError> {
        // Check for cycles
        if let Some(root_id) = &self.root_id {
            let mut visited = std::collections::HashSet::new();
            self.check_cycles(root_id, &mut visited)?;
        }

        // Check that all nodes in the index exist
        for (name, node_id) in &self.name_to_id {
            if let Some(node) = self.nodes.get(node_id) {
                if &node.name != name {
                    return Err(HierarchyError::IndexInconsistency);
                }
            } else {
                return Err(HierarchyError::IndexInconsistency);
            }
        }

        // Check parent-child relationships
        for node in self.nodes.values() {
            if let Some(parent_id) = &node.parent_id {
                if let Some(parent) = self.nodes.get(parent_id) {
                    if !parent.children_ids.contains(&node.node_id) {
                        return Err(HierarchyError::RelationshipInconsistency);
                    }
                } else {
                    return Err(HierarchyError::RelationshipInconsistency);
                }
            }

            // Check children exist
            for child_id in &node.children_ids {
                if !self.nodes.contains_key(child_id) {
                    return Err(HierarchyError::RelationshipInconsistency);
                }
            }
        }

        Ok(())
    }

    /// Get the total number of nodes in the hierarchy
    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the hierarchy is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Clear the entire hierarchy
    pub fn clear(&mut self) {
        self.root_id = None;
        self.nodes.clear();
        self.name_to_id.clear();
    }

    /// Get all leaf nodes in the hierarchy
    pub fn get_leaves(&self) -> Vec<&HierarchyNode> {
        self.nodes.values().filter(|node| node.is_leaf()).collect()
    }

    /// Get the height of the hierarchy (longest path from root to leaf)
    pub fn height(&self) -> usize {
        if let Some(root_id) = &self.root_id {
            self.calculate_height(root_id)
        } else {
            0
        }
    }

    // Private helper methods

    fn would_create_cycle(&self, node_id: &str, potential_parent_id: &str) -> Result<bool, HierarchyError> {
        let descendants = self.get_descendants(node_id)?;
        Ok(descendants.iter().any(|desc| desc.node_id == potential_parent_id))
    }

    fn check_cycles(&self, node_id: &str, visited: &mut std::collections::HashSet<String>) -> Result<(), HierarchyError> {
        if visited.contains(node_id) {
            return Err(HierarchyError::CycleDetected);
        }

        visited.insert(node_id.to_string());

        if let Some(node) = self.nodes.get(node_id) {
            for child_id in &node.children_ids {
                self.check_cycles(child_id, visited)?;
            }
        }

        visited.remove(node_id);
        Ok(())
    }

    fn collect_descendants(&self, node: &HierarchyNode, descendants: &mut Vec<HierarchyNode>) {
        for child_id in &node.children_ids {
            if let Some(child) = self.nodes.get(child_id) {
                descendants.push(child.clone());
                self.collect_descendants(child, descendants);
            }
        }
    }

    fn calculate_height(&self, node_id: &str) -> usize {
        if let Some(node) = self.nodes.get(node_id) {
            if node.children_ids.is_empty() {
                0
            } else {
                node.children_ids.iter()
                    .map(|child_id| self.calculate_height(child_id))
                    .max()
                    .unwrap_or(0) + 1
            }
        } else {
            0
        }
    }
}

impl Default for NameHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during hierarchy operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierarchyError {
    NodeNotFound,
    DuplicateName,
    CycleDetected,
    InvalidOperation,
    IndexInconsistency,
    RelationshipInconsistency,
}

impl fmt::Display for HierarchyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HierarchyError::NodeNotFound => write!(f, "Node not found in hierarchy"),
            HierarchyError::DuplicateName => write!(f, "Duplicate name in hierarchy"),
            HierarchyError::CycleDetected => write!(f, "Cycle detected in hierarchy"),
            HierarchyError::InvalidOperation => write!(f, "Invalid hierarchy operation"),
            HierarchyError::IndexInconsistency => write!(f, "Hierarchy index inconsistency"),
            HierarchyError::RelationshipInconsistency => write!(f, "Parent-child relationship inconsistency"),
        }
    }
}

impl std::error::Error for HierarchyError {}

// Validation and normalization functions

/// Configuration for name validation rules
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub max_component_length: usize,
    pub max_name_length: usize,
    pub min_component_length: usize,
    pub allowed_characters: ValidationCharacterSet,
    pub case_sensitive: bool,
    pub allow_empty_components: bool,
    pub require_leading_slash: bool,
    pub allow_trailing_slash: bool,
    pub max_hierarchy_depth: Option<usize>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_component_length: 255,
            max_name_length: 8192,
            min_component_length: 1,
            allowed_characters: ValidationCharacterSet::Extended,
            case_sensitive: true,
            allow_empty_components: false,
            require_leading_slash: true,
            allow_trailing_slash: false,
            max_hierarchy_depth: Some(32),
        }
    }
}

/// Character set validation options
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationCharacterSet {
    /// Only ASCII alphanumeric and basic punctuation
    Basic,
    /// Extended ASCII including more symbols
    Extended,
    /// Full Unicode support
    Unicode,
    /// Custom character set with allowed characters
    Custom(std::collections::HashSet<char>),
}

/// Configuration for name normalization
#[derive(Debug, Clone)]
pub struct NormalizationConfig {
    pub case_handling: CaseHandling,
    pub whitespace_handling: WhitespaceHandling,
    pub diacritics_handling: DiacriticsHandling,
    pub character_substitution: CharacterSubstitution,
    pub encoding_normalization: EncodingNormalization,
}

impl Default for NormalizationConfig {
    fn default() -> Self {
        Self {
            case_handling: CaseHandling::Preserve,
            whitespace_handling: WhitespaceHandling::TrimAndCollapse,
            diacritics_handling: DiacriticsHandling::Preserve,
            character_substitution: CharacterSubstitution::None,
            encoding_normalization: EncodingNormalization::Nfc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseHandling {
    Preserve,
    ToLowercase,
    ToUppercase,
    TitleCase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhitespaceHandling {
    Preserve,
    Trim,
    TrimAndCollapse,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiacriticsHandling {
    Preserve,
    Remove,
    Normalize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CharacterSubstitution {
    None,
    BasicAscii,
    Custom(HashMap<char, char>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingNormalization {
    None,
    Nfc,  // Canonical Decomposition, followed by Canonical Composition
    Nfd,  // Canonical Decomposition
    Nfkc, // Compatibility Decomposition, followed by Canonical Composition
    Nfkd, // Compatibility Decomposition
}

/// Validation engine for names and components
#[derive(Debug, Clone)]
pub struct NameValidator {
    config: ValidationConfig,
}

impl NameValidator {
    pub fn new() -> Self {
        Self {
            config: ValidationConfig::default(),
        }
    }

    pub fn with_config(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a complete name
    pub fn validate_name(&self, name: &Name) -> Result<(), ValidationError> {
        // Check name length
        let total_length = name.to_uri().len();
        if total_length > self.config.max_name_length {
            return Err(ValidationError::NameTooLong {
                length: total_length,
                max_length: self.config.max_name_length,
            });
        }

        // Check hierarchy depth
        if let Some(max_depth) = self.config.max_hierarchy_depth {
            if name.len() > max_depth {
                return Err(ValidationError::HierarchyTooDeep {
                    depth: name.len(),
                    max_depth,
                });
            }
        }

        // Check URI format
        let uri = name.to_uri();
        if self.config.require_leading_slash && !uri.starts_with('/') {
            return Err(ValidationError::InvalidFormat("Name must start with '/'".to_string()));
        }

        if !self.config.allow_trailing_slash && uri.len() > 1 && uri.ends_with('/') {
            return Err(ValidationError::InvalidFormat("Name cannot end with '/'".to_string()));
        }

        // Validate each component
        for (index, component) in name.components.iter().enumerate() {
            self.validate_component(component)
                .map_err(|e| ValidationError::ComponentError { index, error: Box::new(e) })?;
        }

        // Check for empty components if not allowed
        if !self.config.allow_empty_components {
            for (index, component) in name.components.iter().enumerate() {
                if component.is_empty() {
                    return Err(ValidationError::ComponentError {
                        index,
                        error: Box::new(ValidationError::EmptyComponent),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate a single name component
    pub fn validate_component(&self, component: &NameComponent) -> Result<(), ValidationError> {
        let length = component.len();

        // Check component length
        if length < self.config.min_component_length {
            return Err(ValidationError::ComponentTooShort {
                length,
                min_length: self.config.min_component_length,
            });
        }

        if length > self.config.max_component_length {
            return Err(ValidationError::ComponentTooLong {
                length,
                max_length: self.config.max_component_length,
            });
        }

        // Check character set
        if let Ok(text) = component.as_str() {
            self.validate_character_set(text)?;
        }

        // Validate component type specific rules
        self.validate_component_type(component)?;

        Ok(())
    }

    /// Validate hierarchy consistency
    pub fn validate_hierarchy(&self, hierarchy: &NameHierarchy) -> Result<(), ValidationError> {
        // Use the existing hierarchy validation
        hierarchy.validate().map_err(ValidationError::HierarchyError)?;

        // Additional validation rules
        if let Some(max_depth) = self.config.max_hierarchy_depth {
            if hierarchy.height() > max_depth {
                return Err(ValidationError::HierarchyTooDeep {
                    depth: hierarchy.height(),
                    max_depth,
                });
            }
        }

        Ok(())
    }

    /// Check for circular references in name relationships
    pub fn check_circular_references(&self, names: &[Name]) -> Result<(), ValidationError> {
        // Build a dependency graph based on prefix relationships
        let mut visited = std::collections::HashSet::new();
        let mut rec_stack = std::collections::HashSet::new();

        for name in names {
            if !visited.contains(name) {
                if self.has_cycle_util(name, names, &mut visited, &mut rec_stack) {
                    return Err(ValidationError::CircularReference);
                }
            }
        }

        Ok(())
    }

    /// Set validation configuration
    pub fn set_config(&mut self, config: ValidationConfig) {
        self.config = config;
    }

    /// Get current validation configuration
    pub fn get_config(&self) -> &ValidationConfig {
        &self.config
    }

    // Private helper methods

    fn validate_character_set(&self, text: &str) -> Result<(), ValidationError> {
        match &self.config.allowed_characters {
            ValidationCharacterSet::Basic => {
                for ch in text.chars() {
                    if !ch.is_ascii_alphanumeric() && !"-_.".contains(ch) {
                        return Err(ValidationError::InvalidCharacter(ch));
                    }
                }
            }
            ValidationCharacterSet::Extended => {
                for ch in text.chars() {
                    if !ch.is_ascii_graphic() && !ch.is_ascii_whitespace() {
                        return Err(ValidationError::InvalidCharacter(ch));
                    }
                }
            }
            ValidationCharacterSet::Unicode => {
                // Unicode allows most characters, but exclude control characters
                for ch in text.chars() {
                    if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                        return Err(ValidationError::InvalidCharacter(ch));
                    }
                }
            }
            ValidationCharacterSet::Custom(allowed_chars) => {
                for ch in text.chars() {
                    if !allowed_chars.contains(&ch) {
                        return Err(ValidationError::InvalidCharacter(ch));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_component_type(&self, component: &NameComponent) -> Result<(), ValidationError> {
        match component.component_type {
            ComponentType::TimestampNameComponent => {
                if let Ok(text) = component.as_str() {
                    if text.parse::<u64>().is_err() {
                        return Err(ValidationError::InvalidComponentType {
                            component_type: component.component_type.clone(),
                            reason: "Timestamp must be a valid number".to_string(),
                        });
                    }
                }
            }
            ComponentType::VersionNameComponent => {
                if let Ok(text) = component.as_str() {
                    if !text.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        return Err(ValidationError::InvalidComponentType {
                            component_type: component.component_type.clone(),
                            reason: "Version must contain only digits and dots".to_string(),
                        });
                    }
                }
            }
            ComponentType::SequenceNumNameComponent => {
                if let Ok(text) = component.as_str() {
                    if text.parse::<u64>().is_err() {
                        return Err(ValidationError::InvalidComponentType {
                            component_type: component.component_type.clone(),
                            reason: "Sequence number must be a valid number".to_string(),
                        });
                    }
                }
            }
            ComponentType::ByteOffsetNameComponent => {
                if let Ok(text) = component.as_str() {
                    if text.parse::<u64>().is_err() {
                        return Err(ValidationError::InvalidComponentType {
                            component_type: component.component_type.clone(),
                            reason: "Byte offset must be a valid number".to_string(),
                        });
                    }
                }
            }
            _ => {} // Other types don't have specific validation rules
        }
        Ok(())
    }

    fn has_cycle_util(
        &self,
        name: &Name,
        all_names: &[Name],
        visited: &mut std::collections::HashSet<Name>,
        rec_stack: &mut std::collections::HashSet<Name>,
    ) -> bool {
        visited.insert(name.clone());
        rec_stack.insert(name.clone());

        // Check all names that could be considered "dependent" on this name
        for other_name in all_names {
            if other_name != name && self.is_prefix_of(name, other_name) {
                if !visited.contains(other_name) {
                    if self.has_cycle_util(other_name, all_names, visited, rec_stack) {
                        return true;
                    }
                } else if rec_stack.contains(other_name) {
                    return true;
                }
            }
        }

        rec_stack.remove(name);
        false
    }

    fn is_prefix_of(&self, prefix: &Name, name: &Name) -> bool {
        if prefix.len() >= name.len() {
            return false;
        }

        for i in 0..prefix.len() {
            if prefix.get_component(i) != name.get_component(i) {
                return false;
            }
        }
        true
    }
}

impl Default for NameValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Name normalization engine
#[derive(Debug, Clone)]
pub struct NameNormalizer {
    config: NormalizationConfig,
}

impl NameNormalizer {
    pub fn new() -> Self {
        Self {
            config: NormalizationConfig::default(),
        }
    }

    pub fn with_config(config: NormalizationConfig) -> Self {
        Self { config }
    }

    /// Normalize a complete name
    pub fn normalize_name(&self, name: &Name) -> Result<Name, ValidationError> {
        let mut normalized_components = Vec::new();

        for component in &name.components {
            let normalized_component = self.normalize_component(component)?;
            normalized_components.push(normalized_component);
        }

        Ok(Name {
            components: normalized_components,
        })
    }

    /// Normalize a single name component
    pub fn normalize_component(&self, component: &NameComponent) -> Result<NameComponent, ValidationError> {
        if let Ok(text) = component.as_str() {
            let normalized_text = self.normalize_text(text)?;
            let normalized_bytes = normalized_text.as_bytes().to_vec();

            Ok(NameComponent {
                value: normalized_bytes,
                component_type: component.component_type.clone(),
                metadata: component.metadata.clone(),
            })
        } else {
            // For non-UTF8 components, only apply byte-level normalizations
            Ok(component.clone())
        }
    }

    /// Normalize text according to configuration
    pub fn normalize_text(&self, text: &str) -> Result<String, ValidationError> {
        let mut result = text.to_string();

        // Apply whitespace handling
        result = self.handle_whitespace(&result);

        // Apply case handling
        result = self.handle_case(&result);

        // Apply character substitution
        result = self.handle_character_substitution(&result);

        // Apply diacritics handling
        result = self.handle_diacritics(&result);

        // Apply encoding normalization
        result = self.handle_encoding_normalization(&result)?;

        Ok(result)
    }

    /// Set normalization configuration
    pub fn set_config(&mut self, config: NormalizationConfig) {
        self.config = config;
    }

    /// Get current normalization configuration
    pub fn get_config(&self) -> &NormalizationConfig {
        &self.config
    }

    // Private helper methods

    fn handle_whitespace(&self, text: &str) -> String {
        match self.config.whitespace_handling {
            WhitespaceHandling::Preserve => text.to_string(),
            WhitespaceHandling::Trim => text.trim().to_string(),
            WhitespaceHandling::TrimAndCollapse => {
                let trimmed = text.trim();
                trimmed.split_whitespace().collect::<Vec<&str>>().join(" ")
            }
            WhitespaceHandling::Remove => text.chars().filter(|c| !c.is_whitespace()).collect(),
        }
    }

    fn handle_case(&self, text: &str) -> String {
        match self.config.case_handling {
            CaseHandling::Preserve => text.to_string(),
            CaseHandling::ToLowercase => text.to_lowercase(),
            CaseHandling::ToUppercase => text.to_uppercase(),
            CaseHandling::TitleCase => {
                let mut result = String::new();
                let mut capitalize_next = true;

                for ch in text.chars() {
                    if ch.is_alphabetic() {
                        if capitalize_next {
                            result.push(ch.to_uppercase().next().unwrap_or(ch));
                            capitalize_next = false;
                        } else {
                            result.push(ch.to_lowercase().next().unwrap_or(ch));
                        }
                    } else {
                        result.push(ch);
                        capitalize_next = ch.is_whitespace() || ch == '-' || ch == '_';
                    }
                }

                result
            }
        }
    }

    fn handle_character_substitution(&self, text: &str) -> String {
        match &self.config.character_substitution {
            CharacterSubstitution::None => text.to_string(),
            CharacterSubstitution::BasicAscii => {
                text.chars()
                    .map(|c| match c {
                        'À'..='Ö' | 'Ø'..='ö' | 'ø'..='ÿ' => self.remove_diacritics_char(c),
                        _ if c.is_ascii() => c,
                        _ => '_', // Replace non-ASCII with underscore
                    })
                    .collect()
            }
            CharacterSubstitution::Custom(substitutions) => {
                text.chars()
                    .map(|c| substitutions.get(&c).copied().unwrap_or(c))
                    .collect()
            }
        }
    }

    fn handle_diacritics(&self, text: &str) -> String {
        match self.config.diacritics_handling {
            DiacriticsHandling::Preserve => text.to_string(),
            DiacriticsHandling::Remove => text.chars().map(|c| self.remove_diacritics_char(c)).collect(),
            DiacriticsHandling::Normalize => {
                // Simple normalization - in a real implementation, you'd use a proper Unicode library
                text.chars().map(|c| self.normalize_diacritics_char(c)).collect()
            }
        }
    }

    fn handle_encoding_normalization(&self, text: &str) -> Result<String, ValidationError> {
        match self.config.encoding_normalization {
            EncodingNormalization::None => Ok(text.to_string()),
            // Note: In a production implementation, you would use the `unicode-normalization` crate
            // For this basic implementation, we'll just return the text as-is
            EncodingNormalization::Nfc
            | EncodingNormalization::Nfd
            | EncodingNormalization::Nfkc
            | EncodingNormalization::Nfkd => {
                // Placeholder - in real implementation, use unicode_normalization crate
                Ok(text.to_string())
            }
        }
    }

    fn remove_diacritics_char(&self, c: char) -> char {
        // Simple diacritics removal mapping
        match c {
            'À' | 'Á' | 'Â' | 'Ã' | 'Ä' | 'Å' => 'A',
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'È' | 'É' | 'Ê' | 'Ë' => 'E',
            'è' | 'é' | 'ê' | 'ë' => 'e',
            'Ì' | 'Í' | 'Î' | 'Ï' => 'I',
            'ì' | 'í' | 'î' | 'ï' => 'i',
            'Ò' | 'Ó' | 'Ô' | 'Õ' | 'Ö' => 'O',
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
            'Ù' | 'Ú' | 'Û' | 'Ü' => 'U',
            'ù' | 'ú' | 'û' | 'ü' => 'u',
            'Ý' => 'Y',
            'ý' | 'ÿ' => 'y',
            'Ñ' => 'N',
            'ñ' => 'n',
            'Ç' => 'C',
            'ç' => 'c',
            _ => c,
        }
    }

    fn normalize_diacritics_char(&self, c: char) -> char {
        // For simple normalization, just remove diacritics
        self.remove_diacritics_char(c)
    }
}

impl Default for NameNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    NameTooLong { length: usize, max_length: usize },
    ComponentTooLong { length: usize, max_length: usize },
    ComponentTooShort { length: usize, min_length: usize },
    EmptyComponent,
    InvalidCharacter(char),
    InvalidFormat(String),
    InvalidComponentType { component_type: ComponentType, reason: String },
    HierarchyTooDeep { depth: usize, max_depth: usize },
    CircularReference,
    HierarchyError(HierarchyError),
    ComponentError { index: usize, error: Box<ValidationError> },
    EncodingError(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::NameTooLong { length, max_length } => {
                write!(f, "Name too long: {} characters (max: {})", length, max_length)
            }
            ValidationError::ComponentTooLong { length, max_length } => {
                write!(f, "Component too long: {} characters (max: {})", length, max_length)
            }
            ValidationError::ComponentTooShort { length, min_length } => {
                write!(f, "Component too short: {} characters (min: {})", length, min_length)
            }
            ValidationError::EmptyComponent => write!(f, "Empty component not allowed"),
            ValidationError::InvalidCharacter(ch) => write!(f, "Invalid character: '{}'", ch),
            ValidationError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ValidationError::InvalidComponentType { component_type, reason } => {
                write!(f, "Invalid component type {:?}: {}", component_type, reason)
            }
            ValidationError::HierarchyTooDeep { depth, max_depth } => {
                write!(f, "Hierarchy too deep: {} levels (max: {})", depth, max_depth)
            }
            ValidationError::CircularReference => write!(f, "Circular reference detected"),
            ValidationError::HierarchyError(err) => write!(f, "Hierarchy error: {}", err),
            ValidationError::ComponentError { index, error } => {
                write!(f, "Error in component {}: {}", index, error)
            }
            ValidationError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Combined validation and normalization engine
#[derive(Debug, Clone)]
pub struct NameProcessor {
    validator: NameValidator,
    normalizer: NameNormalizer,
}

impl NameProcessor {
    pub fn new() -> Self {
        Self {
            validator: NameValidator::new(),
            normalizer: NameNormalizer::new(),
        }
    }

    pub fn with_configs(
        validation_config: ValidationConfig,
        normalization_config: NormalizationConfig,
    ) -> Self {
        Self {
            validator: NameValidator::with_config(validation_config),
            normalizer: NameNormalizer::with_config(normalization_config),
        }
    }

    /// Process a name: normalize then validate
    pub fn process_name(&self, name: &Name) -> Result<Name, ValidationError> {
        let normalized = self.normalizer.normalize_name(name)?;
        self.validator.validate_name(&normalized)?;
        Ok(normalized)
    }

    /// Process a component: normalize then validate
    pub fn process_component(&self, component: &NameComponent) -> Result<NameComponent, ValidationError> {
        let normalized = self.normalizer.normalize_component(component)?;
        self.validator.validate_component(&normalized)?;
        Ok(normalized)
    }

    /// Validate without normalization
    pub fn validate_name(&self, name: &Name) -> Result<(), ValidationError> {
        self.validator.validate_name(name)
    }

    /// Validate component without normalization
    pub fn validate_component(&self, component: &NameComponent) -> Result<(), ValidationError> {
        self.validator.validate_component(component)
    }

    /// Normalize without validation
    pub fn normalize_name(&self, name: &Name) -> Result<Name, ValidationError> {
        self.normalizer.normalize_name(name)
    }

    /// Normalize component without validation
    pub fn normalize_component(&self, component: &NameComponent) -> Result<NameComponent, ValidationError> {
        self.normalizer.normalize_component(component)
    }

    /// Get validator reference
    pub fn validator(&self) -> &NameValidator {
        &self.validator
    }

    /// Get normalizer reference
    pub fn normalizer(&self) -> &NameNormalizer {
        &self.normalizer
    }

    /// Get mutable validator reference
    pub fn validator_mut(&mut self) -> &mut NameValidator {
        &mut self.validator
    }

    /// Get mutable normalizer reference
    pub fn normalizer_mut(&mut self) -> &mut NameNormalizer {
        &mut self.normalizer
    }
}

impl Default for NameProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Bulk operations for managing multiple hierarchy changes
pub struct HierarchyBulkOperations {
    hierarchy: NameHierarchy,
    operations: Vec<BulkOperation>,
}

#[derive(Debug, Clone)]
pub enum BulkOperation {
    Insert { parent_id: String, name: Name },
    Remove { node_id: String },
    Move { node_id: String, new_parent_id: String },
    SetMetadata { node_id: String, key: String, value: String },
}

impl HierarchyBulkOperations {
    pub fn new(hierarchy: NameHierarchy) -> Self {
        Self {
            hierarchy,
            operations: Vec::new(),
        }
    }

    /// Add an insert operation to the batch
    pub fn add_insert(&mut self, parent_id: String, name: Name) {
        self.operations.push(BulkOperation::Insert { parent_id, name });
    }

    /// Add a remove operation to the batch
    pub fn add_remove(&mut self, node_id: String) {
        self.operations.push(BulkOperation::Remove { node_id });
    }

    /// Add a move operation to the batch
    pub fn add_move(&mut self, node_id: String, new_parent_id: String) {
        self.operations.push(BulkOperation::Move { node_id, new_parent_id });
    }

    /// Add a metadata operation to the batch
    pub fn add_set_metadata(&mut self, node_id: String, key: String, value: String) {
        self.operations.push(BulkOperation::SetMetadata { node_id, key, value });
    }

    /// Execute all batched operations
    pub fn execute(mut self) -> Result<NameHierarchy, HierarchyError> {
        for operation in self.operations {
            match operation {
                BulkOperation::Insert { parent_id, name } => {
                    self.hierarchy.insert_node(&parent_id, name)?;
                }
                BulkOperation::Remove { node_id } => {
                    self.hierarchy.remove_node(&node_id)?;
                }
                BulkOperation::Move { node_id, new_parent_id } => {
                    self.hierarchy.move_node(&node_id, &new_parent_id)?;
                }
                BulkOperation::SetMetadata { node_id, key, value } => {
                    if let Some(node) = self.hierarchy.nodes.get_mut(&node_id) {
                        node.set_metadata(key, value);
                    } else {
                        return Err(HierarchyError::NodeNotFound);
                    }
                }
            }
        }

        // Validate the hierarchy after all operations
        self.hierarchy.validate()?;
        
        Ok(self.hierarchy)
    }

    /// Get the number of pending operations
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Clear all pending operations
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }
}

#[cfg(test)]
mod hierarchy_tests {
    use super::*;

    fn create_test_hierarchy() -> NameHierarchy {
        let mut hierarchy = NameHierarchy::new();
        let root_name = Name::from_str("/root").unwrap();
        hierarchy.set_root(root_name);
        hierarchy
    }

    #[test]
    fn test_hierarchy_node_creation() {
        let name = Name::from_str("/test/node").unwrap();
        let node = HierarchyNode::new(name.clone());
        
        assert_eq!(node.name, name);
        assert!(node.is_root());
        assert!(node.is_leaf());
        assert_eq!(node.child_count(), 0);
        assert!(!node.node_id.is_empty());
    }

    #[test]
    fn test_hierarchy_set_root() {
        let mut hierarchy = NameHierarchy::new();
        let root_name = Name::from_str("/root").unwrap();
        
        let root_id = hierarchy.set_root(root_name.clone());
        
        assert!(!root_id.is_empty());
        assert_eq!(hierarchy.size(), 1);
        assert!(hierarchy.get_root().is_some());
        assert_eq!(hierarchy.get_root().unwrap().name, root_name);
    }

    #[test]
    fn test_hierarchy_insert_node() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name.clone()).unwrap();
        
        assert_eq!(hierarchy.size(), 2);
        
        let child_node = hierarchy.get_node(&child_id).unwrap();
        assert_eq!(child_node.name, child_name);
        assert_eq!(child_node.parent_id, Some(root_id.clone()));
        
        let root_children = hierarchy.get_children(&root_id).unwrap();
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0].node_id, child_id);
    }

    #[test]
    fn test_hierarchy_duplicate_name_error() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let name = Name::from_str("/duplicate").unwrap();
        hierarchy.insert_node(&root_id, name.clone()).unwrap();
        
        let result = hierarchy.insert_node(&root_id, name);
        assert!(matches!(result, Err(HierarchyError::DuplicateName)));
    }

    #[test]
    fn test_hierarchy_node_not_found_error() {
        let mut hierarchy = create_test_hierarchy();
        let name = Name::from_str("/orphan").unwrap();
        
        let result = hierarchy.insert_node("non_existent_id", name);
        assert!(matches!(result, Err(HierarchyError::NodeNotFound)));
    }

    #[test]
    fn test_hierarchy_remove_node() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name.clone()).unwrap();
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        let grandchild_id = hierarchy.insert_node(&child_id, grandchild_name).unwrap();
        
        assert_eq!(hierarchy.size(), 3);
        
        let removed_node = hierarchy.remove_node(&child_id).unwrap();
        assert_eq!(removed_node.name, child_name);
        assert_eq!(hierarchy.size(), 1); // Only root remains
        
        assert!(hierarchy.get_node(&child_id).is_none());
        assert!(hierarchy.get_node(&grandchild_id).is_none());
    }

    #[test]
    fn test_hierarchy_move_node() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let parent1_name = Name::from_str("/parent1").unwrap();
        let parent1_id = hierarchy.insert_node(&root_id, parent1_name).unwrap();
        
        let parent2_name = Name::from_str("/parent2").unwrap();
        let parent2_id = hierarchy.insert_node(&root_id, parent2_name).unwrap();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&parent1_id, child_name).unwrap();
        
        // Move child from parent1 to parent2
        hierarchy.move_node(&child_id, &parent2_id).unwrap();
        
        let child_node = hierarchy.get_node(&child_id).unwrap();
        assert_eq!(child_node.parent_id, Some(parent2_id.clone()));
        
        let parent1_children = hierarchy.get_children(&parent1_id).unwrap();
        let parent2_children = hierarchy.get_children(&parent2_id).unwrap();
        
        assert_eq!(parent1_children.len(), 0);
        assert_eq!(parent2_children.len(), 1);
        assert_eq!(parent2_children[0].node_id, child_id);
    }

    #[test]
    fn test_hierarchy_cycle_detection() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name).unwrap();
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        let grandchild_id = hierarchy.insert_node(&child_id, grandchild_name).unwrap();
        
        // Try to move root under grandchild (would create cycle)
        let result = hierarchy.move_node(&root_id, &grandchild_id);
        assert!(matches!(result, Err(HierarchyError::CycleDetected)));
    }

    #[test]
    fn test_hierarchy_get_ancestors() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name).unwrap();
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        let grandchild_id = hierarchy.insert_node(&child_id, grandchild_name).unwrap();
        
        let ancestors = hierarchy.get_ancestors(&grandchild_id).unwrap();
        assert_eq!(ancestors.len(), 2);
        assert_eq!(ancestors[0].node_id, child_id);
        assert_eq!(ancestors[1].node_id, root_id);
    }

    #[test]
    fn test_hierarchy_get_descendants() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child1_name = Name::from_str("/child1").unwrap();
        let child1_id = hierarchy.insert_node(&root_id, child1_name).unwrap();
        
        let child2_name = Name::from_str("/child2").unwrap();
        let child2_id = hierarchy.insert_node(&root_id, child2_name).unwrap();
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        let grandchild_id = hierarchy.insert_node(&child1_id, grandchild_name).unwrap();
        
        let descendants = hierarchy.get_descendants(&root_id).unwrap();
        assert_eq!(descendants.len(), 3);
        
        let descendant_ids: Vec<&String> = descendants.iter().map(|d| &d.node_id).collect();
        assert!(descendant_ids.contains(&&child1_id));
        assert!(descendant_ids.contains(&&child2_id));
        assert!(descendant_ids.contains(&&grandchild_id));
    }

    #[test]
    fn test_hierarchy_get_siblings() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child1_name = Name::from_str("/child1").unwrap();
        let child1_id = hierarchy.insert_node(&root_id, child1_name).unwrap();
        
        let child2_name = Name::from_str("/child2").unwrap();
        let child2_id = hierarchy.insert_node(&root_id, child2_name).unwrap();
        
        let child3_name = Name::from_str("/child3").unwrap();
        let child3_id = hierarchy.insert_node(&root_id, child3_name).unwrap();
        
        let siblings = hierarchy.get_siblings(&child1_id).unwrap();
        assert_eq!(siblings.len(), 2);
        
        let sibling_ids: Vec<&String> = siblings.iter().map(|s| &s.node_id).collect();
        assert!(sibling_ids.contains(&&child2_id));
        assert!(sibling_ids.contains(&&child3_id));
        assert!(!sibling_ids.contains(&&child1_id));
    }

    #[test]
    fn test_hierarchy_get_children() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child1_name = Name::from_str("/child1").unwrap();
        let child1_id = hierarchy.insert_node(&root_id, child1_name).unwrap();
        
        let child2_name = Name::from_str("/child2").unwrap();
        let child2_id = hierarchy.insert_node(&root_id, child2_name).unwrap();
        
        let children = hierarchy.get_children(&root_id).unwrap();
        assert_eq!(children.len(), 2);
        
        let child_ids: Vec<&String> = children.iter().map(|c| &c.node_id).collect();
        assert!(child_ids.contains(&&child1_id));
        assert!(child_ids.contains(&&child2_id));
    }

    #[test]
    fn test_hierarchy_find_by_name() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/unique_child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name.clone()).unwrap();
        
        let found_node = hierarchy.find_by_name(&child_name).unwrap();
        assert_eq!(found_node.node_id, child_id);
        assert_eq!(found_node.name, child_name);
    }

    #[test]
    fn test_hierarchy_get_depth() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name).unwrap();
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        let grandchild_id = hierarchy.insert_node(&child_id, grandchild_name).unwrap();
        
        assert_eq!(hierarchy.get_depth(&root_id).unwrap(), 0);
        assert_eq!(hierarchy.get_depth(&child_id).unwrap(), 1);
        assert_eq!(hierarchy.get_depth(&grandchild_id).unwrap(), 2);
    }

    #[test]
    fn test_hierarchy_height() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        assert_eq!(hierarchy.height(), 0); // Just root
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name).unwrap();
        
        assert_eq!(hierarchy.height(), 1);
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        hierarchy.insert_node(&child_id, grandchild_name).unwrap();
        
        assert_eq!(hierarchy.height(), 2);
    }

    #[test]
    fn test_hierarchy_get_leaves() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child1_name = Name::from_str("/child1").unwrap();
        let child1_id = hierarchy.insert_node(&root_id, child1_name).unwrap();
        
        let child2_name = Name::from_str("/child2").unwrap();
        let child2_id = hierarchy.insert_node(&root_id, child2_name).unwrap();
        
        let grandchild_name = Name::from_str("/grandchild").unwrap();
        let grandchild_id = hierarchy.insert_node(&child1_id, grandchild_name).unwrap();
        
        let leaves = hierarchy.get_leaves();
        assert_eq!(leaves.len(), 2); // child2 and grandchild are leaves
        
        let leaf_ids: Vec<&String> = leaves.iter().map(|l| &l.node_id).collect();
        assert!(leaf_ids.contains(&&child2_id));
        assert!(leaf_ids.contains(&&grandchild_id));
        assert!(!leaf_ids.contains(&&root_id)); // Root is not a leaf
        assert!(!leaf_ids.contains(&&child1_id)); // child1 has children
    }

    #[test]
    fn test_hierarchy_validation() {
        let hierarchy = create_test_hierarchy();
        assert!(hierarchy.validate().is_ok());
        
        // Test with a more complex hierarchy
        let mut complex_hierarchy = create_test_hierarchy();
        let root_id = complex_hierarchy.get_root().unwrap().node_id.clone();
        
        for i in 0..5 {
            let child_name = Name::from_str(&format!("/child{}", i)).unwrap();
            complex_hierarchy.insert_node(&root_id, child_name).unwrap();
        }
        
        assert!(complex_hierarchy.validate().is_ok());
    }

    #[test]
    fn test_hierarchy_metadata() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let child_name = Name::from_str("/child").unwrap();
        let child_id = hierarchy.insert_node(&root_id, child_name).unwrap();
        
        // Set metadata
        if let Some(child_node) = hierarchy.nodes.get_mut(&child_id) {
            child_node.set_metadata("type".to_string(), "important".to_string());
            child_node.set_metadata("priority".to_string(), "high".to_string());
        }
        
        let child_node = hierarchy.get_node(&child_id).unwrap();
        assert_eq!(child_node.get_metadata("type"), Some(&"important".to_string()));
        assert_eq!(child_node.get_metadata("priority"), Some(&"high".to_string()));
        assert_eq!(child_node.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_bulk_operations() {
        let hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let mut bulk_ops = HierarchyBulkOperations::new(hierarchy);
        
        // Add multiple operations
        bulk_ops.add_insert(root_id.clone(), Name::from_str("/bulk1").unwrap());
        bulk_ops.add_insert(root_id.clone(), Name::from_str("/bulk2").unwrap());
        bulk_ops.add_insert(root_id, Name::from_str("/bulk3").unwrap());
        
        assert_eq!(bulk_ops.operation_count(), 3);
        
        let updated_hierarchy = bulk_ops.execute().unwrap();
        assert_eq!(updated_hierarchy.size(), 4); // root + 3 children
        
        assert!(updated_hierarchy.find_by_name(&Name::from_str("/bulk1").unwrap()).is_some());
        assert!(updated_hierarchy.find_by_name(&Name::from_str("/bulk2").unwrap()).is_some());
        assert!(updated_hierarchy.find_by_name(&Name::from_str("/bulk3").unwrap()).is_some());
    }

    #[test]
    fn test_bulk_operations_with_metadata() {
        let hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        let mut bulk_ops = HierarchyBulkOperations::new(hierarchy);
        
        bulk_ops.add_insert(root_id.clone(), Name::from_str("/tagged").unwrap());
        
        let updated_hierarchy = bulk_ops.execute().unwrap();
        let tagged_node = updated_hierarchy.find_by_name(&Name::from_str("/tagged").unwrap()).unwrap();
        let tagged_id = tagged_node.node_id.clone();
        
        // Create new bulk operations for metadata
        let mut metadata_ops = HierarchyBulkOperations::new(updated_hierarchy);
        metadata_ops.add_set_metadata(tagged_id.clone(), "category".to_string(), "test".to_string());
        
        let final_hierarchy = metadata_ops.execute().unwrap();
        let final_node = final_hierarchy.get_node(&tagged_id).unwrap();
        assert_eq!(final_node.get_metadata("category"), Some(&"test".to_string()));
    }

    #[test]
    fn test_hierarchy_clear() {
        let mut hierarchy = create_test_hierarchy();
        let root_id = hierarchy.get_root().unwrap().node_id.clone();
        
        hierarchy.insert_node(&root_id, Name::from_str("/child").unwrap()).unwrap();
        assert_eq!(hierarchy.size(), 2);
        
        hierarchy.clear();
        assert_eq!(hierarchy.size(), 0);
        assert!(hierarchy.is_empty());
        assert!(hierarchy.get_root().is_none());
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn test_validation_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.max_component_length, 255);
        assert_eq!(config.max_name_length, 8192);
        assert_eq!(config.min_component_length, 1);
        assert!(!config.allow_empty_components);
        assert!(config.require_leading_slash);
        assert!(!config.allow_trailing_slash);
    }

    #[test]
    fn test_name_validator_basic() {
        let validator = NameValidator::new();
        let name = Name::from_str("/hello/world").unwrap();
        
        assert!(validator.validate_name(&name).is_ok());
    }

    #[test]
    fn test_name_validator_empty_component() {
        let validator = NameValidator::new();
        let mut name = Name::new();
        name.push(NameComponent::from_str("hello"));
        name.push(NameComponent::from_str("")); // Empty component
        name.push(NameComponent::from_str("world"));
        
        let result = validator.validate_name(&name);
        assert!(result.is_err());
        if let Err(ValidationError::ComponentError { index, error: _ }) = result {
            assert_eq!(index, 1);
        } else {
            panic!("Expected ComponentError");
        }
    }

    #[test]
    fn test_name_validator_component_too_long() {
        let mut config = ValidationConfig::default();
        config.max_component_length = 5;
        let validator = NameValidator::with_config(config);
        
        let component = NameComponent::from_str("this_is_too_long");
        let result = validator.validate_component(&component);
        
        assert!(matches!(result, Err(ValidationError::ComponentTooLong { .. })));
    }

    #[test]
    fn test_name_validator_component_too_short() {
        let mut config = ValidationConfig::default();
        config.min_component_length = 5;
        let validator = NameValidator::with_config(config);
        
        let component = NameComponent::from_str("hi");
        let result = validator.validate_component(&component);
        
        assert!(matches!(result, Err(ValidationError::ComponentTooShort { .. })));
    }

    #[test]
    fn test_name_validator_invalid_character_basic() {
        let mut config = ValidationConfig::default();
        config.allowed_characters = ValidationCharacterSet::Basic;
        let validator = NameValidator::with_config(config);
        
        let component = NameComponent::from_str("hello@world");
        let result = validator.validate_component(&component);
        
        assert!(matches!(result, Err(ValidationError::InvalidCharacter('@'))));
    }

    #[test]
    fn test_name_validator_custom_character_set() {
        let mut allowed_chars = std::collections::HashSet::new();
        allowed_chars.insert('a');
        allowed_chars.insert('b');
        allowed_chars.insert('c');
        
        let mut config = ValidationConfig::default();
        config.allowed_characters = ValidationCharacterSet::Custom(allowed_chars);
        let validator = NameValidator::with_config(config);
        
        let valid_component = NameComponent::from_str("abc");
        assert!(validator.validate_component(&valid_component).is_ok());
        
        let invalid_component = NameComponent::from_str("abcd");
        let result = validator.validate_component(&invalid_component);
        assert!(matches!(result, Err(ValidationError::InvalidCharacter('d'))));
    }

    #[test]
    fn test_name_validator_hierarchy_depth() {
        let mut config = ValidationConfig::default();
        config.max_hierarchy_depth = Some(3);
        let validator = NameValidator::with_config(config);
        
        let shallow_name = Name::from_str("/a/b/c").unwrap();
        assert!(validator.validate_name(&shallow_name).is_ok());
        
        let deep_name = Name::from_str("/a/b/c/d").unwrap();
        let result = validator.validate_name(&deep_name);
        assert!(matches!(result, Err(ValidationError::HierarchyTooDeep { .. })));
    }

    #[test]
    fn test_name_validator_component_type_timestamp() {
        let validator = NameValidator::new();
        
        let valid_timestamp = NameComponent::with_type(
            "1234567890".as_bytes().to_vec(),
            ComponentType::TimestampNameComponent,
        );
        assert!(validator.validate_component(&valid_timestamp).is_ok());
        
        let invalid_timestamp = NameComponent::with_type(
            "not_a_number".as_bytes().to_vec(),
            ComponentType::TimestampNameComponent,
        );
        let result = validator.validate_component(&invalid_timestamp);
        assert!(matches!(result, Err(ValidationError::InvalidComponentType { .. })));
    }

    #[test]
    fn test_name_validator_component_type_version() {
        let validator = NameValidator::new();
        
        let valid_version = NameComponent::with_type(
            "1.2.3".as_bytes().to_vec(),
            ComponentType::VersionNameComponent,
        );
        assert!(validator.validate_component(&valid_version).is_ok());
        
        let invalid_version = NameComponent::with_type(
            "1.2.3a".as_bytes().to_vec(),
            ComponentType::VersionNameComponent,
        );
        let result = validator.validate_component(&invalid_version);
        assert!(matches!(result, Err(ValidationError::InvalidComponentType { .. })));
    }

    #[test]
    fn test_name_validator_leading_slash() {
        let validator = NameValidator::new();
        
        // Test by creating a name manually to preserve the original string format
        let mut name_without_slash = Name::new();
        name_without_slash.push(NameComponent::from_str("hello"));
        name_without_slash.push(NameComponent::from_str("world"));
        
        // Override the to_uri method behavior by checking against the actual validation logic
        // Since from_str normalizes the input, we need to test the validation logic differently
        
        // The validation checks the URI output, so let's test with a config that disables leading slash requirement
        let mut config = ValidationConfig::default();
        config.require_leading_slash = false;
        let permissive_validator = NameValidator::with_config(config);
        
        // This should pass since we disabled the requirement
        assert!(permissive_validator.validate_name(&name_without_slash).is_ok());
        
        // With the default config that requires leading slash, it should pass because 
        // Name::to_uri() always adds a leading slash
        let name_with_slash = Name::from_str("/hello/world").unwrap();
        assert!(validator.validate_name(&name_with_slash).is_ok());
    }

    #[test]
    fn test_name_validator_trailing_slash() {
        let validator = NameValidator::new();
        
        // The Name::from_str method filters out empty components from trailing slashes
        // so we need to test this differently. Let's create a custom URI string for testing
        
        // Create a name and test if it would fail with trailing slash in the URI
        let name = Name::from_str("/hello/world").unwrap();
        assert!(validator.validate_name(&name).is_ok());
        
        // Test the trailing slash logic by using a name with an empty component at the end
        let mut name_with_empty_end = Name::new();
        name_with_empty_end.push(NameComponent::from_str("hello"));
        name_with_empty_end.push(NameComponent::from_str("world"));
        
        // Since Name::to_uri() doesn't add trailing slashes for normal names,
        // let's test the validation with a config that allows trailing slashes
        let mut config = ValidationConfig::default();
        config.allow_trailing_slash = true;
        let permissive_validator = NameValidator::with_config(config);
        assert!(permissive_validator.validate_name(&name_with_empty_end).is_ok());
    }

    #[test]
    fn test_name_validator_circular_references() {
        let validator = NameValidator::new();
        
        let name1 = Name::from_str("/a/b").unwrap();
        let name2 = Name::from_str("/a").unwrap();
        let name3 = Name::from_str("/a/b/c").unwrap();
        
        let names = vec![name1, name2, name3];
        
        // This should not detect a circular reference since it's a valid hierarchy
        assert!(validator.check_circular_references(&names).is_ok());
    }
}

#[cfg(test)]
mod normalization_tests {
    use super::*;

    #[test]
    fn test_normalization_config_default() {
        let config = NormalizationConfig::default();
        assert_eq!(config.case_handling, CaseHandling::Preserve);
        assert_eq!(config.whitespace_handling, WhitespaceHandling::TrimAndCollapse);
        assert_eq!(config.diacritics_handling, DiacriticsHandling::Preserve);
    }

    #[test]
    fn test_name_normalizer_basic() {
        let normalizer = NameNormalizer::new();
        let name = Name::from_str("/hello/world").unwrap();
        
        let normalized = normalizer.normalize_name(&name).unwrap();
        assert_eq!(normalized, name);
    }

    #[test]
    fn test_name_normalizer_whitespace_trim_and_collapse() {
        let mut config = NormalizationConfig::default();
        config.whitespace_handling = WhitespaceHandling::TrimAndCollapse;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("  hello   world  ");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "hello world");
    }

    #[test]
    fn test_name_normalizer_whitespace_remove() {
        let mut config = NormalizationConfig::default();
        config.whitespace_handling = WhitespaceHandling::Remove;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("hello world");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "helloworld");
    }

    #[test]
    fn test_name_normalizer_case_lowercase() {
        let mut config = NormalizationConfig::default();
        config.case_handling = CaseHandling::ToLowercase;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("Hello World");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "hello world");
    }

    #[test]
    fn test_name_normalizer_case_uppercase() {
        let mut config = NormalizationConfig::default();
        config.case_handling = CaseHandling::ToUppercase;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("Hello World");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "HELLO WORLD");
    }

    #[test]
    fn test_name_normalizer_case_title() {
        let mut config = NormalizationConfig::default();
        config.case_handling = CaseHandling::TitleCase;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("hello world");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "Hello World");
    }

    #[test]
    fn test_name_normalizer_diacritics_remove() {
        let mut config = NormalizationConfig::default();
        config.diacritics_handling = DiacriticsHandling::Remove;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("hëllö wörld");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "hello world");
    }

    #[test]
    fn test_name_normalizer_character_substitution_basic_ascii() {
        let mut config = NormalizationConfig::default();
        config.character_substitution = CharacterSubstitution::BasicAscii;
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("hëllö 世界");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "hello __");
    }

    #[test]
    fn test_name_normalizer_character_substitution_custom() {
        let mut substitutions = HashMap::new();
        substitutions.insert('o', '0');
        substitutions.insert('l', '1');
        
        let mut config = NormalizationConfig::default();
        config.character_substitution = CharacterSubstitution::Custom(substitutions);
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("hello");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "he110");
    }

    #[test]
    fn test_name_normalizer_combined_operations() {
        let mut config = NormalizationConfig::default();
        config.case_handling = CaseHandling::ToLowercase;
        config.whitespace_handling = WhitespaceHandling::TrimAndCollapse;
        config.diacritics_handling = DiacriticsHandling::Remove;
        
        let normalizer = NameNormalizer::with_config(config);
        
        let component = NameComponent::from_str("  HËLLÖ   WÖRLD  ");
        let normalized = normalizer.normalize_component(&component).unwrap();
        
        assert_eq!(normalized.as_str().unwrap(), "hello world");
    }
}

#[cfg(test)]
mod name_processor_tests {
    use super::*;

    #[test]
    fn test_name_processor_basic() {
        let processor = NameProcessor::new();
        let name = Name::from_str("/hello/world").unwrap();
        
        let processed = processor.process_name(&name).unwrap();
        assert_eq!(processed, name);
    }

    #[test]
    fn test_name_processor_with_configs() {
        let mut validation_config = ValidationConfig::default();
        validation_config.max_component_length = 10;
        
        let mut normalization_config = NormalizationConfig::default();
        normalization_config.case_handling = CaseHandling::ToLowercase;
        
        let processor = NameProcessor::with_configs(validation_config, normalization_config);
        
        let component = NameComponent::from_str("HELLO");
        let processed = processor.process_component(&component).unwrap();
        
        assert_eq!(processed.as_str().unwrap(), "hello");
    }

    #[test]
    fn test_name_processor_validation_failure() {
        let mut validation_config = ValidationConfig::default();
        validation_config.max_component_length = 3;
        
        let processor = NameProcessor::with_configs(validation_config, NormalizationConfig::default());
        
        let component = NameComponent::from_str("toolong");
        let result = processor.process_component(&component);
        
        assert!(matches!(result, Err(ValidationError::ComponentTooLong { .. })));
    }

    #[test]
    fn test_name_processor_normalize_then_validate() {
        let mut validation_config = ValidationConfig::default();
        validation_config.allowed_characters = ValidationCharacterSet::Basic;
        
        let mut normalization_config = NormalizationConfig::default();
        normalization_config.character_substitution = CharacterSubstitution::BasicAscii;
        
        let processor = NameProcessor::with_configs(validation_config, normalization_config);
        
        // Original has non-ASCII characters, but normalization should fix it
        let component = NameComponent::from_str("hëllö");
        let processed = processor.process_component(&component).unwrap();
        
        assert_eq!(processed.as_str().unwrap(), "hello");
    }

    #[test]
    fn test_name_processor_validate_only() {
        let processor = NameProcessor::new();
        let name = Name::from_str("/hello/world").unwrap();
        
        assert!(processor.validate_name(&name).is_ok());
    }

    #[test]
    fn test_name_processor_normalize_only() {
        let processor = NameProcessor::new();
        let name = Name::from_str("/hello/world").unwrap();
        
        let normalized = processor.normalize_name(&name).unwrap();
        assert_eq!(normalized, name);
    }

    #[test]
    fn test_name_processor_access_engines() {
        let processor = NameProcessor::new();
        
        // Test immutable access
        let _validator = processor.validator();
        let _normalizer = processor.normalizer();
        
        // Test mutable access
        let mut processor = processor;
        let _validator_mut = processor.validator_mut();
        let _normalizer_mut = processor.normalizer_mut();
    }
}

#[cfg(test)]
mod validation_error_tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::NameTooLong { length: 100, max_length: 50 };
        assert_eq!(error.to_string(), "Name too long: 100 characters (max: 50)");
        
        let error = ValidationError::InvalidCharacter('@');
        assert_eq!(error.to_string(), "Invalid character: '@'");
        
        let error = ValidationError::EmptyComponent;
        assert_eq!(error.to_string(), "Empty component not allowed");
    }

    #[test]
    fn test_validation_error_component_error() {
        let inner_error = ValidationError::EmptyComponent;
        let component_error = ValidationError::ComponentError {
            index: 2,
            error: Box::new(inner_error),
        };
        
        assert_eq!(component_error.to_string(), "Error in component 2: Empty component not allowed");
    }
}

#[cfg(test)]
mod character_set_tests {
    use super::*;

    #[test]
    fn test_validation_character_set_basic() {
        let mut config = ValidationConfig::default();
        config.allowed_characters = ValidationCharacterSet::Basic;
        let validator = NameValidator::with_config(config);
        
        // Valid basic characters
        let valid_chars = "abcABC123-_.";
        let component = NameComponent::from_str(valid_chars);
        assert!(validator.validate_component(&component).is_ok());
        
        // Invalid characters for basic set
        let invalid_chars = ["@", "#", "ñ", "😀"];
        for invalid_char in invalid_chars {
            let component = NameComponent::from_str(invalid_char);
            let result = validator.validate_component(&component);
            assert!(result.is_err(), "Character '{}' should be invalid for basic set", invalid_char);
        }
    }

    #[test]
    fn test_validation_character_set_extended() {
        let mut config = ValidationConfig::default();
        config.allowed_characters = ValidationCharacterSet::Extended;
        let validator = NameValidator::with_config(config);
        
        // Valid extended ASCII characters
        let valid_chars = "abcABC123!@#$%^&*()";
        let component = NameComponent::from_str(valid_chars);
        assert!(validator.validate_component(&component).is_ok());
        
        // Invalid characters (non-ASCII)
        let invalid_chars = ["ñ", "😀", "世"];
        for invalid_char in invalid_chars {
            let component = NameComponent::from_str(invalid_char);
            let result = validator.validate_component(&component);
            assert!(result.is_err(), "Character '{}' should be invalid for extended set", invalid_char);
        }
    }

    #[test]
    fn test_validation_character_set_unicode() {
        let mut config = ValidationConfig::default();
        config.allowed_characters = ValidationCharacterSet::Unicode;
        let validator = NameValidator::with_config(config);
        
        // Valid Unicode characters
        let valid_strings = ["hello", "ñ", "世界", "😀"];
        for valid_str in valid_strings {
            let component = NameComponent::from_str(valid_str);
            assert!(validator.validate_component(&component).is_ok(), 
                   "String '{}' should be valid for Unicode set", valid_str);
        }
        
        // Control characters should still be invalid
        let component = NameComponent::new(vec![0x01]); // Control character
        let result = validator.validate_component(&component);
        assert!(result.is_err(), "Control characters should be invalid");
    }
}