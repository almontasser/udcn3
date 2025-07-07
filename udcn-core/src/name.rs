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