use log::info;

pub mod network;
pub mod protocol;
pub mod security;
pub mod tlv;
pub mod packets;
pub mod name;

pub use network::*;
pub use protocol::*;
pub use security::*;
pub use tlv::*;
pub use packets::{Interest, Data, Packet, MetaInfo, SignatureInfo, KeyLocator, Selectors, Exclude, ContentType, ValidationError, ValidationConfig, tlv_types};
pub use name::{
    Name as ComponentName, NameComponent, NameComponents, ComponentType, NameParseError,
    TrieNode, NameTrie, MatchingConfig, MatchResult, MatchType, PrefixMatcher,
    levenshtein_distance, jaro_winkler_similarity, jaro_similarity, common_prefix_length,
    HierarchyNode, NameHierarchy, HierarchyError, HierarchyBulkOperations, BulkOperation
};

pub fn init() {
    info!("UDCN Core initialized");
}
