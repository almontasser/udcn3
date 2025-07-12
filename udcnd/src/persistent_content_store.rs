use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use udcn_core::packets::Data;

/// Serializable version of ContentEntry for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableContentEntry {
    pub data: Data,
    pub stored_at_unix_nanos: u128,
    pub freshness_period_secs: Option<u64>,
    pub access_count: u64,
}

impl SerializableContentEntry {
    pub fn from_content_entry(entry: &super::packet_handler::ContentEntry) -> Self {
        Self {
            data: entry.data.clone(),
            stored_at_unix_nanos: entry.stored_at.elapsed().as_nanos(),
            freshness_period_secs: entry.freshness_period.map(|d| d.as_secs()),
            access_count: entry.access_count,
        }
    }

    pub fn to_content_entry(&self) -> super::packet_handler::ContentEntry {
        // Calculate stored_at by subtracting elapsed time from now
        let now = Instant::now();
        let elapsed_duration = Duration::from_nanos(self.stored_at_unix_nanos as u64);
        let stored_at = now.checked_sub(elapsed_duration).unwrap_or(now);

        super::packet_handler::ContentEntry {
            data: self.data.clone(),
            stored_at,
            freshness_period: self.freshness_period_secs.map(Duration::from_secs),
            access_count: self.access_count,
        }
    }
}

/// Configuration for persistent content store
#[derive(Debug, Clone)]
pub struct PersistentContentStoreConfig {
    /// Directory where content store data is persisted
    pub data_directory: PathBuf,
    /// Maximum number of entries to persist
    pub max_entries: usize,
    /// Auto-save interval in seconds
    pub auto_save_interval_secs: u64,
    /// Compression enabled for storage
    pub compression_enabled: bool,
    /// Backup enabled
    pub backup_enabled: bool,
    /// Maximum file size for single storage file (in bytes)
    pub max_file_size_bytes: usize,
}

impl Default for PersistentContentStoreConfig {
    fn default() -> Self {
        Self {
            data_directory: PathBuf::from("./udcn_content_store"),
            max_entries: 10000,
            auto_save_interval_secs: 30,
            compression_enabled: true,
            backup_enabled: true,
            max_file_size_bytes: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Statistics for persistent content store
#[derive(Debug, Clone, Default)]
pub struct PersistentContentStoreStats {
    pub entries_loaded: u64,
    pub entries_saved: u64,
    pub entries_purged: u64,
    pub save_operations: u64,
    pub load_operations: u64,
    pub last_save_time: Option<SystemTime>,
    pub last_load_time: Option<SystemTime>,
    pub storage_size_bytes: u64,
}

/// Persistent content store implementation
pub struct PersistentContentStore {
    config: PersistentContentStoreConfig,
    stats: PersistentContentStoreStats,
    is_initialized: bool,
}

impl PersistentContentStore {
    /// Create a new persistent content store
    pub fn new(config: PersistentContentStoreConfig) -> Self {
        Self {
            config,
            stats: PersistentContentStoreStats::default(),
            is_initialized: false,
        }
    }

    /// Initialize the persistent content store
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create data directory if it doesn't exist
        if !self.config.data_directory.exists() {
            fs::create_dir_all(&self.config.data_directory).await?;
            info!("Created content store data directory: {:?}", self.config.data_directory);
        }

        self.is_initialized = true;
        info!("Persistent content store initialized with config: {:?}", self.config);
        Ok(())
    }

    /// Save content store to disk
    pub async fn save_content_store(
        &mut self,
        content_store: &HashMap<String, super::packet_handler::ContentEntry>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.is_initialized {
            return Err("Persistent content store not initialized".into());
        }

        let start_time = Instant::now();
        info!("Saving content store with {} entries", content_store.len());

        // Convert to serializable format
        let serializable_entries: HashMap<String, SerializableContentEntry> = content_store
            .iter()
            .filter_map(|(name, entry)| {
                // Only save fresh entries
                if entry.is_fresh() {
                    Some((name.clone(), SerializableContentEntry::from_content_entry(entry)))
                } else {
                    None
                }
            })
            .collect();

        if serializable_entries.is_empty() {
            debug!("No fresh entries to save");
            return Ok(());
        }

        // Create backup if enabled
        if self.config.backup_enabled {
            self.create_backup().await?;
        }

        // Serialize to JSON
        let json_data = serde_json::to_string_pretty(&serializable_entries)?;
        
        // Optionally compress
        let data_to_write = if self.config.compression_enabled {
            // For now, just use the JSON directly. Could add compression here.
            json_data.into_bytes()
        } else {
            json_data.into_bytes()
        };

        // Write to temporary file first, then rename for atomicity
        let data_file_path = self.config.data_directory.join("content_store.json");
        let temp_file_path = self.config.data_directory.join("content_store.json.tmp");

        let mut file = File::create(&temp_file_path).await?;
        file.write_all(&data_to_write).await?;
        file.sync_all().await?;
        drop(file);

        // Atomic rename
        fs::rename(&temp_file_path, &data_file_path).await?;

        // Write metadata
        let metadata = PersistentContentStoreMetadata {
            version: 1,
            entry_count: serializable_entries.len(),
            saved_at: SystemTime::now(),
            compression_enabled: self.config.compression_enabled,
        };

        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        let metadata_path = self.config.data_directory.join("metadata.json");
        fs::write(&metadata_path, metadata_json).await?;

        // Update statistics
        self.stats.entries_saved = serializable_entries.len() as u64;
        self.stats.save_operations += 1;
        self.stats.last_save_time = Some(SystemTime::now());
        self.stats.storage_size_bytes = data_to_write.len() as u64;

        let elapsed = start_time.elapsed();
        info!(
            "Successfully saved {} entries to disk in {:?}",
            serializable_entries.len(),
            elapsed
        );

        Ok(())
    }

    /// Load content store from disk
    pub async fn load_content_store(
        &mut self,
    ) -> Result<HashMap<String, super::packet_handler::ContentEntry>, Box<dyn std::error::Error + Send + Sync>> {
        if !self.is_initialized {
            return Err("Persistent content store not initialized".into());
        }

        let start_time = Instant::now();
        let data_file_path = self.config.data_directory.join("content_store.json");

        if !data_file_path.exists() {
            info!("No existing content store data found");
            return Ok(HashMap::new());
        }

        info!("Loading content store from disk");

        // Read file
        let data = fs::read(&data_file_path).await?;

        // Decompress if needed (for now, just treat as plain JSON)
        let json_str = String::from_utf8(data)?;

        // Deserialize
        let serializable_entries: HashMap<String, SerializableContentEntry> = 
            serde_json::from_str(&json_str)?;

        // Convert back to content entries and filter out expired ones
        let mut content_store = HashMap::new();
        let mut expired_count = 0;

        for (name, serializable_entry) in serializable_entries {
            let entry = serializable_entry.to_content_entry();
            
            if entry.is_fresh() {
                content_store.insert(name, entry);
            } else {
                expired_count += 1;
            }
        }

        // Update statistics
        self.stats.entries_loaded = content_store.len() as u64;
        self.stats.entries_purged = expired_count;
        self.stats.load_operations += 1;
        self.stats.last_load_time = Some(SystemTime::now());

        let elapsed = start_time.elapsed();
        info!(
            "Successfully loaded {} entries from disk (purged {} expired) in {:?}",
            content_store.len(),
            expired_count,
            elapsed
        );

        Ok(content_store)
    }

    /// Create a backup of the current content store
    async fn create_backup(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data_file_path = self.config.data_directory.join("content_store.json");
        
        if !data_file_path.exists() {
            return Ok(());
        }

        let backup_dir = self.config.data_directory.join("backups");
        if !backup_dir.exists() {
            fs::create_dir_all(&backup_dir).await?;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let backup_file_path = backup_dir.join(format!("content_store_backup_{}.json", timestamp));
        
        fs::copy(&data_file_path, &backup_file_path).await?;
        debug!("Created backup: {:?}", backup_file_path);

        // Clean up old backups (keep only last 5)
        self.cleanup_old_backups(&backup_dir).await?;

        Ok(())
    }

    /// Clean up old backup files
    async fn cleanup_old_backups(&self, backup_dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = fs::read_dir(backup_dir).await?;
        let mut backup_files = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() && path.file_name().unwrap_or_default().to_string_lossy().starts_with("content_store_backup_") {
                if let Ok(metadata) = entry.metadata().await {
                    backup_files.push((path, metadata.modified()?));
                }
            }
        }

        // Sort by modification time (newest first)
        backup_files.sort_by(|a, b| b.1.cmp(&a.1));

        // Remove old backups (keep only 5 most recent)
        for (path, _) in backup_files.into_iter().skip(5) {
            if let Err(e) = fs::remove_file(&path).await {
                warn!("Failed to remove old backup {:?}: {}", path, e);
            } else {
                debug!("Removed old backup: {:?}", path);
            }
        }

        Ok(())
    }

    /// Get persistent content store statistics
    pub fn get_stats(&self) -> &PersistentContentStoreStats {
        &self.stats
    }

    /// Check if the store is initialized
    pub fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    /// Get the data directory path
    pub fn get_data_directory(&self) -> &Path {
        &self.config.data_directory
    }
}

/// Metadata for the persistent content store
#[derive(Debug, Serialize, Deserialize)]
struct PersistentContentStoreMetadata {
    version: u32,
    entry_count: usize,
    saved_at: SystemTime,
    compression_enabled: bool,
}