use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::error::{Result, SchlusselError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

impl Token {
    pub fn new(access_token: impl Into<String>, token_type: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            token_type: token_type.into(),
            refresh_token: None,
            expires_in: None,
            expires_at: None,
            scope: None,
            id_token: None,
        }
    }

    pub fn with_expiration(mut self, expires_in: Option<u64>) -> Self {
        self.expires_in = expires_in;
        self.expires_at = expires_in.map(|ttl| current_unix_timestamp() + ttl);
        self
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| current_unix_timestamp() >= expires_at)
    }

    pub fn expires_within(&self, seconds: u64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| current_unix_timestamp() + seconds >= expires_at)
    }

    pub fn remaining_lifetime_fraction(&self) -> Option<f64> {
        let expires_at = self.expires_at?;
        let expires_in = self.expires_in?;
        let now = current_unix_timestamp();
        if now >= expires_at {
            return Some(0.0);
        }
        Some((expires_at - now) as f64 / expires_in as f64)
    }
}

pub trait SessionStorage: Send + Sync {
    fn save(&self, key: &str, token: &Token) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Token>>;
    fn delete(&self, key: &str) -> Result<()>;
    fn list_keys(&self) -> Result<Vec<String>>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryStorage {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStorage for MemoryStorage {
    fn save(&self, key: &str, token: &Token) -> Result<()> {
        self.tokens
            .lock()
            .map_err(|error| SchlusselError::storage(error.to_string()))?
            .insert(key.to_string(), token.clone());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Token>> {
        Ok(self
            .tokens
            .lock()
            .map_err(|error| SchlusselError::storage(error.to_string()))?
            .get(key)
            .cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.tokens
            .lock()
            .map_err(|error| SchlusselError::storage(error.to_string()))?
            .remove(key);
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = self
            .tokens
            .lock()
            .map_err(|error| SchlusselError::storage(error.to_string()))?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }
}

#[derive(Debug, Clone)]
pub struct FileStorage {
    root: PathBuf,
}

impl FileStorage {
    pub fn new(app_name: &str) -> Result<Self> {
        let root = data_dir(app_name);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn with_path(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn token_path(&self, key: &str) -> PathBuf {
        let encoded = URL_SAFE_NO_PAD.encode(key.as_bytes());
        self.root.join(format!("{encoded}.json"))
    }
}

impl SessionStorage for FileStorage {
    fn save(&self, key: &str, token: &Token) -> Result<()> {
        let path = self.token_path(key);
        let contents = serde_json::to_vec_pretty(token)?;
        let mut temp = NamedTempFile::new_in(&self.root)?;
        temp.write_all(&contents)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        temp.persist(&path).map_err(|error| error.error)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Token>> {
        let path = self.token_path(key);
        match fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.token_path(key);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }

            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Ok(decoded) = URL_SAFE_NO_PAD.decode(stem) else {
                continue;
            };
            let Ok(key) = String::from_utf8(decoded) else {
                continue;
            };
            keys.push(key);
        }
        keys.sort();
        Ok(keys)
    }
}

#[derive(Debug, Clone)]
pub struct SecureStorage {
    app_name: String,
}

impl SecureStorage {
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.app_name, key).map_err(Into::into)
    }
}

impl SessionStorage for SecureStorage {
    fn save(&self, key: &str, token: &Token) -> Result<()> {
        let value = serde_json::to_string(token)?;
        self.entry(key)?.set_password(&value)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Token>> {
        match self.entry(key)?.get_password() {
            Ok(value) => Ok(Some(serde_json::from_str(&value)?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        Err(SchlusselError::UnsupportedOperation(
            "secure storage does not support key enumeration".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKey {
    pub formula: String,
    pub method: Option<String>,
    pub identity: Option<String>,
}

pub fn build_storage_key(formula: &str, method: Option<&str>, identity: Option<&str>) -> String {
    match (method, identity) {
        (Some(method), Some(identity)) => format!("{formula}:{method}:{identity}"),
        (Some(method), None) => format!("{formula}:{method}"),
        (None, _) => formula.to_string(),
    }
}

pub fn parse_storage_key(key: &str) -> SessionKey {
    let mut parts = key.split(':');
    let formula = parts.next().unwrap_or_default().to_string();
    let method = parts.next().map(ToString::to_string);
    let identity = parts.next().map(ToString::to_string);

    SessionKey {
        formula,
        method,
        identity,
    }
}

pub fn data_dir(app_name: &str) -> PathBuf {
    if let Some(project_dirs) = ProjectDirs::from("", "", app_name) {
        project_dirs.data_local_dir().to_path_buf()
    } else {
        std::env::temp_dir().join(app_name)
    }
}

pub fn lock_dir(app_name: &str) -> PathBuf {
    if let Some(project_dirs) = ProjectDirs::from("", "", app_name) {
        project_dirs.cache_dir().join("locks")
    } else {
        std::env::temp_dir().join(app_name).join("locks")
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn key_roundtrip_is_stable() {
        let key = build_storage_key("github", Some("device_code"), Some("personal"));
        let parsed = parse_storage_key(&key);
        assert_eq!(parsed.formula, "github");
        assert_eq!(parsed.method.as_deref(), Some("device_code"));
        assert_eq!(parsed.identity.as_deref(), Some("personal"));
    }

    #[test]
    fn file_storage_roundtrip_works() {
        let temp = tempdir().expect("tempdir");
        let storage = FileStorage::with_path(temp.path()).expect("storage");
        let token = Token::new("access", "Bearer").with_expiration(Some(60));

        storage.save("github:device_code", &token).expect("save");
        let loaded = storage
            .load("github:device_code")
            .expect("load")
            .expect("token");
        assert_eq!(loaded.access_token, "access");
        assert_eq!(
            storage.list_keys().expect("keys"),
            vec!["github:device_code"]
        );
    }

    #[test]
    fn file_storage_overwrites_existing_token_atomically() {
        let temp = tempdir().expect("tempdir");
        let storage = FileStorage::with_path(temp.path()).expect("storage");

        storage
            .save("github:device_code", &Token::new("access-1", "Bearer"))
            .expect("initial save");
        storage
            .save("github:device_code", &Token::new("access-2", "Bearer"))
            .expect("replacement save");

        let loaded = storage
            .load("github:device_code")
            .expect("load")
            .expect("token");
        assert_eq!(loaded.access_token, "access-2");
    }
}
