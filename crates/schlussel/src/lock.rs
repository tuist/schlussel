use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use fs4::FileExt;

use crate::error::{Result, SchlusselError};
use crate::session;

#[derive(Debug, Clone)]
pub struct RefreshLockManager {
    lock_dir: PathBuf,
}

impl RefreshLockManager {
    pub fn new(app_name: &str) -> Result<Self> {
        let lock_dir = session::lock_dir(app_name);
        fs::create_dir_all(&lock_dir)?;
        Ok(Self { lock_dir })
    }

    pub fn with_path(path: impl AsRef<Path>) -> Result<Self> {
        let lock_dir = path.as_ref().to_path_buf();
        fs::create_dir_all(&lock_dir)?;
        Ok(Self { lock_dir })
    }

    pub fn acquire(&self, key: &str) -> Result<RefreshLock> {
        RefreshLock::acquire(&self.lock_dir, key, false)
    }

    pub fn try_acquire(&self, key: &str) -> Result<Option<RefreshLock>> {
        RefreshLock::acquire(&self.lock_dir, key, true)
            .map(Some)
            .or_else(|error| match error {
                SchlusselError::Lock(message) if message == "would block" => Ok(None),
                _ => Err(error),
            })
    }
}

#[derive(Debug)]
pub struct RefreshLock {
    file: Option<File>,
    path: PathBuf,
}

impl RefreshLock {
    fn acquire(lock_dir: &Path, key: &str, nonblocking: bool) -> Result<Self> {
        if key.is_empty() {
            return Err(SchlusselError::invalid_parameter(
                "lock key must not be empty",
            ));
        }

        let path = lock_dir.join(format!("{}.lock", URL_SAFE_NO_PAD.encode(key.as_bytes())));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;

        let outcome = if nonblocking {
            file.try_lock_exclusive()
        } else {
            file.lock_exclusive()
        };

        if let Err(error) = outcome {
            return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
                SchlusselError::Lock("would block".to_string())
            } else {
                SchlusselError::Lock(error.to_string())
            });
        }

        Ok(Self {
            file: Some(file),
            path,
        })
    }

    pub fn is_held(&self) -> bool {
        self.file.is_some()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn release(&mut self) -> Result<()> {
        if let Some(file) = self.file.take() {
            file.unlock()
                .map_err(|error| SchlusselError::Lock(error.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for RefreshLock {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn lock_manager_roundtrip() {
        let temp = tempdir().expect("tempdir");
        let manager = RefreshLockManager::with_path(temp.path()).expect("manager");
        let lock = manager.acquire("github:device_code").expect("lock");
        assert!(lock.is_held());
    }
}
