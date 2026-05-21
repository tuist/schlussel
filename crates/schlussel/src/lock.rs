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

    #[test]
    fn lock_path_uses_encoded_key_and_creates_file() {
        let temp = tempdir().expect("tempdir");
        let manager = RefreshLockManager::with_path(temp.path()).expect("manager");
        let lock = manager.acquire("github:device_code").expect("lock");
        let expected_path = temp.path().join(format!(
            "{}.lock",
            URL_SAFE_NO_PAD.encode("github:device_code")
        ));

        assert_eq!(lock.path(), expected_path.as_path());
        assert!(expected_path.exists());
    }

    #[test]
    fn try_acquire_returns_none_while_lock_is_held() {
        let temp = tempdir().expect("tempdir");
        let manager = RefreshLockManager::with_path(temp.path()).expect("manager");
        let _held = manager.acquire("github:device_code").expect("held lock");

        let contender = manager
            .try_acquire("github:device_code")
            .expect("try_acquire");
        assert!(contender.is_none());
    }

    #[test]
    fn release_is_idempotent_and_allows_reacquire() {
        let temp = tempdir().expect("tempdir");
        let manager = RefreshLockManager::with_path(temp.path()).expect("manager");
        let mut lock = manager.acquire("github:device_code").expect("lock");

        lock.release().expect("first release");
        assert!(!lock.is_held());
        lock.release().expect("second release");

        let next = manager
            .try_acquire("github:device_code")
            .expect("reacquire after release");
        assert!(next.is_some());
    }

    #[test]
    fn drop_releases_lock_for_future_callers() {
        let temp = tempdir().expect("tempdir");
        let manager = RefreshLockManager::with_path(temp.path()).expect("manager");

        {
            let _held = manager.acquire("github:device_code").expect("held lock");
            assert!(manager
                .try_acquire("github:device_code")
                .expect("contender")
                .is_none());
        }

        let reacquired = manager
            .try_acquire("github:device_code")
            .expect("reacquired after drop");
        assert!(reacquired.is_some());
    }

    #[test]
    fn empty_key_is_rejected() {
        let temp = tempdir().expect("tempdir");
        let manager = RefreshLockManager::with_path(temp.path()).expect("manager");
        let error = manager.acquire("").expect_err("empty key should fail");

        assert!(matches!(
            error,
            SchlusselError::InvalidParameter(message)
            if message.contains("must not be empty")
        ));
    }
}
