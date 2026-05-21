use crate::error::{Result, SchlusselError};
use crate::lock::RefreshLockManager;
use crate::session::{SessionStorage, Token};

use super::client::OAuthClient;

#[derive(Debug, Clone)]
pub struct TokenRefresher<S: SessionStorage> {
    client: OAuthClient<S>,
    lock_manager: Option<RefreshLockManager>,
    refresh_threshold: f64,
}

impl<S: SessionStorage> TokenRefresher<S> {
    pub fn new(client: OAuthClient<S>) -> Self {
        Self {
            client,
            lock_manager: None,
            refresh_threshold: 0.1,
        }
    }

    pub fn with_file_locking(mut self, app_name: &str) -> Result<Self> {
        self.lock_manager = Some(RefreshLockManager::new(app_name)?);
        Ok(self)
    }

    pub fn with_refresh_threshold(mut self, threshold: f64) -> Self {
        self.refresh_threshold = threshold;
        self
    }

    pub fn get_valid_token(&self, key: &str) -> Result<Token> {
        self.get_valid_token_with_threshold(key, self.refresh_threshold)
    }

    pub fn get_valid_token_with_threshold(&self, key: &str, threshold: f64) -> Result<Token> {
        let token = self.load_token(key)?;
        if !token_needs_refresh(&token, threshold) {
            return Ok(token);
        }

        let refresh_token = token
            .refresh_token
            .clone()
            .ok_or(SchlusselError::NoRefreshToken)?;
        let mut lock = self
            .lock_manager
            .as_ref()
            .map(|manager| manager.acquire(key))
            .transpose()?;

        if lock.is_some() {
            let current = self.load_token(key)?;
            if !token_needs_refresh(&current, threshold) {
                return Ok(current);
            }
        }

        let refreshed =
            normalize_refresh_token(self.client.refresh_token(&refresh_token)?, refresh_token);
        self.client.save_token(key, &refreshed)?;
        if let Some(lock) = &mut lock {
            lock.release()?;
        }

        Ok(refreshed)
    }

    fn load_token(&self, key: &str) -> Result<Token> {
        self.client
            .get_token(key)?
            .ok_or_else(|| SchlusselError::TokenNotFound(key.to_string()))
    }
}

fn token_needs_refresh(token: &Token, threshold: f64) -> bool {
    token.is_expired()
        || token
            .remaining_lifetime_fraction()
            .is_some_and(|fraction| fraction <= threshold)
}

fn normalize_refresh_token(mut token: Token, fallback_refresh_token: String) -> Token {
    token.refresh_token.get_or_insert(fallback_refresh_token);
    token
}

#[cfg(test)]
mod tests {
    use super::super::client::OAuthClient;
    use super::super::test_support::{oauth_config, OneShotServer};
    use super::*;
    use crate::session::MemoryStorage;

    #[test]
    fn returns_existing_token_when_it_is_still_fresh() {
        let storage = MemoryStorage::new();
        let token = Token::new("access-1", "Bearer").with_expiration(Some(3600));
        storage
            .save("github:device_code", &token)
            .expect("seed token");

        let client =
            OAuthClient::new(oauth_config("https://example.com/token"), storage).expect("client");
        let refresher = TokenRefresher::new(client);

        let current = refresher
            .get_valid_token("github:device_code")
            .expect("current token");
        assert_eq!(current.access_token, "access-1");
    }

    #[test]
    fn rejects_expired_tokens_without_refresh_token() {
        let storage = MemoryStorage::new();
        let token = Token {
            access_token: "access-1".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: Some(1),
            expires_at: Some(0),
            scope: None,
            id_token: None,
        };
        storage
            .save("github:device_code", &token)
            .expect("seed token");

        let client =
            OAuthClient::new(oauth_config("https://example.com/token"), storage).expect("client");
        let refresher = TokenRefresher::new(client);

        let error = refresher
            .get_valid_token("github:device_code")
            .expect_err("missing refresh token");
        assert!(matches!(error, SchlusselError::NoRefreshToken));
    }

    #[test]
    fn refreshes_expired_token_and_persists_fallback_refresh_token() {
        let server = OneShotServer::respond(
            200,
            "application/json",
            r#"{
                "access_token": "access-2",
                "token_type": "Bearer",
                "expires_in": 3600
            }"#,
        );
        let storage = MemoryStorage::new();
        let token = Token {
            access_token: "access-1".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: Some("refresh-1".to_string()),
            expires_in: Some(1),
            expires_at: Some(0),
            scope: None,
            id_token: None,
        };
        storage
            .save("github:device_code", &token)
            .expect("seed token");

        let client = OAuthClient::new(oauth_config(server.endpoint("/token")), storage.clone())
            .expect("client");
        let refresher = TokenRefresher::new(client);

        let refreshed = refresher
            .get_valid_token("github:device_code")
            .expect("refreshed token");
        let request = server.next_request();
        let saved = storage
            .load("github:device_code")
            .expect("load saved token")
            .expect("persisted token");

        assert_eq!(refreshed.access_token, "access-2");
        assert_eq!(refreshed.refresh_token.as_deref(), Some("refresh-1"));
        assert_eq!(saved.access_token, "access-2");
        assert_eq!(saved.refresh_token.as_deref(), Some("refresh-1"));
        assert!(request.body.contains("grant_type=refresh_token"));
        assert!(request.body.contains("refresh_token=refresh-1"));
    }
}
