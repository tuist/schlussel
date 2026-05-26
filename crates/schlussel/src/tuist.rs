use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use url::Url;

use crate::{Result, SchlusselError, Token};

const TUIST_REFRESH_WINDOW_SECS: u64 = 30;
const TUIST_LOCK_STALE_SECS: u64 = 10;
const TUIST_LOCK_RETRY_INTERVAL_MS: u64 = 500;
const TUIST_LOCK_MAX_ATTEMPTS: usize = 30;

#[derive(Debug, Clone)]
pub struct TuistSessionStore {
    config_dir: PathBuf,
    state_dir: PathBuf,
    http: HttpClient,
}

impl TuistSessionStore {
    pub fn new() -> Result<Self> {
        Self::with_paths(default_tuist_config_dir(), default_tuist_state_dir())
    }

    pub fn with_paths(config_dir: impl AsRef<Path>, state_dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            config_dir: config_dir.as_ref().to_path_buf(),
            state_dir: state_dir.as_ref().to_path_buf(),
            http: HttpClient::builder().build()?,
        })
    }

    pub fn load_token(&self, server_url: &str) -> Result<Option<Token>> {
        let parsed = ParsedServerUrl::parse(server_url)?;
        self.load_token_for(&parsed)
    }

    pub fn save_token(&self, server_url: &str, token: &Token) -> Result<()> {
        let parsed = ParsedServerUrl::parse(server_url)?;
        self.save_token_for(&parsed, token)
    }

    pub fn delete_token(&self, server_url: &str) -> Result<()> {
        let parsed = ParsedServerUrl::parse(server_url)?;
        self.delete_token_for(&parsed)
    }

    pub fn list_hosts(&self) -> Result<Vec<String>> {
        let directory = self.credentials_dir();
        if !directory.exists() {
            return Ok(Vec::new());
        }

        let mut hosts = fs::read_dir(directory)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                if !path.is_file() {
                    return None;
                }

                let extension = path.extension().and_then(|value| value.to_str());
                if extension != Some("json") {
                    return None;
                }

                path.file_stem()
                    .and_then(|value| value.to_str())
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        hosts.sort();
        Ok(hosts)
    }

    pub fn get_valid_token(&self, server_url: &str) -> Result<Token> {
        self.token_with_refresh(server_url, false)
    }

    #[cfg(test)]
    pub fn refresh_token(&self, server_url: &str) -> Result<Token> {
        self.token_with_refresh(server_url, true)
    }

    #[cfg(test)]
    pub fn credentials_file(&self, server_url: &str) -> Result<PathBuf> {
        let parsed = ParsedServerUrl::parse(server_url)?;
        Ok(self.credentials_path(&parsed))
    }

    #[cfg(test)]
    pub fn lock_file(&self, server_url: &str) -> Result<PathBuf> {
        let parsed = ParsedServerUrl::parse(server_url)?;
        Ok(self.lock_path(&parsed))
    }

    fn token_with_refresh(&self, server_url: &str, force_refresh: bool) -> Result<Token> {
        let parsed = ParsedServerUrl::parse(server_url)?;
        if let Some(token) = self.fresh_token(&parsed, force_refresh)? {
            return Ok(token);
        }

        self.refresh_with_lock(&parsed, force_refresh, 0)
    }

    fn refresh_with_lock(
        &self,
        parsed: &ParsedServerUrl,
        force_refresh: bool,
        attempt_count: usize,
    ) -> Result<Token> {
        if let Some(token) = self.fresh_token(parsed, force_refresh)? {
            return Ok(token);
        }

        if attempt_count >= TUIST_LOCK_MAX_ATTEMPTS {
            return Err(SchlusselError::Timeout);
        }

        let lock_path = self.lock_path(parsed);
        let lock_exists = lock_path.exists();
        let seconds_since_last_modified = if lock_exists {
            lock_age_seconds(&lock_path)
        } else {
            None
        };

        if !lock_exists
            || seconds_since_last_modified
                .is_some_and(|seconds| seconds > TUIST_LOCK_STALE_SECS as f64)
        {
            fs::create_dir_all(lock_path.parent().unwrap_or(&self.state_dir))?;
            if lock_exists {
                remove_file_if_exists(&lock_path)?;
            }
            touch_lock_file(&lock_path)?;

            let result = self.refresh_owned(parsed, force_refresh);
            let _ = remove_file_if_exists(&lock_path);
            return result;
        }

        thread::sleep(Duration::from_millis(TUIST_LOCK_RETRY_INTERVAL_MS));
        self.refresh_with_lock(parsed, force_refresh, attempt_count + 1)
    }

    fn fresh_token(&self, parsed: &ParsedServerUrl, force_refresh: bool) -> Result<Option<Token>> {
        let Some(token) = self.load_token_for(parsed)? else {
            return Ok(None);
        };

        if tuist_token_needs_refresh(&token, force_refresh) {
            Ok(None)
        } else {
            Ok(Some(token))
        }
    }

    fn refresh_owned(&self, parsed: &ParsedServerUrl, force_refresh: bool) -> Result<Token> {
        if let Some(token) = self.fresh_token(parsed, force_refresh)? {
            return Ok(token);
        }

        let current = self
            .load_token_for(parsed)?
            .ok_or_else(|| SchlusselError::TokenNotFound(parsed.raw.clone()))?;
        let refresh_token = current
            .refresh_token
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or(SchlusselError::TokenExpired)?;
        let refreshed = normalize_refresh_token(
            self.exchange_refresh(parsed, &refresh_token)?,
            refresh_token,
        );
        self.save_token_for(parsed, &refreshed)?;
        Ok(refreshed)
    }

    fn exchange_refresh(&self, parsed: &ParsedServerUrl, refresh_token: &str) -> Result<Token> {
        let endpoint = parsed.refresh_endpoint();
        let response = self
            .http
            .post(endpoint)
            .header("Accept", "application/json")
            .json(&TuistRefreshRequest { refresh_token })
            .send()?;
        let status = response.status().as_u16();

        match status {
            200 => {
                let payload: TuistRefreshResponse = response.json()?;
                payload.into_token()
            }
            401 => {
                let description = response_error_message(response);
                let _ = self.delete_token_for(parsed);
                Err(SchlusselError::server(
                    Some(status),
                    None,
                    Some(description),
                ))
            }
            _ => Err(SchlusselError::server(
                Some(status),
                None,
                Some(response_error_message(response)),
            )),
        }
    }

    fn load_token_for(&self, parsed: &ParsedServerUrl) -> Result<Option<Token>> {
        let path = self.credentials_path(parsed);
        match fs::read(path) {
            Ok(bytes) => {
                let credentials: TuistCredentials = match serde_json::from_slice(&bytes) {
                    Ok(credentials) => credentials,
                    Err(_) => return Ok(None),
                };
                Ok(Some(credentials.into_token()?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save_token_for(&self, parsed: &ParsedServerUrl, token: &Token) -> Result<()> {
        let path = self.credentials_path(parsed);
        let directory = path.parent().unwrap_or(&self.config_dir);
        fs::create_dir_all(directory)?;

        let contents = serde_json::to_vec_pretty(&TuistCredentials::from_token(token))?;
        let mut temp = NamedTempFile::new_in(directory)?;
        temp.write_all(&contents)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        temp.persist(&path).map_err(|error| error.error)?;
        Ok(())
    }

    fn delete_token_for(&self, parsed: &ParsedServerUrl) -> Result<()> {
        remove_file_if_exists(&self.credentials_path(parsed))
    }

    fn credentials_dir(&self) -> PathBuf {
        self.config_dir.join("credentials")
    }

    fn credentials_path(&self, parsed: &ParsedServerUrl) -> PathBuf {
        self.credentials_dir().join(format!("{}.json", parsed.host))
    }

    fn lock_path(&self, parsed: &ParsedServerUrl) -> PathBuf {
        let key = format!("token_{}", parsed.raw);
        let sanitized = key.replace('/', "_").replace(':', "_").replace(' ', "_");
        self.state_dir
            .join("auth-locks")
            .join(format!("{sanitized}.lock"))
    }
}

pub fn normalize_server_url(identity: Option<&str>) -> Result<String> {
    match identity
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
    {
        None => Ok("https://tuist.dev".to_string()),
        Some(identity) if identity.starts_with("https://") || identity.starts_with("http://") => {
            ParsedServerUrl::parse(identity)?;
            Ok(identity.to_string())
        }
        Some(identity) => {
            let server_url = format!("https://{identity}");
            ParsedServerUrl::parse(&server_url)?;
            Ok(server_url)
        }
    }
}

pub fn host_matches_identity(host: &str, identity: Option<&str>) -> bool {
    let Some(identity) = identity
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
    else {
        return true;
    };

    if identity.starts_with("https://") || identity.starts_with("http://") {
        return Url::parse(identity)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|candidate| candidate == host);
    }

    identity == host
}

#[derive(Debug, Clone)]
struct ParsedServerUrl {
    raw: String,
    parsed: Url,
    host: String,
}

impl ParsedServerUrl {
    fn parse(server_url: &str) -> Result<Self> {
        let parsed = Url::parse(server_url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| {
                SchlusselError::invalid_parameter(format!("invalid Tuist server URL: {server_url}"))
            })?
            .to_string();

        Ok(Self {
            raw: server_url.to_string(),
            parsed,
            host,
        })
    }

    fn refresh_endpoint(&self) -> Url {
        let mut endpoint = self.parsed.clone();
        endpoint.set_path("/api/auth/refresh_token");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TuistCredentials {
    #[serde(rename = "accessToken", alias = "access_token")]
    access_token: String,
    #[serde(rename = "refreshToken", alias = "refresh_token", default)]
    refresh_token: Option<String>,
}

impl TuistCredentials {
    fn from_token(token: &Token) -> Self {
        Self {
            access_token: token.access_token.clone(),
            refresh_token: token
                .refresh_token
                .clone()
                .filter(|value| !value.is_empty()),
        }
    }

    fn into_token(self) -> Result<Token> {
        Ok(Token {
            access_token: self.access_token.clone(),
            token_type: "Bearer".to_string(),
            refresh_token: self.refresh_token.filter(|value| !value.is_empty()),
            expires_in: None,
            expires_at: jwt_expiration(&self.access_token)?,
            scope: None,
            id_token: None,
        })
    }
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    exp: Option<u64>,
}

#[derive(Debug, Serialize)]
struct TuistRefreshRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Debug, Deserialize)]
struct TuistRefreshResponse {
    access_token: String,
    refresh_token: String,
}

impl TuistRefreshResponse {
    fn into_token(self) -> Result<Token> {
        TuistCredentials {
            access_token: self.access_token,
            refresh_token: Some(self.refresh_token),
        }
        .into_token()
    }
}

#[derive(Debug, Deserialize)]
struct TuistErrorResponse {
    message: String,
}

fn tuist_token_needs_refresh(token: &Token, force_refresh: bool) -> bool {
    token.expires_within(TUIST_REFRESH_WINDOW_SECS)
        || token.is_expired()
        || (force_refresh
            && token
                .refresh_token
                .as_deref()
                .is_some_and(|value| !value.is_empty()))
}

fn normalize_refresh_token(mut token: Token, fallback_refresh_token: String) -> Token {
    token.refresh_token.get_or_insert(fallback_refresh_token);
    token
}

fn jwt_expiration(token: &str) -> Result<Option<u64>> {
    let claims = token
        .split('.')
        .nth(1)
        .ok_or_else(|| SchlusselError::storage("invalid Tuist access token"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(claims)
        .map_err(|_| SchlusselError::storage("invalid Tuist access token"))?;
    let claims: JwtClaims = serde_json::from_slice(&bytes)
        .map_err(|_| SchlusselError::storage("invalid Tuist access token"))?;
    Ok(claims.exp)
}

fn response_error_message(response: reqwest::blocking::Response) -> String {
    let body = response.text().unwrap_or_default();
    serde_json::from_str::<TuistErrorResponse>(&body)
        .map(|payload| payload.message)
        .unwrap_or(body)
}

fn lock_age_seconds(path: &Path) -> Option<f64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|duration| duration.as_secs_f64())
}

fn touch_lock_file(path: &Path) -> Result<()> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn default_tuist_config_dir() -> PathBuf {
    default_tuist_dir("XDG_CONFIG_HOME", [".config"])
}

fn default_tuist_state_dir() -> PathBuf {
    default_tuist_dir("XDG_STATE_HOME", [".local", "state"])
}

fn default_tuist_dir<'a>(
    variable_name: &str,
    default_suffix: impl IntoIterator<Item = &'a str>,
) -> PathBuf {
    env::var_os(format!("TUIST_{variable_name}"))
        .or_else(|| env::var_os(variable_name))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(env::temp_dir);
            default_suffix
                .into_iter()
                .fold(home, |path, component| path.join(component))
        })
        .join("tuist")
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn load_token_reads_tuist_credentials() {
        let temp = tempdir().expect("tempdir");
        let store =
            TuistSessionStore::with_paths(temp.path().join("config"), temp.path().join("state"))
                .expect("store");
        let expires_at = now_unix_timestamp() + 600;

        write_credentials(
            &store,
            "https://tuist.dev",
            &TuistCredentials {
                access_token: make_access_token(expires_at),
                refresh_token: Some("refresh-1".to_string()),
            },
        );

        let token = store
            .load_token("https://tuist.dev")
            .expect("load token")
            .expect("token");

        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-1"));
        assert_eq!(token.expires_at, Some(expires_at));
    }

    #[test]
    fn save_token_writes_tuist_credentials_shape() {
        let temp = tempdir().expect("tempdir");
        let store =
            TuistSessionStore::with_paths(temp.path().join("config"), temp.path().join("state"))
                .expect("store");
        let token = Token {
            access_token: make_access_token(now_unix_timestamp() + 600),
            token_type: "Bearer".to_string(),
            refresh_token: Some("refresh-1".to_string()),
            expires_in: None,
            expires_at: None,
            scope: None,
            id_token: None,
        };

        store
            .save_token("https://tuist.dev", &token)
            .expect("save token");

        let path = store
            .credentials_file("https://tuist.dev")
            .expect("credentials path");
        let payload: serde_json::Value =
            serde_json::from_slice(&fs::read(path).expect("read credentials")).expect("json");

        assert_eq!(payload["accessToken"], token.access_token);
        assert_eq!(payload["refreshToken"], "refresh-1");
        assert!(payload.get("access_token").is_none());
        assert!(payload.get("refresh_token").is_none());
    }

    #[test]
    fn list_hosts_returns_sorted_tuist_hosts() {
        let temp = tempdir().expect("tempdir");
        let store =
            TuistSessionStore::with_paths(temp.path().join("config"), temp.path().join("state"))
                .expect("store");

        write_credentials(
            &store,
            "https://zeta.tuist.dev",
            &TuistCredentials {
                access_token: make_access_token(now_unix_timestamp() + 600),
                refresh_token: Some("refresh-zeta".to_string()),
            },
        );
        write_credentials(
            &store,
            "https://alpha.tuist.dev",
            &TuistCredentials {
                access_token: make_access_token(now_unix_timestamp() + 600),
                refresh_token: Some("refresh-alpha".to_string()),
            },
        );

        assert_eq!(
            store.list_hosts().expect("list hosts"),
            vec!["alpha.tuist.dev".to_string(), "zeta.tuist.dev".to_string()]
        );
    }

    #[test]
    fn get_valid_token_refreshes_tuist_credentials_and_persists_them() {
        let temp = tempdir().expect("tempdir");
        let store =
            TuistSessionStore::with_paths(temp.path().join("config"), temp.path().join("state"))
                .expect("store");
        let server = OneShotServer::respond(
            200,
            "application/json",
            format!(
                r#"{{
                    "access_token": "{}",
                    "refresh_token": "refresh-2"
                }}"#,
                make_access_token(now_unix_timestamp() + 1200)
            ),
        );

        write_credentials(
            &store,
            &server.endpoint(""),
            &TuistCredentials {
                access_token: make_access_token(now_unix_timestamp().saturating_sub(60)),
                refresh_token: Some("refresh-1".to_string()),
            },
        );

        let token = store
            .get_valid_token(&server.endpoint(""))
            .expect("refreshed token");
        let request = server.next_request();
        let persisted = store
            .load_token(&server.endpoint(""))
            .expect("load persisted token")
            .expect("persisted token");

        assert_eq!(request.path, "/api/auth/refresh_token");
        assert!(request.body.contains(r#""refresh_token":"refresh-1""#));
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-2"));
        assert_eq!(persisted.refresh_token.as_deref(), Some("refresh-2"));
    }

    #[test]
    fn get_valid_token_waits_for_tuist_lock_and_uses_refreshed_credentials() {
        let temp = tempdir().expect("tempdir");
        let config_dir = temp.path().join("config");
        let state_dir = temp.path().join("state");
        let store =
            TuistSessionStore::with_paths(config_dir.clone(), state_dir.clone()).expect("store");
        let server_url = "https://tuist.dev";
        let lock_path = store.lock_file(server_url).expect("lock path");

        write_credentials(
            &store,
            server_url,
            &TuistCredentials {
                access_token: make_access_token(now_unix_timestamp().saturating_sub(60)),
                refresh_token: Some("refresh-1".to_string()),
            },
        );
        fs::create_dir_all(lock_path.parent().expect("lock parent")).expect("make lock dir");
        touch_lock_file(&lock_path).expect("touch lock file");

        let config_dir_clone = config_dir.clone();
        let state_dir_clone = state_dir.clone();
        let lock_path_clone = lock_path.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            let store = TuistSessionStore::with_paths(config_dir_clone, state_dir_clone)
                .expect("store in worker");
            write_credentials(
                &store,
                server_url,
                &TuistCredentials {
                    access_token: make_access_token(now_unix_timestamp() + 900),
                    refresh_token: Some("refresh-2".to_string()),
                },
            );
            remove_file_if_exists(&lock_path_clone).expect("remove lock file");
        });

        let token = store
            .get_valid_token(server_url)
            .expect("refreshed token from other process");
        handle.join().expect("worker join");

        assert_eq!(token.refresh_token.as_deref(), Some("refresh-2"));
    }

    #[test]
    fn refresh_token_deletes_credentials_after_unauthorized_response() {
        let temp = tempdir().expect("tempdir");
        let store =
            TuistSessionStore::with_paths(temp.path().join("config"), temp.path().join("state"))
                .expect("store");
        let server =
            OneShotServer::respond(401, "application/json", r#"{"message":"Invalid token"}"#);

        write_credentials(
            &store,
            &server.endpoint(""),
            &TuistCredentials {
                access_token: make_access_token(now_unix_timestamp().saturating_sub(60)),
                refresh_token: Some("refresh-1".to_string()),
            },
        );

        let error = store
            .refresh_token(&server.endpoint(""))
            .expect_err("refresh should fail");
        let remaining = store
            .load_token(&server.endpoint(""))
            .expect("load remaining token");

        assert!(matches!(
            error,
            SchlusselError::Server {
                status: Some(401),
                ..
            }
        ));
        assert!(remaining.is_none());
    }

    #[test]
    fn lock_file_matches_tuist_lock_naming() {
        let temp = tempdir().expect("tempdir");
        let store =
            TuistSessionStore::with_paths(temp.path().join("config"), temp.path().join("state"))
                .expect("store");

        let lock_path = store.lock_file("https://tuist.dev").expect("lock path");

        assert_eq!(
            lock_path,
            temp.path()
                .join("state")
                .join("auth-locks")
                .join("token_https___tuist.dev.lock")
        );
    }

    fn write_credentials(
        store: &TuistSessionStore,
        server_url: &str,
        credentials: &TuistCredentials,
    ) {
        let path = store
            .credentials_file(server_url)
            .expect("credentials path");
        fs::create_dir_all(path.parent().expect("credentials parent"))
            .expect("make credentials dir");
        fs::write(
            path,
            serde_json::to_vec_pretty(credentials).expect("serialize credentials"),
        )
        .expect("write credentials");
    }

    fn make_access_token(expires_at: u64) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{expires_at}}}"#));
        format!("{header}.{claims}.signature")
    }

    fn now_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix timestamp")
            .as_secs()
    }

    #[derive(Debug)]
    struct CapturedRequest {
        path: String,
        body: String,
    }

    #[derive(Debug)]
    struct OneShotServer {
        base_url: String,
        requests: Receiver<CapturedRequest>,
        handle: Option<JoinHandle<()>>,
    }

    impl OneShotServer {
        fn respond(status: u16, content_type: &'static str, body: impl Into<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
            let address = listener.local_addr().expect("listener address");
            let response_body = body.into();
            let (request_tx, requests) = mpsc::channel();
            let handle = thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accept request");
                let mut reader = BufReader::new(stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).expect("request line");
                let mut content_length = 0usize;

                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).expect("header line");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }

                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().expect("content length");
                        }
                    }
                }

                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).expect("request body");
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                request_tx
                    .send(CapturedRequest {
                        path,
                        body: String::from_utf8(body).expect("utf8 request body"),
                    })
                    .expect("send captured request");

                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                reader
                    .get_mut()
                    .write_all(response.as_bytes())
                    .expect("write response");
            });

            Self {
                base_url: format!("http://{address}"),
                requests,
                handle: Some(handle),
            }
        }

        fn endpoint(&self, path: &str) -> String {
            format!("{}{}", self.base_url, path)
        }

        fn next_request(&self) -> CapturedRequest {
            self.requests.recv().expect("captured request")
        }
    }

    impl Drop for OneShotServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
}
