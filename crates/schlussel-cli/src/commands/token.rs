use std::path::Path;

use anyhow::{anyhow, bail, Result};
use schlussel::oauth::{config_from_formula, OAuthClient};
use schlussel::session::{
    build_storage_key, parse_storage_key, FileStorage, MemoryStorage, SessionStorage, Token,
};
use schlussel::{RefreshLockManager, SchlusselError};
use serde::Serialize;

use crate::cli::{TokenAction, TokenArgs, TokenKeyArgs, TokenListArgs};
use crate::formula_support::load_formula;
use crate::output::{OutputContext, OutputMode};
use crate::render::{print_deleted_token, print_token_details, print_token_list};
use crate::tuist::{host_matches_identity, normalize_server_url, TuistSessionStore};

pub fn execute(args: TokenArgs, output: OutputContext) -> Result<()> {
    match args.action {
        TokenAction::Get(options) => get_token(&options, output),
        TokenAction::List(options) => list_tokens(&options, output),
        TokenAction::Delete(options) => delete_token(options, output),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenDescriptor {
    pub key: String,
    pub formula: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub source: TokenSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

impl TokenDescriptor {
    fn from_key(key: &str) -> Self {
        let parsed = parse_storage_key(key);
        Self {
            key: key.to_string(),
            formula: parsed.formula,
            method: parsed.method,
            identity: parsed.identity,
            source: TokenSource::File,
            server_url: None,
        }
    }

    fn tuist_host(host: &str) -> Self {
        Self {
            key: build_storage_key("tuist", Some("session"), Some(host)),
            formula: "tuist".to_string(),
            method: Some("session".to_string()),
            identity: Some(host.to_string()),
            source: TokenSource::Tuist,
            server_url: None,
        }
    }

    fn tuist_server_url(server_url: &str) -> Result<Self> {
        let host = tuist_host(server_url)?;
        Ok(Self {
            server_url: Some(server_url.to_string()),
            ..Self::tuist_host(&host)
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    File,
    Tuist,
}

impl TokenSource {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Tuist => "tuist",
        }
    }
}

#[derive(Debug, Serialize)]
struct TokenEnvelope {
    #[serde(flatten)]
    metadata: TokenDescriptor,
    token: Token,
}

#[derive(Debug, Serialize)]
struct DeletedToken {
    deleted: bool,
    #[serde(flatten)]
    metadata: TokenDescriptor,
}

#[derive(Debug, Clone)]
enum TokenTarget {
    File { key: String },
    Tuist { server_url: String },
}

impl TokenTarget {
    fn from_args(
        key: Option<&str>,
        formula: Option<&str>,
        method: Option<&str>,
        identity: Option<&str>,
    ) -> Result<Self> {
        if let Some(key) = key {
            let parsed = parse_storage_key(key);
            if parsed.formula == "tuist" {
                ensure_tuist_method(parsed.method.as_deref().or(method))?;
                return Ok(Self::Tuist {
                    server_url: normalize_server_url(parsed.identity.as_deref().or(identity))?,
                });
            }

            return Ok(Self::File {
                key: key.to_string(),
            });
        }

        if let Some(formula) = formula {
            if formula == "tuist" {
                ensure_tuist_method(method)?;
                return Ok(Self::Tuist {
                    server_url: normalize_server_url(identity)?,
                });
            }

            return Ok(Self::File {
                key: build_storage_key(formula, method, identity),
            });
        }

        bail!("either --key or --formula is required")
    }

    fn descriptor(&self) -> TokenDescriptor {
        match self {
            Self::File { key } => TokenDescriptor::from_key(key),
            Self::Tuist { server_url } => {
                TokenDescriptor::tuist_server_url(server_url).expect("valid Tuist target")
            }
        }
    }

    fn read(&self, options: &TokenKeyArgs, output: OutputContext) -> Result<Token> {
        match self {
            Self::File { key } => read_file_token(key, options, output),
            Self::Tuist { server_url } => read_tuist_token(server_url, options.no_refresh),
        }
    }

    fn delete(self) -> Result<()> {
        match self {
            Self::File { key } => {
                let storage = FileStorage::new("schlussel")?;
                storage.delete(&key)?;
            }
            Self::Tuist { server_url } => {
                let store = TuistSessionStore::new()?;
                store.delete_token(&server_url)?;
            }
        }

        Ok(())
    }
}

fn get_token(options: &TokenKeyArgs, output: OutputContext) -> Result<()> {
    let target = TokenTarget::from_args(
        options.key.as_deref(),
        options.formula.as_deref(),
        options.method.as_deref(),
        options.identity.as_deref(),
    )?;
    let descriptor = target.descriptor();
    let token = target.read(options, output)?;

    match output.mode() {
        OutputMode::Json => println!(
            "{}",
            serde_json::to_string_pretty(&TokenEnvelope {
                token,
                metadata: descriptor,
            })?
        ),
        OutputMode::Toon => print_token_details(&descriptor, &token, output)?,
        OutputMode::Default => println!("{}", token.access_token),
    }

    Ok(())
}

fn list_tokens(options: &TokenListArgs, output: OutputContext) -> Result<()> {
    let items = list_token_descriptors(options)?;

    if output.mode() == OutputMode::Json {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }

    if items.is_empty() {
        println!("{}", empty_list_message(options.formula.as_deref()));
        return Ok(());
    }

    print_token_list(&items, output)
}

fn delete_token(options: TokenKeyArgs, output: OutputContext) -> Result<()> {
    let target = TokenTarget::from_args(
        options.key.as_deref(),
        options.formula.as_deref(),
        options.method.as_deref(),
        options.identity.as_deref(),
    )?;
    let descriptor = target.descriptor();
    target.delete()?;

    if output.mode() == OutputMode::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&DeletedToken {
                deleted: true,
                metadata: descriptor,
            })?
        );
    } else {
        print_deleted_token(&descriptor, output)?;
    }

    Ok(())
}

fn read_file_token(key: &str, options: &TokenKeyArgs, output: OutputContext) -> Result<Token> {
    let storage = FileStorage::new("schlussel")?;
    let mut token = storage
        .load(key)?
        .ok_or_else(|| anyhow!("token not found for key '{key}'"))?;

    if !needs_refresh(&token, options.no_refresh) {
        return Ok(token);
    }

    let manager = RefreshLockManager::new("schlussel")?;
    let mut lock = manager.acquire(key)?;
    let fresh = storage
        .load(key)?
        .ok_or_else(|| anyhow!("token not found for key '{key}'"))?;
    token = if needs_refresh(&fresh, false) {
        refresh_stored_token(
            &storage,
            key,
            fresh,
            options.formula_json.as_deref(),
            output,
        )?
    } else {
        fresh
    };
    lock.release()?;
    Ok(token)
}

fn read_tuist_token(server_url: &str, no_refresh: bool) -> Result<Token> {
    let store = TuistSessionStore::new()?;
    if no_refresh {
        return store
            .load_token(server_url)?
            .ok_or_else(|| anyhow!("token not found for server URL '{server_url}'"));
    }

    store.get_valid_token(server_url).map_err(Into::into)
}

fn needs_refresh(token: &Token, no_refresh: bool) -> bool {
    !no_refresh && token.refresh_token.is_some() && token.expires_within(300)
}

fn refresh_stored_token(
    storage: &FileStorage,
    key: &str,
    token: Token,
    formula_json: Option<&Path>,
    output: OutputContext,
) -> Result<Token> {
    let refresh_token = token
        .refresh_token
        .clone()
        .ok_or(SchlusselError::NoRefreshToken)?;
    let parsed = parse_storage_key(key);
    let method_name = parsed.method.as_deref().unwrap_or("oauth");
    let formula = if let Some(path) = formula_json {
        load_formula(&parsed.formula, Some(path), output)?
    } else {
        schlussel::formulas::find_builtin(&parsed.formula)
            .ok_or_else(|| anyhow!("unknown formula '{}'", parsed.formula))?
    };
    let config = config_from_formula(
        &formula,
        method_name,
        None,
        None,
        "http://127.0.0.1:0/callback",
        None,
    )?;
    let client = OAuthClient::new(config, MemoryStorage::new())?;
    let mut new_token = client.refresh_token(&refresh_token)?;
    if new_token.refresh_token.is_none() {
        new_token.refresh_token = Some(refresh_token);
    }
    storage.save(key, &new_token)?;
    Ok(new_token)
}

pub fn list_token_descriptors(options: &TokenListArgs) -> Result<Vec<TokenDescriptor>> {
    let storage = FileStorage::new("schlussel")?;
    let mut items = storage
        .list_keys()?
        .into_iter()
        .filter(|key| matches_token_filters(key, options))
        .map(|key| TokenDescriptor::from_key(&key))
        .collect::<Vec<_>>();

    items.extend(list_tuist_descriptors(options)?);
    items.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(items)
}

fn list_tuist_descriptors(options: &TokenListArgs) -> Result<Vec<TokenDescriptor>> {
    if !includes_tuist_formula(options.formula.as_deref())
        || !includes_tuist_method(options.method.as_deref())
    {
        return Ok(Vec::new());
    }

    let store = TuistSessionStore::new()?;
    Ok(store
        .list_hosts()?
        .into_iter()
        .filter(|host| tuist_host_has_credentials(&store, host))
        .map(|host| TokenDescriptor::tuist_host(&host))
        .filter(|item| matches_tuist_filters(item, options))
        .collect())
}

fn includes_tuist_formula(formula: Option<&str>) -> bool {
    !matches!(formula, Some(value) if value != "tuist")
}

fn includes_tuist_method(method: Option<&str>) -> bool {
    !matches!(method, Some(value) if value != "session")
}

fn tuist_host_has_credentials(store: &TuistSessionStore, host: &str) -> bool {
    store
        .load_token(&format!("https://{host}"))
        .ok()
        .flatten()
        .is_some()
}

fn matches_tuist_filters(item: &TokenDescriptor, options: &TokenListArgs) -> bool {
    options
        .key
        .as_ref()
        .is_none_or(|prefix| item.key.starts_with(prefix))
        && host_matches_identity(
            item.identity.as_deref().unwrap_or_default(),
            options.identity.as_deref(),
        )
}

fn matches_token_filters(key: &str, options: &TokenListArgs) -> bool {
    options
        .key
        .as_ref()
        .is_none_or(|prefix| key.starts_with(prefix))
        && key_matches_filter(
            key,
            options.formula.as_deref(),
            options.method.as_deref(),
            options.identity.as_deref(),
        )
}

fn key_matches_filter(
    key: &str,
    formula_filter: Option<&str>,
    method_filter: Option<&str>,
    identity_filter: Option<&str>,
) -> bool {
    let parsed = parse_storage_key(key);
    formula_filter.is_none_or(|formula| parsed.formula == formula)
        && method_filter.is_none_or(|method| parsed.method.as_deref() == Some(method))
        && identity_filter.is_none_or(|identity| parsed.identity.as_deref() == Some(identity))
}

fn empty_list_message(formula: Option<&str>) -> &'static str {
    if formula == Some("tuist") {
        "No Tuist sessions found"
    } else {
        "No tokens found"
    }
}

fn ensure_tuist_method(method: Option<&str>) -> Result<()> {
    if method.is_none_or(|method| method == "session") {
        return Ok(());
    }

    bail!("Tuist only supports the 'session' method")
}

fn tuist_host(server_url: &str) -> Result<String> {
    url::Url::parse(server_url)?
        .host_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("invalid Tuist server URL '{server_url}'"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    use tempfile::tempdir;

    use super::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct TuistEnvGuard {
        old_config_home: Option<OsString>,
        old_state_home: Option<OsString>,
    }

    impl TuistEnvGuard {
        fn new(config_home: &Path, state_home: &Path) -> Self {
            let old_config_home = std::env::var_os("TUIST_XDG_CONFIG_HOME");
            let old_state_home = std::env::var_os("TUIST_XDG_STATE_HOME");
            std::env::set_var("TUIST_XDG_CONFIG_HOME", config_home);
            std::env::set_var("TUIST_XDG_STATE_HOME", state_home);
            Self {
                old_config_home,
                old_state_home,
            }
        }
    }

    impl Drop for TuistEnvGuard {
        fn drop(&mut self) {
            match &self.old_config_home {
                Some(value) => std::env::set_var("TUIST_XDG_CONFIG_HOME", value),
                None => std::env::remove_var("TUIST_XDG_CONFIG_HOME"),
            }
            match &self.old_state_home {
                Some(value) => std::env::set_var("TUIST_XDG_STATE_HOME", value),
                None => std::env::remove_var("TUIST_XDG_STATE_HOME"),
            }
        }
    }

    fn valid_tuist_token() -> Token {
        Token {
            access_token: "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            expires_in: None,
            expires_at: Some(4_102_444_800),
            scope: None,
            id_token: None,
        }
    }

    #[test]
    fn token_key_filters_match_components() {
        assert!(key_matches_filter(
            "github:device_code:personal",
            Some("github"),
            Some("device_code"),
            Some("personal"),
        ));
        assert!(!key_matches_filter(
            "github:device_code:personal",
            Some("github"),
            Some("oauth"),
            Some("personal"),
        ));
    }

    #[test]
    fn resolves_tuist_targets_to_synthetic_keys() {
        let descriptor = TokenTarget::from_args(None, Some("tuist"), None, Some("cloud.tuist.dev"))
            .expect("tuist target")
            .descriptor();

        assert_eq!(descriptor.key, "tuist:session:cloud.tuist.dev");
        assert_eq!(descriptor.identity.as_deref(), Some("cloud.tuist.dev"));
        assert_eq!(
            descriptor.server_url.as_deref(),
            Some("https://cloud.tuist.dev")
        );
    }

    #[test]
    fn token_list_includes_tuist_sessions() {
        let _lock = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        let config_home = temp.path().join("config-home");
        let state_home = temp.path().join("state-home");
        let _guard = TuistEnvGuard::new(&config_home, &state_home);
        let store =
            TuistSessionStore::with_paths(config_home.join("tuist"), state_home.join("tuist"))
                .expect("store");
        store
            .save_token("https://app.tuist.dev", &valid_tuist_token())
            .expect("save token");

        let items = list_token_descriptors(&TokenListArgs {
            key: None,
            formula: None,
            formula_json: None,
            method: None,
            identity: None,
        })
        .expect("list tokens");

        assert!(items
            .iter()
            .any(|item| item.key == "tuist:session:app.tuist.dev"));
    }
}
