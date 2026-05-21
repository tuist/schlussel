use std::time::{SystemTime, UNIX_EPOCH};

use crate::pkce::PkcePair;

pub(super) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn random_state() -> String {
    PkcePair::generate().verifier()[..22].to_string()
}
