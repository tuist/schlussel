use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{Result, SchlusselError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkcePair {
    verifier: String,
    challenge: String,
}

impl PkcePair {
    pub fn generate() -> Self {
        let mut verifier_bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut verifier_bytes);

        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        let challenge = challenge_from_verifier(&verifier);

        Self {
            verifier,
            challenge,
        }
    }

    pub fn from_verifier(verifier: impl Into<String>) -> Result<Self> {
        let verifier = verifier.into();
        if verifier.len() != 43 {
            return Err(SchlusselError::invalid_parameter(
                "PKCE verifier must be 43 characters",
            ));
        }

        let challenge = challenge_from_verifier(&verifier);
        Ok(Self {
            verifier,
            challenge,
        })
    }

    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    pub const fn challenge_method() -> &'static str {
        "S256"
    }
}

fn challenge_from_verifier(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pkce_lengths_are_expected() {
        let pair = PkcePair::generate();
        assert_eq!(pair.verifier().len(), 43);
        assert_eq!(pair.challenge().len(), 43);
    }

    #[test]
    fn challenge_roundtrips_from_existing_verifier() {
        let pair = PkcePair::generate();
        let rebuilt = PkcePair::from_verifier(pair.verifier().to_string()).expect("pair");
        assert_eq!(pair, rebuilt);
    }
}
