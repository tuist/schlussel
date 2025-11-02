/// Example: Secure Token Storage with OS Credential Manager
///
/// This example demonstrates how to use SecureStorage to store OAuth tokens
/// securely in the operating system's credential manager instead of plain files.
///
/// Platform-specific storage:
/// - macOS: Keychain
/// - Windows: Credential Manager
/// - Linux: Secret Service API (libsecret)
///
/// Run:
/// cargo run --example secure_storage
use schlussel::prelude::*;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("=== Secure Token Storage Example ===\n");

    // Create secure storage using OS credential manager
    let storage = Arc::new(
        SecureStorage::new("schlussel-secure-example").expect("Failed to create secure storage"),
    );

    println!("Storage backend: OS Credential Manager");
    #[cfg(target_os = "macos")]
    println!("  Platform: macOS Keychain");
    #[cfg(target_os = "windows")]
    println!("  Platform: Windows Credential Manager");
    #[cfg(target_os = "linux")]
    println!("  Platform: Linux Secret Service (libsecret)");
    println!();

    // Configure OAuth for GitHub using preset
    let config = OAuthConfig::github("example-client-id", Some("repo user"));

    let client = OAuthClient::new(config, storage.clone());

    // Create a sample token
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token = Token {
        access_token: "ghp_secureAccessToken123456789".to_string(),
        refresh_token: Some("ghp_secureRefreshToken987654321".to_string()),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        expires_at: Some(now + 3600),
        scope: Some("repo user".to_string()),
    };

    println!("=== Saving Token to Secure Storage ===");
    println!("Token key: github.com:secure-example");
    println!("Access token: {}...", &token.access_token[..20]);
    println!();

    // Save token to OS credential manager
    client
        .save_token("github.com:secure-example", token.clone())
        .expect("Failed to save token");

    println!("✓ Token saved to OS credential manager");
    println!("  Stored encrypted by the operating system");
    println!("  Not accessible as plain text in filesystem");
    println!();

    // Retrieve token from OS credential manager
    println!("=== Retrieving Token from Secure Storage ===");

    let retrieved = client
        .get_token("github.com:secure-example")
        .expect("Failed to get token")
        .expect("Token not found");

    println!("✓ Token retrieved successfully");
    println!("  Access token: {}...", &retrieved.access_token[..20]);
    if let Some(ref refresh) = retrieved.refresh_token {
        println!("  Refresh token: {}...", &refresh[..20]);
    }
    println!("  Token type: {}", retrieved.token_type);
    println!();

    // Delete token from OS credential manager
    println!("=== Deleting Token from Secure Storage ===");

    storage
        .delete_token("github.com:secure-example")
        .expect("Failed to delete token");

    println!("✓ Token deleted from OS credential manager");
    println!();

    // Verify deletion
    let deleted = storage.get_token("github.com:secure-example").unwrap();
    assert!(deleted.is_none());

    println!("✓ Verified: Token no longer exists in storage");
    println!();

    println!("=== Summary ===");
    println!();
    println!("SecureStorage vs FileStorage:");
    println!();
    println!("FileStorage:");
    println!("  - Stores tokens in JSON files (~/.local/share/app-name/)");
    println!("  - Tokens readable as plain text");
    println!("  - Good for: development, testing");
    println!();
    println!("SecureStorage:");
    println!("  - Stores tokens in OS credential manager");
    println!("  - Tokens encrypted by the OS");
    println!("  - Protected by OS security mechanisms");
    println!("  - Good for: production, sensitive tokens");
    println!();
    println!("Security Benefits:");
    println!("  ✓ Tokens encrypted at rest");
    println!("  ✓ OS-level access control");
    println!("  ✓ Not visible in file system");
    println!("  ✓ Integrates with OS security features");
    println!("  ✓ Automatic encryption key management");
}
