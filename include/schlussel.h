/**
 * Schlussel - Cross-platform OAuth 2.0 with PKCE library for CLIs
 *
 * This library provides OAuth 2.0 authorization code flow with PKCE
 * (Proof Key for Code Exchange) for command-line applications.
 *
 * Features:
 * - PKCE challenge generation (RFC 7636)
 * - Session management with pluggable storage
 * - Token refresh with concurrency control
 * - Cross-platform support
 */

#ifndef SCHLUSSEL_H
#define SCHLUSSEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* Opaque types */
typedef struct SchlusselOAuth SchlusselOAuth;
typedef struct SchlusselStorage SchlusselStorage;
typedef struct SchlusselTokenRefresher SchlusselTokenRefresher;
typedef struct SchlusselToken SchlusselToken;

/* Error codes */
typedef enum {
    SCHLUSSEL_OK = 0,
    SCHLUSSEL_OUT_OF_MEMORY = 1,
    SCHLUSSEL_INVALID_ARGUMENT = 2,
    SCHLUSSEL_NOT_FOUND = 3,
    SCHLUSSEL_UNKNOWN = 99
} SchlusselError;

/* OAuth configuration */
typedef struct {
    const char* client_id;
    const char* authorization_endpoint;
    const char* token_endpoint;
    const char* redirect_uri;
    const char* scope; /* Optional, can be NULL */
} SchlusselOAuthConfig;

/* Auth flow result */
typedef struct {
    char* url;   /* Authorization URL - must be freed with schlussel_auth_flow_free */
    char* state; /* State parameter - must be freed with schlussel_auth_flow_free */
} SchlusselAuthFlow;

/* Token information */
typedef struct {
    const char* access_token;
    const char* refresh_token; /* Optional, can be NULL */
    const char* token_type;
    int64_t expires_at;
} SchlusselTokenInfo;

/* Storage interface callbacks */
typedef struct {
    int (*save_session)(void* ctx, const char* state, const char* code_verifier);
    int (*get_session)(void* ctx, const char* state, char* out_verifier, size_t verifier_len);
    int (*delete_session)(void* ctx, const char* state);
    int (*save_token)(void* ctx, const char* key, const SchlusselTokenInfo* token);
    int (*get_token)(void* ctx, const char* key, SchlusselTokenInfo* token);
    int (*delete_token)(void* ctx, const char* key);
} SchlusselStorageVTable;

/**
 * Get library version
 * @return Version string (do not free)
 */
const char* schlussel_version(void);

/**
 * Create a new in-memory storage (for testing/simple use cases)
 * @return Storage instance or NULL on error
 */
SchlusselStorage* schlussel_storage_memory_create(void);

/**
 * Destroy storage instance
 * @param storage Storage to destroy
 */
void schlussel_storage_destroy(SchlusselStorage* storage);

/**
 * Create OAuth client
 * @param config OAuth configuration
 * @param storage Storage backend
 * @return OAuth client or NULL on error
 */
SchlusselOAuth* schlussel_oauth_create(
    const SchlusselOAuthConfig* config,
    SchlusselStorage* storage
);

/**
 * Destroy OAuth client
 * @param client OAuth client to destroy
 */
void schlussel_oauth_destroy(SchlusselOAuth* client);

/**
 * Start OAuth authorization flow
 *
 * This generates a PKCE challenge, saves the session, and returns
 * the authorization URL that the user should open in their browser.
 *
 * @param client OAuth client
 * @param result Output parameter for flow result (must be freed with schlussel_auth_flow_free)
 * @return Error code
 */
SchlusselError schlussel_oauth_start_flow(
    SchlusselOAuth* client,
    SchlusselAuthFlow* result
);

/**
 * Free auth flow result
 * @param result Result to free
 */
void schlussel_auth_flow_free(SchlusselAuthFlow* result);

/**
 * Create token refresher
 *
 * The token refresher manages concurrent token refresh requests,
 * ensuring only one refresh happens at a time for a given token.
 *
 * @param client OAuth client
 * @return Token refresher or NULL on error
 */
SchlusselTokenRefresher* schlussel_token_refresher_create(SchlusselOAuth* client);

/**
 * Destroy token refresher
 * @param refresher Token refresher to destroy
 */
void schlussel_token_refresher_destroy(SchlusselTokenRefresher* refresher);

/**
 * Wait for any in-progress token refresh to complete
 *
 * This should be called before process exit to ensure token refresh
 * completes and the updated token is persisted.
 *
 * @param refresher Token refresher
 * @param key Token key to wait for
 */
void schlussel_token_refresher_wait(SchlusselTokenRefresher* refresher, const char* key);

#ifdef __cplusplus
}
#endif

#endif /* SCHLUSSEL_H */
