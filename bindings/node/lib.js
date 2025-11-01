/**
 * @fileoverview Native library loader for Schlussel
 * Handles loading the correct native library for the current platform
 */

const ffi = require('ffi-napi');
const ref = require('ref-napi');
const path = require('path');
const os = require('os');

/**
 * Determine the library path based on platform
 * @returns {string} Path to the native library
 */
function getLibraryPath() {
  const platform = os.platform();
  const arch = os.arch();

  let libName;
  let libDir;

  if (platform === 'darwin') {
    libName = 'libschlussel.dylib';
    libDir = arch === 'arm64' ? 'macos-aarch64' : 'macos-x86_64';
  } else if (platform === 'linux') {
    libName = 'libschlussel.so';
    libDir = arch === 'arm64' ? 'linux-aarch64' : 'linux-x86_64';
  } else if (platform === 'win32') {
    libName = 'schlussel.dll';
    libDir = arch === 'arm64' ? 'windows-aarch64' : 'windows-x86_64';
  } else {
    throw new Error(`Unsupported platform: ${platform}`);
  }

  // Try multiple potential locations
  const locations = [
    path.join(__dirname, '..', '..', 'dist', libDir, 'lib', libName),
    path.join(__dirname, '..', '..', 'zig-out', 'lib', libName),
    path.join(process.cwd(), 'zig-out', 'lib', libName),
  ];

  const fs = require('fs');
  for (const loc of locations) {
    if (fs.existsSync(loc)) {
      return loc;
    }
  }

  throw new Error(`Could not find native library. Searched: ${locations.join(', ')}`);
}

// Define opaque pointer types
const SchlusselOAuth = ref.refType(ref.types.void);
const SchlusselStorage = ref.refType(ref.types.void);
const SchlusselTokenRefresher = ref.refType(ref.types.void);

// Define structs
const SchlusselOAuthConfig = ref.types.void; // Handled manually
const SchlusselAuthFlow = ref.types.void; // Handled manually

/**
 * Load the native library
 * @type {object}
 */
const lib = ffi.Library(getLibraryPath(), {
  'schlussel_version': ['string', []],
  'schlussel_storage_memory_create': [SchlusselStorage, []],
  'schlussel_storage_destroy': ['void', [SchlusselStorage]],
  'schlussel_oauth_create': [SchlusselOAuth, ['pointer', SchlusselStorage]],
  'schlussel_oauth_destroy': ['void', [SchlusselOAuth]],
  'schlussel_oauth_start_flow': ['int', [SchlusselOAuth, 'pointer']],
  'schlussel_auth_flow_free': ['void', ['pointer']],
  'schlussel_token_refresher_create': [SchlusselTokenRefresher, [SchlusselOAuth]],
  'schlussel_token_refresher_destroy': ['void', [SchlusselTokenRefresher]],
  'schlussel_token_refresher_wait': ['void', [SchlusselTokenRefresher, 'string']],
});

module.exports = {
  lib,
  types: {
    SchlusselOAuth,
    SchlusselStorage,
    SchlusselTokenRefresher,
  }
};
