/**
 * Example usage of the Schlussel Node.js bindings
 */

const { getVersion, OAuthClient, MemoryStorage, TokenRefresher } = require('./index');

async function main() {
  console.log('Schlussel Node.js Example');
  console.log('=========================\n');

  // Get library version
  const version = getVersion();
  console.log(`Library version: ${version}\n`);

  // Create storage
  const storage = new MemoryStorage();
  console.log('✓ Created memory storage');

  // Configure OAuth
  const config = {
    clientId: 'example-client-id',
    authorizationEndpoint: 'https://accounts.example.com/oauth/authorize',
    tokenEndpoint: 'https://accounts.example.com/oauth/token',
    redirectUri: 'http://localhost:8080/callback',
    scope: 'read write'
  };

  // Create OAuth client
  const client = new OAuthClient(config, storage);
  console.log('✓ Created OAuth client\n');

  // Start OAuth flow
  try {
    const { url, state } = client.startAuthFlow();
    console.log('OAuth Authorization Flow Started:');
    console.log('----------------------------------');
    console.log(`URL: ${url}`);
    console.log(`State: ${state}\n`);

    // Verify URL structure
    if (url.includes('client_id=example-client-id') &&
        url.includes('code_challenge_method=S256') &&
        url.includes('response_type=code')) {
      console.log('✓ Authorization URL is properly formatted\n');
    }

  } catch (error) {
    console.error('Error starting auth flow:', error);
  }

  // Create token refresher
  const refresher = new TokenRefresher(client);
  console.log('✓ Created token refresher');

  // Cleanup
  console.log('\nCleaning up...');
  refresher.waitForRefresh('example-key');
  refresher.destroy();
  client.destroy();
  storage.destroy();

  console.log('✓ Done!');
}

main().catch(console.error);
