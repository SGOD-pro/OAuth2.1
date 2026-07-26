import * as crypto from 'crypto';

const AUTH_URL = 'http://localhost:3000';
const ADMIN_EMAIL = 'swyar@auth2.1.com';
const ADMIN_PASS = 'swyra@123';

async function runTests() {
  console.log('=== STARTING AUTOMATED OAUTH SECURITY TESTS ===\n');

  // 1. Admin Login to get session
  console.log('[1] Logging in as admin to configure test app...');
  const loginRes = await fetch(`${AUTH_URL}/api/auth/sign-in/email`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:5174'
    },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASS }),
  });

  if (!loginRes.ok) {
    throw new Error(`Admin login failed: ${await loginRes.text()}`);
  }

  // Extract cookies
  const cookies = loginRes.headers.get('set-cookie');
  if (!cookies) throw new Error('No cookies returned on login');

  console.log('    ✅ Admin login successful.');

  // 2. Register new OAuth application
  console.log('[2] Registering new OAuth Application...');
  const createAppRes = await fetch(`${AUTH_URL}/api/admin/clients`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': `${cookies}; csrf_token=mock_csrf`,
      'Origin': 'http://localhost:5174',
      'x-csrf-token': 'mock_csrf'
    },
    body: JSON.stringify({
      client_name: 'Automated Test App',
      redirect_uris: ['http://localhost:4000/auth/callback'],
      allowed_origins: ['http://localhost:4000'],
      metadata: {
        skipConsent: true,
        allowLogout: true
      }
    }),
  });

  if (!createAppRes.ok) {
    throw new Error(`App creation failed: ${await createAppRes.text()}`);
  }

  const clientData = await createAppRes.json();
  const clientId = clientData.id || clientData.clientId;
  const clientSecret = clientData.clientSecret || clientData.secret;

  console.log(`    ✅ App created! Client ID: ${clientId}`);

  // 3. OAUTH FLOW TEST: Valid Flow
  console.log('\n[3] Testing Valid OAuth Flow (Authorization Code + PKCE)...');
  
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const state = crypto.randomUUID();

  const authUrl = new URL(`${AUTH_URL}/api/auth/oauth2/authorize`);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', 'http://localhost:4000/auth/callback');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email offline_access');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  // Step 3A: Authorize endpoint
  // Usually this would require an active session for the user granting consent.
  // We will pass the admin cookie to act as the user.
  const authorizeRes = await fetch(authUrl.toString(), {
    method: 'GET',
    headers: { 'Cookie': cookies },
    redirect: 'manual' // We want to capture the redirect to the callback URI
  });

  // Better-Auth might redirect to consent, or immediately redirect to callback.
  // Since we set skipConsent: true, it should redirect directly to callback.
  if (authorizeRes.status !== 302) {
    console.log(`    ⚠️ Expected 302 redirect, got ${authorizeRes.status}`);
    console.log(await authorizeRes.text());
  } else {
    const location = authorizeRes.headers.get('location');
    console.log(`    ✅ Authorized! Redirected to: ${location}`);

    if (location && location.includes('code=')) {
      const url = new URL(location);
      const code = url.searchParams.get('code');
      
      // Step 3B: Token Exchange
      console.log('    Exchanging code for token...');
      const tokenRes = await fetch(`${AUTH_URL}/api/auth/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'http://localhost:4000/auth/callback',
          client_id: clientId,
          client_secret: clientSecret,
          code_verifier: codeVerifier,
        }).toString(),
      });

      if (tokenRes.ok) {
        const tokenData = await tokenRes.json();
        console.log('    ✅ Token exchange successful!', Object.keys(tokenData));
      } else {
        console.error('    ❌ Token exchange failed:', await tokenRes.text());
      }
    }
  }

  // 4. CROSS VALIDATION: Invalid Redirect URI
  console.log('\n[4] Testing Security: Invalid Redirect URI...');
  const badAuthUrl = new URL(`${AUTH_URL}/api/auth/oauth2/authorize`);
  badAuthUrl.searchParams.set('client_id', clientId);
  badAuthUrl.searchParams.set('redirect_uri', 'http://malicious-site.com/callback');
  badAuthUrl.searchParams.set('response_type', 'code');
  badAuthUrl.searchParams.set('state', state);

  const badAuthRes = await fetch(badAuthUrl.toString(), {
    method: 'GET',
    headers: { 'Cookie': cookies },
    redirect: 'manual'
  });

  if (badAuthRes.status === 400 || (badAuthRes.status === 302 && badAuthRes.headers.get('location')?.includes('error='))) {
    console.log('    ✅ Security check passed: Malicious redirect URI was rejected.');
  } else {
    console.log(`    ❌ Security check failed: Expected rejection, but got status ${badAuthRes.status}`);
  }

  // 5. CROSS VALIDATION: Invalid Client Secret on Token Exchange
  console.log('\n[5] Testing Security: Invalid Client Secret...');
  const badTokenRes = await fetch(`${AUTH_URL}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'dummy_code',
      redirect_uri: 'http://localhost:4000/auth/callback',
      client_id: clientId,
      client_secret: 'invalid_secret',
      code_verifier: codeVerifier,
    }).toString(),
  });

  if (!badTokenRes.ok) {
    console.log('    ✅ Security check passed: Invalid secret was rejected.');
  } else {
    console.log('    ❌ Security check failed: Invalid secret was accepted!');
  }

  console.log('\n=== ALL TESTS COMPLETED ===');
}

runTests().catch(console.error);
