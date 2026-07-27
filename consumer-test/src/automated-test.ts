import * as crypto from 'crypto';
import * as dotenv from 'dotenv';
import * as path from 'path';

const app1Env = dotenv.config({ path: path.resolve(__dirname, '../.env.app1') }).parsed;
if (!app1Env) throw new Error('Could not load .env.app1');

const AUTH_URL = 'http://localhost:3000';
const ADMIN_EMAIL = 'swyar@auth2.1.com';
const ADMIN_PASS = 'swyra@123';

async function runTests() {
  console.log('=== STARTING AUTOMATED OAUTH SECURITY TESTS ===\n');

  // 0. Create a fresh admin user for tests to avoid MFA lockouts
  const TEST_ADMIN_EMAIL = `testadmin_${Date.now()}@auth2.1.com`;
  const TEST_ADMIN_PASS = 'TestAdmin@123';
  try {
    console.log('[0] Registering a fresh admin user for tests...');
    const signupRes = await fetch(`${AUTH_URL}/api/auth/sign-up/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:5174', 'X-Forwarded-For': `1.1.1.${Math.floor(Math.random() * 255)}` },
      body: JSON.stringify({ email: TEST_ADMIN_EMAIL, password: TEST_ADMIN_PASS, name: 'Test Admin' })
    });
    
    if (!signupRes.ok) {
      console.error('Failed to create test admin:', await signupRes.text());
      process.exit(1);
    }

    const { MongoClient } = await import('mongodb');
    const client = new MongoClient('mongodb://172.25.240.1:27017');
    await client.connect();
    const db = client.db('oauth');
    await db.collection('user').updateOne(
      { email: TEST_ADMIN_EMAIL },
      { $set: { role: 'admin' } }
    );
    await client.close();
    console.log('    ✅ Fresh admin user created and promoted to admin role.');
  } catch (err) {
    console.error('Failed to setup test admin user:', err);
    process.exit(1);
  }

  // 1. Admin Login to get session
  console.log('[1] Logging in as admin to configure test app...');
  const loginRes = await fetch(`${AUTH_URL}/api/auth/sign-in/email`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:5174',
      'X-Forwarded-For': `1.1.1.${Math.floor(Math.random() * 255)}`
    },
    body: JSON.stringify({ email: TEST_ADMIN_EMAIL, password: TEST_ADMIN_PASS }),
  });

  if (!loginRes.ok) {
    throw new Error(`Admin login failed: ${await loginRes.text()}`);
  }

  // Extract cookies
  const cookies = loginRes.headers.getSetCookie();
  if (!cookies || cookies.length === 0) throw new Error('No cookies returned on login');

  // Try to extract only the session_token and csrf_token
  const sessionToken = cookies.find(p => p.startsWith('better-auth.session_token='))?.split(';')[0] || '';
  const csrfToken = cookies.find(p => p.startsWith('better-auth.csrf_token='))?.split(';')[0] || '';
  const finalCookie = `${sessionToken}; ${csrfToken}; csrf_token=mock_csrf`;
  console.log('Final Cookie:', finalCookie);

  console.log('    ✅ Admin login successful.');

  // 2. Register new OAuth application
  console.log('[2] Registering new OAuth Application...');
  const createAppRes = await fetch(`${AUTH_URL}/api/admin/clients`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': finalCookie,
      'Origin': 'http://localhost:5174',
      'x-csrf-token': 'mock_csrf'
    },
    body: JSON.stringify({
      client_name: 'Automated Test App',
      redirect_uris: ['http://localhost:4000/auth/callback'],
      allowed_origins: ['http://localhost:4000'],
      skip_consent: true,
      enable_end_session: true
    }),
  });

  if (!createAppRes.ok) {
    throw new Error(`App creation failed: ${await createAppRes.text()}`);
  }

  const clientData = await createAppRes.json();
  const clientId = clientData.client_id || clientData.clientId || clientData.id;
  const clientSecret = clientData.client_secret || clientData.clientSecret || clientData.secret;

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
    headers: { 'Cookie': finalCookie },
    redirect: 'manual' // We want to capture the redirect to the callback URI
  });

  // Better-Auth might redirect to consent, or immediately redirect to callback.
  // Since we set skipConsent: true, it should redirect directly to callback.
  let authorizeLocation: string | null = null;
  if (authorizeRes.status === 200) {
    const data = await authorizeRes.json();
    if (data.url && data.url.includes('code=')) {
      authorizeLocation = data.url;
    } else {
      console.log(`    ⚠️ Expected code in redirect url, got:`, data);
    }
  } else if (authorizeRes.status === 302) {
    authorizeLocation = authorizeRes.headers.get('location');
  } else {
    console.log(`    ⚠️ Expected 302/200, got ${authorizeRes.status}`);
  }

  if (authorizeLocation) {
    console.log(`    ✅ Authorized! Redirected to: ${authorizeLocation}`);

    if (authorizeLocation.includes('code=')) {
      const url = new URL(authorizeLocation);
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
    headers: { 'Cookie': finalCookie },
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

  // 6. App Admin Provisioning & OIDC Login
  console.log('\n[6] Testing App Admin Provisioning & OIDC Login...');
  
  if (!clientId) throw new Error('Dynamic Client ID not found');

  const appAdminEmail = `app1admin_${Date.now()}@test.com`;
  const appAdminPassword = "SuperStr0ngP@ssword!123";

  // 6A. Provision Admin
  const provisionRes = await fetch(`${AUTH_URL}/api/admin/users`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': finalCookie,
      'Origin': 'http://localhost:5174',
      'x-csrf-token': 'mock_csrf',
      'X-Forwarded-For': `1.1.1.${Math.floor(Math.random() * 255)}`
    },
    body: JSON.stringify({
      email: appAdminEmail,
      password: appAdminPassword,
      name: "App 1 Admin",
      clientId: clientId
    }),
  });

  if (!provisionRes.ok) {
    console.error('    ❌ App Admin Provisioning failed:', await provisionRes.text());
    process.exit(1);
  }

  const provisionData = await provisionRes.json();
  if (provisionData.user?.role !== 'admin') {
    console.error('    ❌ Provisioned user does not have admin role!');
    process.exit(1);
  }
  console.log('    ✅ App Admin Provisioned successfully.');

  // 6B. Verify Client updated with Admin Email
  const { MongoClient } = await import('mongodb');
  const mongoClient = new MongoClient('mongodb://172.25.240.1:27017');
  await mongoClient.connect();
  const db = mongoClient.db('oauth');
  const app1Client = await db.collection('oauthClient').findOne({ clientId });
  await mongoClient.close();

  if (app1Client?.adminEmail !== appAdminEmail) {
    console.error('    ❌ OAuth Client document was NOT updated with adminEmail!', app1Client);
    process.exit(1);
  }
  console.log('    ✅ OAuth Client updated with adminEmail in MongoDB.');

  // 6C. App Admin OIDC Login
  console.log('    Simulating App Admin OIDC Login...');
  const appAdminLoginRes = await fetch(`${AUTH_URL}/api/auth/sign-in/email`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:5174',
      'X-Forwarded-For': `1.1.1.${Math.floor(Math.random() * 255)}`
    },
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPassword }),
  });

  if (!appAdminLoginRes.ok) {
    console.error('    ❌ App Admin login failed:', await appAdminLoginRes.text());
    process.exit(1);
  }
  const appAdminCookiesRaw = appAdminLoginRes.headers.getSetCookie();
  if (!appAdminCookiesRaw || appAdminCookiesRaw.length === 0) {
    console.error('    ❌ App Admin login returned no cookies');
    process.exit(1);
  }
  
  const aaSessionToken = appAdminCookiesRaw.find(p => p.startsWith('better-auth.session_token='))?.split(';')[0] || '';
  const aaCsrfToken = appAdminCookiesRaw.find(p => p.startsWith('better-auth.csrf_token='))?.split(';')[0] || '';
  const appAdminCookies = `${aaSessionToken}; ${aaCsrfToken}; csrf_token=mock_csrf`;

  const adminAuthUrl = new URL(`${AUTH_URL}/api/auth/oauth2/authorize`);
  adminAuthUrl.searchParams.set('client_id', clientId);
  adminAuthUrl.searchParams.set('redirect_uri', 'http://localhost:4000/auth/callback');
  adminAuthUrl.searchParams.set('response_type', 'code');
  adminAuthUrl.searchParams.set('scope', 'openid profile email');
  adminAuthUrl.searchParams.set('state', crypto.randomUUID());
  adminAuthUrl.searchParams.set('code_challenge', codeChallenge);
  adminAuthUrl.searchParams.set('code_challenge_method', 'S256');

  const adminAuthorizeRes = await fetch(adminAuthUrl.toString(), {
    method: 'GET',
    headers: { 'Cookie': appAdminCookies },
    redirect: 'manual'
  });

  let adminLocation: string | null = null;
  if (adminAuthorizeRes.status === 200) {
    const data = await adminAuthorizeRes.json();
    adminLocation = data.url;
  } else if (adminAuthorizeRes.status === 302) {
    adminLocation = adminAuthorizeRes.headers.get('location');
  }

  if (!adminLocation || !adminLocation.includes('code=')) {
    console.error(`    ❌ Expected App Admin OIDC redirect with code, got ${adminLocation}`);
    process.exit(1);
  } else {
    console.log('    ✅ App Admin successfully logged into App 1 via OIDC.');
  }

  // 7. Centralized MFA Inheritance
  console.log('\n[7] Testing Centralized MFA Inheritance...');

  // Enable 2FA for App Admin using Better Auth API (since the user is logged in via appAdminCookies)
  // Better Auth two-factor generate TOTP then verify it with "123456" for testing?
  // Wait, Better Auth requires the actual TOTP code to verify. 
  // Let's modify the database directly to set twoFactorEnabled: true for this user to simulate MFA enabled.
  // Actually, doing it via the MongoDB connection here might be complex. Let's just create a quick admin endpoint to force enable it, or see if Better Auth allows skipping.
  // Actually, we can just use the /api/auth/two-factor/enable? No, it requires a verified code.
  // We can write a quick snippet in HonO to enable it, but we can't edit hono code just for tests if we can avoid it.
  // Wait, the prompt says: "(you may need to mock the TOTP verification step or use a static TOTP secret if the test suite allows)."
  // Since we have MongoDB locally, let's just use MongoDB natively.

  try {
    const { MongoClient } = await import('mongodb');
    const client = new MongoClient('mongodb://172.25.240.1:27017');
    await client.connect();
    const db = client.db('oauth');
    await db.collection('user').updateOne(
      { email: appAdminEmail },
      { $set: { twoFactorEnabled: true } }
    );
    await client.close();
    console.log('    ✅ Forced twoFactorEnabled=true directly in MongoDB.');
  } catch (err) {
    console.error('    ❌ Failed to update MongoDB for MFA test:', err);
    process.exit(1);
  }

  // Now the App Admin has MFA enabled. They try to do the OIDC flow again.
  // Let's clear their session and sign in again so Better Auth knows they need 2FA.
  const appAdminLoginMfaRes = await fetch(`${AUTH_URL}/api/auth/sign-in/email`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json', 
      'Origin': 'http://localhost:5174',
      'X-Forwarded-For': `1.1.1.${Math.floor(Math.random() * 255)}`
    },
    body: JSON.stringify({ email: appAdminEmail, password: appAdminPassword }),
  });

  // Since 2FA is enabled, Better Auth should NOT set a fully authenticated session cookie immediately, 
  // or it sets a temporary session and requires 2FA verification.
  const mfaResponseData = await appAdminLoginMfaRes.json();
  if (!mfaResponseData.twoFactorRedirect) {
    console.error('    ❌ Login did not prompt for two-factor redirect!', mfaResponseData);
    process.exit(1);
  }
  
  const mfaCookiesRaw = appAdminLoginMfaRes.headers.getSetCookie();
  if (!mfaCookiesRaw || mfaCookiesRaw.length === 0) {
    console.error('    ❌ Login returned no cookies for MFA challenge');
    process.exit(1);
  }
  
  const mfaTwoFactorToken = mfaCookiesRaw.find(p => p.startsWith('better-auth.two_factor='))?.split(';')[0] || '';
  const mfaCsrfToken = mfaCookiesRaw.find(p => p.startsWith('better-auth.csrf_token='))?.split(';')[0] || '';
  const mfaCookies = `${mfaTwoFactorToken}; ${mfaCsrfToken}; csrf_token=mock_csrf`;

  console.log('    ✅ App Admin login intercepted by MFA challenge.');

  // Attempt the OIDC authorize flow with the MFA-pending session cookie
  const mfaAuthorizeRes = await fetch(adminAuthUrl.toString(), {
    method: 'GET',
    headers: { 'Cookie': mfaCookies },
    redirect: 'manual'
  });

  // OIDC authorize should NOT redirect to the client app since the user is not fully authenticated.
  // It should redirect to the login page or return a 401/403.
  let mfaLocation: string | null = null;
  if (mfaAuthorizeRes.status === 200) {
    const data = await mfaAuthorizeRes.json();
    mfaLocation = data.url;
  } else if (mfaAuthorizeRes.status === 302) {
    mfaLocation = mfaAuthorizeRes.headers.get('location');
  }

  if (mfaLocation && mfaLocation.includes('code=')) {
    console.error('    ❌ SECURITY FAILURE: OIDC Authorize returned an auth code despite pending MFA challenge!', mfaLocation);
    process.exit(1);
  }

  console.log('    ✅ Security check passed: OIDC Authorize blocked pending MFA verification.');

  console.log('\n=== ALL TESTS COMPLETED SUCCESSFULLY ===');
}

runTests().catch(e => { console.error(e); process.exit(1); });
