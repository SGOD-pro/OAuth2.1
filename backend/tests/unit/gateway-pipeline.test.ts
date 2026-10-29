import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');
const scriptPath = path.join(repoRoot, 'scripts/prepare-vercel-config.mjs');
const rootVercelJson = path.join(repoRoot, 'vercel.json');
const frontendVercelJson = path.join(repoRoot, 'frontend/vercel.json');
const deployShPath = path.join(repoRoot, 'backend/deploy.sh');
const frontendPackagePath = path.join(repoRoot, 'frontend/package.json');

console.log('================================================================');
console.log('  TEST SUITE: Gateway Secret Persistence & Deploy Pipeline');
console.log('================================================================');

const rootEnvPath = path.join(repoRoot, '.env');
const backendEnvPath = path.join(repoRoot, 'backend/.env');
const rootEnvBackup = path.join(repoRoot, '.env.pipeline-test-bak');
const backendEnvBackup = path.join(repoRoot, 'backend/.env.pipeline-test-bak');

function cleanGeneratedFiles() {
  if (fs.existsSync(rootVercelJson)) fs.unlinkSync(rootVercelJson);
  if (fs.existsSync(frontendVercelJson)) fs.unlinkSync(frontendVercelJson);
}

function stashLocalEnvFiles() {
  if (fs.existsSync(rootEnvPath)) fs.renameSync(rootEnvPath, rootEnvBackup);
  if (fs.existsSync(backendEnvPath)) fs.renameSync(backendEnvPath, backendEnvBackup);
}

function restoreLocalEnvFiles() {
  if (fs.existsSync(rootEnvBackup)) fs.renameSync(rootEnvBackup, rootEnvPath);
  if (fs.existsSync(backendEnvBackup)) fs.renameSync(backendEnvBackup, backendEnvPath);
}

try {
  stashLocalEnvFiles();
  // Test 1: Clean command removes vercel.json files
  console.log('[TEST 1] Testing --clean argument behavior...');
  fs.writeFileSync(rootVercelJson, '{"test": true}');
  fs.writeFileSync(frontendVercelJson, '{"test": true}');
  assert.ok(fs.existsSync(rootVercelJson), 'root vercel.json must exist before clean');
  assert.ok(fs.existsSync(frontendVercelJson), 'frontend vercel.json must exist before clean');

  const cleanResult = spawnSync('node', [scriptPath, '--clean'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  assert.equal(cleanResult.status, 0, 'Clean command should exit with 0');
  assert.ok(!fs.existsSync(rootVercelJson), 'root vercel.json must be removed after clean');
  assert.ok(!fs.existsSync(frontendVercelJson), 'frontend vercel.json must be removed after clean');
  console.log('  [PASS] --clean removes generated vercel.json files cleanly');

  // Test 2: Missing secret with --if-present skips cleanly with exit 0
  console.log('[TEST 2] Testing --if-present without secret in environment...');
  cleanGeneratedFiles();
  const ifPresentResult = spawnSync('node', [scriptPath, '--if-present'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      INTERNAL_GATEWAY_SECRET: '',
    },
  });
  assert.equal(ifPresentResult.status, 0, '--if-present should exit with 0 when secret is missing');
  assert.ok(
    ifPresentResult.stderr.includes('INTERNAL_GATEWAY_SECRET not found') ||
      ifPresentResult.stdout.includes('INTERNAL_GATEWAY_SECRET not found'),
    'Should output warning message when skipping'
  );
  assert.ok(!fs.existsSync(rootVercelJson), 'root vercel.json must not be created when secret missing');
  console.log('  [PASS] --if-present skips cleanly with exit 0 and warning');

  // Test 3: Missing secret without --if-present fails with exit code 1
  console.log('[TEST 3] Testing missing secret without --if-present...');
  cleanGeneratedFiles();
  const missingResult = spawnSync('node', [scriptPath], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      INTERNAL_GATEWAY_SECRET: '',
    },
  });
  assert.equal(missingResult.status, 1, 'Should fail with exit code 1 when secret is missing without --if-present');
  console.log('  [PASS] Missing secret without --if-present fails closed with exit code 1');

  // Test 4: Secret shorter than 32 characters fails with exit code 1
  console.log('[TEST 4] Testing short secret rejection (< 32 characters)...');
  cleanGeneratedFiles();
  const shortResult = spawnSync('node', [scriptPath, '--if-present'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      INTERNAL_GATEWAY_SECRET: 'too_short_secret_123',
    },
  });
  assert.equal(shortResult.status, 1, 'Short secret must fail with exit code 1 even with --if-present');
  assert.ok(
    shortResult.stderr.includes('must be >= 32 characters'),
    'Error message must state >= 32 characters requirement'
  );
  console.log('  [PASS] Secret under 32 characters is rejected with exit code 1');

  // Test 5: Valid secret generates vercel.json and frontend/vercel.json
  console.log('[TEST 5] Testing valid secret generation...');
  cleanGeneratedFiles();
  const testSecret = 'test_gateway_secret_minimum_32_characters_valid_string';
  const validResult = spawnSync('node', [scriptPath, '--if-present'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      INTERNAL_GATEWAY_SECRET: testSecret,
    },
  });
  assert.equal(validResult.status, 0, 'Valid secret generation must exit with 0');
  assert.ok(fs.existsSync(rootVercelJson), 'root vercel.json must be generated');
  assert.ok(fs.existsSync(frontendVercelJson), 'frontend/vercel.json must be generated');

  const rootConfig = JSON.parse(fs.readFileSync(rootVercelJson, 'utf8'));
  const frontendConfig = JSON.parse(fs.readFileSync(frontendVercelJson, 'utf8'));
  assert.equal(rootConfig.routes[0].transforms[0].args, testSecret);
  assert.equal(frontendConfig.routes[0].transforms[0].args, testSecret);
  console.log('  [PASS] Valid secret correctly populates route transformation headers');

  // Test 6: LAMBDA_BACKEND_URL overrides default backend URL
  console.log('[TEST 6] Testing LAMBDA_BACKEND_URL override...');
  cleanGeneratedFiles();
  const customLambdaUrl = 'https://custom-lambda-url.example.com';
  const customResult = spawnSync('node', [scriptPath], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      INTERNAL_GATEWAY_SECRET: testSecret,
      LAMBDA_BACKEND_URL: customLambdaUrl,
    },
  });
  assert.equal(customResult.status, 0, 'Override execution must exit with 0');
  const customConfig = JSON.parse(fs.readFileSync(rootVercelJson, 'utf8'));
  assert.ok(
    customConfig.routes[0].dest.startsWith(customLambdaUrl),
    `API route dest must start with custom Lambda URL: ${customConfig.routes[0].dest}`
  );
  assert.ok(
    customConfig.routes[1].dest.startsWith(customLambdaUrl),
    `Well known route dest must start with custom Lambda URL: ${customConfig.routes[1].dest}`
  );
  console.log('  [PASS] LAMBDA_BACKEND_URL overrides default API and well known destinations');

  // Clean generated files after tests
  cleanGeneratedFiles();

  // Test 7: Verify frontend/package.json build script invokes prepare-vercel-config --if-present
  console.log('[TEST 7] Verifying frontend/package.json build script...');
  const frontendPkg = JSON.parse(fs.readFileSync(frontendPackagePath, 'utf8'));
  assert.ok(
    frontendPkg.scripts?.build?.includes('prepare-vercel-config.mjs --if-present'),
    'frontend build script must include prepare-vercel-config.mjs --if-present'
  );
  console.log('  [PASS] frontend/package.json build script enforces automated config preparation');

  // Test 8: Verify backend/deploy.sh includes secret validation and parameter override
  console.log('[TEST 8] Verifying backend/deploy.sh parameter overrides...');
  const deployShContent = fs.readFileSync(deployShPath, 'utf8');
  assert.ok(
    deployShContent.includes('InternalGatewaySecret="${INTERNAL_GATEWAY_SECRET}"'),
    'backend/deploy.sh must pass InternalGatewaySecret parameter override to sam deploy'
  );
  assert.ok(
    deployShContent.includes('-lt 32') || deployShContent.includes('< 32'),
    'backend/deploy.sh must validate minimum length of 32 characters'
  );
  console.log('  [PASS] backend/deploy.sh validates and passes gateway secret parameter overrides');

  // Test 9: Production mode must fail closed on missing secret even with --if-present
  console.log('[TEST 9] Testing production fail-closed behavior on missing secret with --if-present...');
  cleanGeneratedFiles();
  const prodMissingResult = spawnSync('node', [scriptPath, '--if-present'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_ENV: 'production',
      INTERNAL_GATEWAY_SECRET: '',
    },
  });
  assert.equal(prodMissingResult.status, 1, 'Production mode must fail closed with exit code 1 when secret is missing even with --if-present');
  console.log('  [PASS] Production mode fails closed on missing secret even with --if-present');

  // Test 10: Local UI build can explicitly skip deployment preparation
  console.log('[TEST 10] Testing local UI build explicit skip of deployment preparation...');
  cleanGeneratedFiles();
  const localSkipResult = spawnSync('node', [scriptPath, '--skip-deployment-prep'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_ENV: 'development',
      INTERNAL_GATEWAY_SECRET: '',
    },
  });
  assert.equal(localSkipResult.status, 0, 'Local UI build must exit with 0 when explicitly skipping deployment preparation');
  assert.ok(!fs.existsSync(rootVercelJson), 'vercel.json must not be created when explicitly skipping');
  console.log('  [PASS] Local UI build can explicitly skip deployment preparation');

  // Test 11: Production mode rejects skipping deployment preparation
  console.log('[TEST 11] Testing production mode rejection of skipping deployment preparation...');
  cleanGeneratedFiles();
  const prodSkipResult = spawnSync('node', [scriptPath, '--skip-deployment-prep'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_ENV: 'production',
      INTERNAL_GATEWAY_SECRET: '',
    },
  });
  assert.equal(prodSkipResult.status, 1, 'Production mode must reject skipping deployment preparation with exit 1');
  console.log('  [PASS] Production mode strictly rejects skipping deployment preparation');

  console.log('================================================================');
  console.log('  ALL GATEWAY PIPELINE TESTS PASSED (0 FAILURES)');
  console.log('================================================================');
} finally {
  cleanGeneratedFiles();
  restoreLocalEnvFiles();
}
