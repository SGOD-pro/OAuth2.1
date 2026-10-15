import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const rootVercelJson = path.join(rootDir, 'vercel.json');
const frontendVercelJson = path.join(rootDir, 'frontend', 'vercel.json');
const rootTemplate = path.join(rootDir, 'vercel.template.json');
const frontendTemplate = path.join(rootDir, 'frontend', 'vercel.template.json');

// Handle clean command
if (process.argv.includes('--clean')) {
  if (fs.existsSync(rootVercelJson)) fs.unlinkSync(rootVercelJson);
  if (fs.existsSync(frontendVercelJson)) fs.unlinkSync(frontendVercelJson);
  console.log('[prepare-vercel-config] Cleaned up generated vercel.json files.');
  process.exit(0);
}

const isIfPresent = process.argv.includes('--if-present');

let gatewaySecret = process.env.INTERNAL_GATEWAY_SECRET;

if (!gatewaySecret) {
  const backendEnvPath = path.join(rootDir, 'backend', '.env');
  if (fs.existsSync(backendEnvPath)) {
    const envContent = fs.readFileSync(backendEnvPath, 'utf8');
    const match = envContent.match(/^INTERNAL_GATEWAY_SECRET=(.*)$/m);
    if (match && match[1]) {
      gatewaySecret = match[1].trim().replace(/^["']|["']$/g, '');
    }
  }
}

if (!gatewaySecret) {
  const rootEnvPath = path.join(rootDir, '.env');
  if (fs.existsSync(rootEnvPath)) {
    const envContent = fs.readFileSync(rootEnvPath, 'utf8');
    const match = envContent.match(/^INTERNAL_GATEWAY_SECRET=(.*)$/m);
    if (match && match[1]) {
      gatewaySecret = match[1].trim().replace(/^["']|["']$/g, '');
    }
  }
}

if (!gatewaySecret) {
  if (isIfPresent) {
    console.warn('[prepare-vercel-config] INTERNAL_GATEWAY_SECRET not found; skipping vercel.json generation (--if-present).');
    process.exit(0);
  }
  console.error('[prepare-vercel-config] FATAL: INTERNAL_GATEWAY_SECRET not found in env or backend/.env');
  process.exit(1);
}

if (gatewaySecret.length < 32) {
  console.error(`[prepare-vercel-config] FATAL: INTERNAL_GATEWAY_SECRET must be >= 32 characters (got ${gatewaySecret.length})`);
  process.exit(1);
}

const defaultLambdaUrl = 'https://yu6fcg6yx4xmq5u4we5n6j3ywm0inmis.lambda-url.ap-south-1.on.aws';
const lambdaBackendUrl = (process.env.LAMBDA_BACKEND_URL || defaultLambdaUrl).trim().replace(/\/+$/, '');

// Generate from template or structure
const baseTemplate = fs.existsSync(rootTemplate)
  ? JSON.parse(fs.readFileSync(rootTemplate, 'utf8'))
  : {
      routes: [
        {
          src: '/api/(.*)',
          dest: `${lambdaBackendUrl}/api/$1`,
          transforms: [
            {
              type: 'request.headers',
              op: 'set',
              target: {
                key: 'x-gateway-secret',
              },
              args: '__INTERNAL_GATEWAY_SECRET__',
            },
          ],
        },
        {
          src: '/.well-known/(.*)',
          dest: `${lambdaBackendUrl}/.well-known/$1`,
        },
        {
          handle: 'filesystem',
        },
        {
          src: '/(.*)',
          dest: '/index.html',
        },
      ],
    };

let configStr = JSON.stringify(baseTemplate, null, 2);

if (process.env.LAMBDA_BACKEND_URL) {
  configStr = configStr.replace(
    /https:\/\/yu6fcg6yx4xmq5u4we5n6j3ywm0inmis\.lambda-url\.ap-south-1\.on\.aws/g,
    () => lambdaBackendUrl
  );
}

configStr = configStr.replace(
  /__INTERNAL_GATEWAY_SECRET__/g,
  () => gatewaySecret
);

fs.writeFileSync(rootVercelJson, configStr + '\n');
fs.writeFileSync(frontendVercelJson, configStr + '\n');
console.log('[prepare-vercel-config] Successfully generated untracked vercel.json artifacts from secure environment.');
