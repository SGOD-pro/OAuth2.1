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
  console.error('[prepare-vercel-config] FATAL: INTERNAL_GATEWAY_SECRET not found in env or backend/.env');
  process.exit(1);
}

if (gatewaySecret.length < 32) {
  console.error(`[prepare-vercel-config] FATAL: INTERNAL_GATEWAY_SECRET must be >= 32 characters (got ${gatewaySecret.length})`);
  process.exit(1);
}

// Generate from template or structure
const baseTemplate = fs.existsSync(rootTemplate)
  ? JSON.parse(fs.readFileSync(rootTemplate, 'utf8'))
  : {
      routes: [
        {
          src: '/api/(.*)',
          dest: 'https://yu6fcg6yx4xmq5u4we5n6j3ywm0inmis.lambda-url.ap-south-1.on.aws/api/$1',
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
          dest: 'https://yu6fcg6yx4xmq5u4we5n6j3ywm0inmis.lambda-url.ap-south-1.on.aws/.well-known/$1',
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

const configStr = JSON.stringify(baseTemplate, null, 2).replace(
  /__INTERNAL_GATEWAY_SECRET__/g,
  gatewaySecret
);

fs.writeFileSync(rootVercelJson, configStr + '\n');
fs.writeFileSync(frontendVercelJson, configStr + '\n');
console.log('[prepare-vercel-config] Successfully generated untracked vercel.json artifacts from secure environment.');
