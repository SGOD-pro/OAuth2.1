import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

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

const config = {
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
          args: gatewaySecret,
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

const rootVercelJson = path.join(rootDir, 'vercel.json');
const frontendVercelJson = path.join(rootDir, 'frontend', 'vercel.json');

fs.writeFileSync(rootVercelJson, JSON.stringify(config, null, 2) + '\n');
fs.writeFileSync(frontendVercelJson, JSON.stringify(config, null, 2) + '\n');
console.log('[prepare-vercel-config] Successfully configured gateway transforms in vercel.json and frontend/vercel.json');
