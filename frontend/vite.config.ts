import { defineConfig } from 'vite'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'
import tailwindcss from '@tailwindcss/vite'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

function getDevGatewaySecret(): string | undefined {
  if (process.env.INTERNAL_GATEWAY_SECRET) {
    return process.env.INTERNAL_GATEWAY_SECRET
  }
  const backendEnvPath = path.resolve(__dirname, '../backend/.env')
  if (fs.existsSync(backendEnvPath)) {
    const content = fs.readFileSync(backendEnvPath, 'utf8')
    const match = content.match(/^INTERNAL_GATEWAY_SECRET=(.*)$/m)
    if (match && match[1]) {
      return match[1].trim().replace(/^["']|["']$/g, '')
    }
  }
  return undefined
}

const devGatewaySecret = getDevGatewaySecret()

export default defineConfig({
  resolve: {
    alias: {
      '@': __dirname,
    },
  },
  plugins: [
    react(),
    babel({ presets: [reactCompilerPreset()] }),
    tailwindcss()
  ],

  server: {
    host: '0.0.0.0', // IMPORTANT
    port: 5174,
    allowedHosts: true,

    watch: {
      usePolling: true,
      interval: 100,
    },

    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        headers: devGatewaySecret ? { 'x-gateway-secret': devGatewaySecret } : undefined,
        configure: (proxy) => {
          if (devGatewaySecret) {
            proxy.on('proxyReq', (proxyReq) => {
              proxyReq.setHeader('x-gateway-secret', devGatewaySecret)
            })
          }
        },
      },
      '/.well-known': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },

})
