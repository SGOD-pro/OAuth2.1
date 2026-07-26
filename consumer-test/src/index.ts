import { createRemoteJWKSet, jwtVerify } from 'jose'
import * as crypto from 'crypto'
import * as http from 'http'
import * as url from 'url'
import * as dotenv from 'dotenv'

dotenv.config()

const AUTH_ISSUER   = process.env.AUTH_ISSUER!
const CLIENT_ID     = process.env.CLIENT_ID!
const CLIENT_SECRET = process.env.CLIENT_SECRET!
const JWKS_URL      = process.env.JWKS_URL!
const CALLBACK_URL  = process.env.AUTH_CALLBACK_URL!
const PORT          = parseInt(process.env.PORT || '4000', 10)

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
console.log('  SWYRA Auth — Test Consumer App')
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
console.log(`  AUTH_ISSUER:  ${AUTH_ISSUER}`)
console.log(`  CLIENT_ID:    ${CLIENT_ID}`)
console.log(`  JWKS_URL:     ${JWKS_URL}`)
console.log(`  CALLBACK_URL: ${CALLBACK_URL}`)
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n')

// ── PKCE Utilities ────────────────────────────────────────────
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url')
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url')
}

// ── In-memory stores ──────────────────────────────────────────
interface PendingAuth {
  codeVerifier: string
  state: string
}

interface UserSession {
  accessToken: string
  refreshToken: string
  expiresAt: number
}

const pendingAuths = new Map<string, PendingAuth>()
const sessions     = new Map<string, UserSession>()

// ── Token Verification via Introspection ──────────────────────
async function verifyToken(token: string) {
  const response = await fetch(
    `${AUTH_ISSUER}/api/auth/oauth2/introspect`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }).toString(),
    }
  )

  const result = await response.json()

  if (!result.active) {
    throw new Error('Token is not active')
  }

  const userInfoRes = await fetch(
    `${AUTH_ISSUER}/api/auth/oauth2/userinfo`,
    { headers: { Authorization: `Bearer ${token}` } }
  )
  const userInfo = await userInfoRes.json()

  return { ...result, ...userInfo }
}

// ── Refresh Token ─────────────────────────────────────────────
async function refreshAccessToken(refreshToken: string): Promise<{
  access_token: string
  refresh_token: string
  expires_in: number
}> {
  const response = await fetch(
    `${AUTH_ISSUER}/api/auth/oauth2/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'refresh_token',
        refresh_token: refreshToken,
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }).toString(),
    }
  )

  if (!response.ok) {
    throw new Error(`Token refresh failed: ${response.status}`)
  }

  return response.json()
}

// ── Cookie Parser ─────────────────────────────────────────────
function parseCookies(header: string): Record<string, string> {
  const cookies: Record<string, string> = {}
  header.split(';').forEach((cookie) => {
    const [key, ...rest] = cookie.trim().split('=')
    if (key) cookies[key] = rest.join('=')
  })
  return cookies
}

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url || '', true)
  const pathname  = parsedUrl.pathname

  if (pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SWYRA Test Consumer</title>
        <style>
          body { font-family: sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; }
          a { display: inline-block; margin: 8px 0; padding: 10px 20px; 
              background: #6366f1; color: white; text-decoration: none; border-radius: 6px; }
          a:hover { background: #4f46e5; }
          pre { background: #f1f5f9; padding: 16px; border-radius: 6px; overflow: auto; }
        </style>
      </head>
      <body>
        <h1>SWYRA Auth — Test Consumer</h1>
        <p>This app tests the full OAuth 2.1 + PKCE integration with SWYRA Auth.</p>
        <a href="/login">Login via SWYRA Auth</a>
        <a href="/protected">Protected Route</a>
        <a href="/logout">Logout</a>
      </body>
      </html>
    `)
    return
  }

  if (pathname === '/login') {
    const codeVerifier  = generateCodeVerifier()
    const codeChallenge = generateCodeChallenge(codeVerifier)
    const state         = crypto.randomUUID()

    pendingAuths.set(state, { codeVerifier, state })

    const authUrl = new URL(`${AUTH_ISSUER}/api/auth/oauth2/authorize`)
    authUrl.searchParams.set('client_id',             CLIENT_ID)
    authUrl.searchParams.set('redirect_uri',          CALLBACK_URL)
    authUrl.searchParams.set('response_type',         'code')
    authUrl.searchParams.set('scope',                 'openid profile email offline_access')
    authUrl.searchParams.set('state',                 state)
    authUrl.searchParams.set('code_challenge',        codeChallenge)
    authUrl.searchParams.set('code_challenge_method', 'S256')

    console.log(`[LOGIN] Redirecting to auth service`)
    console.log(`[LOGIN] state: ${state}`)

    res.writeHead(302, { Location: authUrl.toString() })
    res.end()
    return
  }

  if (pathname === '/auth/callback') {
    const { code, state: returnedState } = parsedUrl.query as { code?: string, state?: string }

    if (!code || !returnedState) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Missing code or state parameter' }))
      return
    }

    const pending = pendingAuths.get(returnedState)
    if (!pending) {
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'State mismatch — possible CSRF attack' }))
      return
    }

    pendingAuths.delete(returnedState)

    try {
      const tokenResponse = await fetch(
        `${AUTH_ISSUER}/api/auth/oauth2/token`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type:    'authorization_code',
            code:          code,
            redirect_uri:  CALLBACK_URL,
            client_id:     CLIENT_ID,
            client_secret: CLIENT_SECRET,
            code_verifier: pending.codeVerifier,
          }).toString(),
        }
      )

      if (!tokenResponse.ok) {
        const errBody = await tokenResponse.text()
        console.error('[CALLBACK] Token exchange failed:', errBody)
        res.writeHead(tokenResponse.status, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Token exchange failed', details: errBody }))
        return
      }

      const tokens = await tokenResponse.json()
      
      const sessionId = crypto.randomUUID()
      sessions.set(sessionId, {
        accessToken:  tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt:    Date.now() + (tokens.expires_in ?? 900) * 1000,
      })

      res.writeHead(302, {
        Location:   '/protected',
        'Set-Cookie': `session=${sessionId}; HttpOnly; Path=/; SameSite=Lax`,
      })
      res.end()
    } catch (err) {
      console.error('[CALLBACK] Error:', err)
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Token exchange error', details: String(err) }))
    }
    return
  }

  if (pathname === '/protected') {
    const cookies   = parseCookies(req.headers.cookie || '')
    const sessionId = cookies['session']

    if (!sessionId || !sessions.has(sessionId)) {
      res.writeHead(302, { Location: '/login' })
      res.end()
      return
    }

    const session = sessions.get(sessionId)!

    if (Date.now() >= session.expiresAt) {
      try {
        const refreshed = await refreshAccessToken(session.refreshToken)
        session.accessToken  = refreshed.access_token
        session.refreshToken = refreshed.refresh_token
        session.expiresAt    = Date.now() + refreshed.expires_in * 1000
      } catch (err) {
        sessions.delete(sessionId)
        res.writeHead(302, { Location: '/login' })
        res.end()
        return
      }
    }

    try {
      const payload = await verifyToken(session.accessToken)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        message: 'Authenticated!',
        user: { sub: payload.sub, email: payload.email, name: payload.name },
        tokenInfo: payload,
      }, null, 2))
    } catch (err) {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Invalid token', details: String(err) }))
    }
    return
  }

  if (pathname === '/logout') {
    const cookies   = parseCookies(req.headers.cookie || '')
    const sessionId = cookies['session']
    if (sessionId) sessions.delete(sessionId)

    res.writeHead(302, {
      Location:     '/',
      'Set-Cookie': 'session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0',
    })
    res.end()
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ error: 'Not found' }))
})

server.listen(PORT, () => {
  console.log(`  Visit http://localhost:${PORT} to start the flow`)
})
