import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { readFileSync, existsSync } from 'node:fs'
import { getRequestListener } from '@hono/node-server'
import app from './index.js'

const HTTP_PORT  = Number(process.env.HTTP_PORT)  || 80
const HTTPS_PORT = Number(process.env.HTTPS_PORT) || 443
const HOST       = process.env.HOST || '0.0.0.0'

// ─── Warna terminal ──────────────────────────────────────────────────────────
const G = '\x1b[32m', C = '\x1b[36m', Y = '\x1b[33m', R = '\x1b[31m', NC = '\x1b[0m', B = '\x1b[1m'

// ─── Cari SSL certificate (Let's Encrypt atau custom path) ───────────────────
function findCert(domain?: string): { key: Buffer; cert: Buffer } | null {
  const candidates: Array<{ key: string; cert: string }> = []

  // Let's Encrypt — deteksi dari DOMAIN env atau domain pertama yang ada
  const leDomain = domain || process.env.DOMAIN || ''
  if (leDomain) {
    candidates.push({
      key:  `/etc/letsencrypt/live/${leDomain}/privkey.pem`,
      cert: `/etc/letsencrypt/live/${leDomain}/fullchain.pem`,
    })
  }
  // Let's Encrypt wildcard scan (ambil domain pertama yang ditemukan)
  if (existsSync('/etc/letsencrypt/live')) {
    try {
      const { readdirSync } = require('node:fs')
      const domains = readdirSync('/etc/letsencrypt/live')
      for (const d of domains) {
        candidates.push({
          key:  `/etc/letsencrypt/live/${d}/privkey.pem`,
          cert: `/etc/letsencrypt/live/${d}/fullchain.pem`,
        })
      }
    } catch { /* skip */ }
  }
  // Custom path dari env
  if (process.env.SSL_KEY && process.env.SSL_CERT) {
    candidates.push({ key: process.env.SSL_KEY, cert: process.env.SSL_CERT })
  }

  for (const c of candidates) {
    if (existsSync(c.key) && existsSync(c.cert)) {
      try {
        return { key: readFileSync(c.key), cert: readFileSync(c.cert) }
      } catch { /* try next */ }
    }
  }
  return null
}

// ─── Buat self-signed cert jika tidak ada cert nyata ─────────────────────────
async function generateSelfSigned(): Promise<{ key: Buffer; cert: Buffer } | null> {
  try {
    const { execSync } = await import('node:child_process')
    const keyPath  = '/tmp/gitleak_self.key'
    const certPath = '/tmp/gitleak_self.crt'
    if (!existsSync(keyPath) || !existsSync(certPath)) {
      execSync(
        `openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath}` +
        ` -days 3650 -nodes -subj "/CN=localhost"`,
        { stdio: 'pipe' }
      )
    }
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) }
  } catch {
    return null
  }
}

// ─── HTTP server (port 80) ────────────────────────────────────────────────────
const requestListener = getRequestListener(app.fetch)

const httpServer = createHttpServer((req, res) => {
  // Jika HTTPS aktif → redirect HTTP ke HTTPS
  const host = req.headers.host?.replace(/:\d+$/, '') || 'localhost'
  const httpsPort = HTTPS_PORT === 443 ? '' : `:${HTTPS_PORT}`
  res.writeHead(301, { Location: `https://${host}${httpsPort}${req.url}` })
  res.end()
})

// ─── Start servers ────────────────────────────────────────────────────────────
async function start() {
  const ssl = findCert() || await generateSelfSigned()

  if (ssl) {
    // ── HTTPS di port 443 ──
    const httpsServer = createHttpsServer(
      { key: ssl.key, cert: ssl.cert },
      requestListener
    )
    httpsServer.listen(HTTPS_PORT, HOST, () => {
      const certType = findCert() ? 'Let\'s Encrypt / custom cert' : 'self-signed cert'
      console.log(`${B}${G}`)
      console.log(`  ██████╗ ██╗████████╗██╗     ███████╗ █████╗ ██╗  ██╗`)
      console.log(`  ██╔════╝██║╚══██╔══╝██║     ██╔════╝██╔══██╗██║ ██╔╝`)
      console.log(`  ██║  ███╗██║   ██║   ██║     █████╗  ███████║█████╔╝ `)
      console.log(`  ██║   ██║██║   ██║   ██║     ██╔══╝  ██╔══██║██╔═██╗ `)
      console.log(`  ╚██████╔╝██║   ██║   ███████╗███████╗██║  ██║██║  ██╗`)
      console.log(`   ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝${NC}`)
      console.log(``)
      console.log(`${B}${G}  ✅ HTTPS  →  https://localhost:${HTTPS_PORT}${NC}  ${Y}(${certType})${NC}`)
      console.log(`${B}${C}  🔀 HTTP   →  http://localhost:${HTTP_PORT}  (redirect → HTTPS)${NC}`)
      console.log(`${C}  Press Ctrl+C to stop${NC}\n`)
    })

    // ── HTTP redirect di port 80 ──
    httpServer.listen(HTTP_PORT, HOST, () => {
      // already logged above
    })

  } else {
    // Fallback: hanya HTTP di port 80 (openssl tidak tersedia)
    const fallbackServer = createHttpServer(requestListener)
    fallbackServer.listen(HTTP_PORT, HOST, () => {
      console.log(`${B}${Y}  ⚠  HTTPS tidak tersedia (openssl tidak ditemukan)${NC}`)
      console.log(`${B}${G}  ✅ HTTP  →  http://localhost:${HTTP_PORT}${NC}`)
      console.log(`${C}  Press Ctrl+C to stop${NC}\n`)
    })
  }
}

start().catch((err) => {
  console.error(`${R}❌ Gagal start server: ${err.message}${NC}`)
  process.exit(1)
})
