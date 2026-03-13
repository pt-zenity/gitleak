import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { readFileSync, existsSync } from 'node:fs'
import { getRequestListener } from '@hono/node-server'
import app from './index.js'

// ─── Config ──────────────────────────────────────────────────────────────────
const HTTP_PORT  = Number(process.env.HTTP_PORT)  || 80
const HTTPS_PORT = Number(process.env.HTTPS_PORT) || 443
const HOST       = process.env.HOST || '0.0.0.0'

// SSL_MODE:
//   'cloudflare'      → Cloudflare Origin Certificate (Full/Full Strict)
//   'letsencrypt'     → Let's Encrypt cert
//   'flexible'        → HTTP only, Cloudflare handle HTTPS (default jika tidak ada cert)
//   'custom'          → SSL_KEY + SSL_CERT env
const SSL_MODE = (process.env.SSL_MODE || 'auto').toLowerCase()

// Path Cloudflare Origin Certificate
// Bisa di-override via env CF_ORIGIN_KEY dan CF_ORIGIN_CERT
const CF_KEY_PATH  = process.env.CF_ORIGIN_KEY  || '/etc/ssl/cloudflare/origin.key'
const CF_CERT_PATH = process.env.CF_ORIGIN_CERT || '/etc/ssl/cloudflare/origin.pem'

// ─── Warna terminal ──────────────────────────────────────────────────────────
const G = '\x1b[32m', C = '\x1b[36m', Y = '\x1b[33m', R = '\x1b[31m', NC = '\x1b[0m', B = '\x1b[1m'

function banner() {
  console.log(`${B}${G}`)
  console.log(`  ██████╗ ██╗████████╗██╗     ███████╗ █████╗ ██╗  ██╗`)
  console.log(`  ██╔════╝██║╚══██╔══╝██║     ██╔════╝██╔══██╗██║ ██╔╝`)
  console.log(`  ██║  ███╗██║   ██║   ██║     █████╗  ███████║█████╔╝ `)
  console.log(`  ██║   ██║██║   ██║   ██║     ██╔══╝  ██╔══██║██╔═██╗ `)
  console.log(`  ╚██████╔╝██║   ██║   ███████╗███████╗██║  ██║██║  ██╗`)
  console.log(`   ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝${NC}`)
  console.log(``)
}

// ─── Cari SSL cert berdasarkan mode ──────────────────────────────────────────
function loadCert(): { key: Buffer; cert: Buffer; type: string } | null {

  // 1. Cloudflare Origin Certificate
  if (SSL_MODE === 'cloudflare' || SSL_MODE === 'auto') {
    if (existsSync(CF_KEY_PATH) && existsSync(CF_CERT_PATH)) {
      try {
        return {
          key:  readFileSync(CF_KEY_PATH),
          cert: readFileSync(CF_CERT_PATH),
          type: 'Cloudflare Origin Certificate',
        }
      } catch { /* try next */ }
    }
    if (SSL_MODE === 'cloudflare') {
      throw new Error(
        `Cloudflare Origin Certificate tidak ditemukan!\n` +
        `  key : ${CF_KEY_PATH}\n` +
        `  cert: ${CF_CERT_PATH}\n` +
        `Lihat README untuk cara mendapatkan Origin Certificate dari Cloudflare Dashboard.`
      )
    }
  }

  // 2. Custom cert dari env
  if ((SSL_MODE === 'custom' || SSL_MODE === 'auto') &&
      process.env.SSL_KEY && process.env.SSL_CERT) {
    if (existsSync(process.env.SSL_KEY) && existsSync(process.env.SSL_CERT)) {
      try {
        return {
          key:  readFileSync(process.env.SSL_KEY),
          cert: readFileSync(process.env.SSL_CERT),
          type: 'Custom certificate',
        }
      } catch { /* try next */ }
    }
  }

  // 3. Let's Encrypt
  if (SSL_MODE === 'letsencrypt' || SSL_MODE === 'auto') {
    const leDomain = process.env.DOMAIN || ''
    const candidates: string[] = []
    if (leDomain) candidates.push(leDomain)
    if (existsSync('/etc/letsencrypt/live')) {
      try {
        const { readdirSync } = require('node:fs')
        candidates.push(...readdirSync('/etc/letsencrypt/live'))
      } catch { /* skip */ }
    }
    for (const d of candidates) {
      const k = `/etc/letsencrypt/live/${d}/privkey.pem`
      const c = `/etc/letsencrypt/live/${d}/fullchain.pem`
      if (existsSync(k) && existsSync(c)) {
        try {
          return { key: readFileSync(k), cert: readFileSync(c), type: `Let's Encrypt (${d})` }
        } catch { /* try next */ }
      }
    }
  }

  return null
}

// ─── Request listener ─────────────────────────────────────────────────────────
const requestListener = getRequestListener(app.fetch)

// ─── HTTP → HTTPS redirect ────────────────────────────────────────────────────
function makeRedirectServer(httpsPort: number) {
  return createHttpServer((req, res) => {
    const host = req.headers.host?.replace(/:\d+$/, '') || 'localhost'
    const portSuffix = httpsPort === 443 ? '' : `:${httpsPort}`
    res.writeHead(301, { Location: `https://${host}${portSuffix}${req.url}` })
    res.end()
  })
}

// ─── Start ────────────────────────────────────────────────────────────────────
async function start() {

  // Mode FLEXIBLE — hanya HTTP, Cloudflare handle SSL dari sisi mereka
  if (SSL_MODE === 'flexible') {
    const httpServer = createHttpServer(requestListener)
    httpServer.listen(HTTP_PORT, HOST, () => {
      banner()
      console.log(`${B}${Y}  ☁️  Mode: Cloudflare Flexible SSL${NC}`)
      console.log(`${B}${G}  ✅ HTTP   →  http://localhost:${HTTP_PORT}${NC}`)
      console.log(`${C}     Cloudflare handle HTTPS ke pengunjung${NC}`)
      console.log(`${C}  Press Ctrl+C to stop${NC}\n`)
    })
    return
  }

  // Coba load cert
  let certData: { key: Buffer; cert: Buffer; type: string } | null = null
  try {
    certData = loadCert()
  } catch (err: any) {
    console.error(`${R}❌ ${err.message}${NC}`)
    process.exit(1)
  }

  if (certData) {
    // ── HTTPS di port 443 ──
    const httpsServer = createHttpsServer(
      { key: certData.key, cert: certData.cert },
      requestListener
    )
    httpsServer.listen(HTTPS_PORT, HOST, () => {
      banner()
      console.log(`${B}${G}  ✅ HTTPS  →  https://localhost:${HTTPS_PORT}${NC}`)
      console.log(`${B}${Y}     SSL: ${certData!.type}${NC}`)
      console.log(`${B}${C}  🔀 HTTP   →  http://localhost:${HTTP_PORT}  (redirect → HTTPS)${NC}`)
      console.log(`${C}  Press Ctrl+C to stop${NC}\n`)
    })
    // ── HTTP redirect di port 80 ──
    makeRedirectServer(HTTPS_PORT).listen(HTTP_PORT, HOST)

  } else {
    // Tidak ada cert → fallback HTTP saja (Cloudflare Flexible)
    const httpServer = createHttpServer(requestListener)
    httpServer.listen(HTTP_PORT, HOST, () => {
      banner()
      console.log(`${B}${Y}  ⚠  Tidak ada SSL cert — mode HTTP only${NC}`)
      console.log(`${Y}     Gunakan Cloudflare Flexible SSL, atau pasang cert:${NC}`)
      console.log(`${C}     - Cloudflare Origin Cert: ${CF_KEY_PATH} + ${CF_CERT_PATH}${NC}`)
      console.log(`${C}     - Let's Encrypt        : sudo certbot --nginx -d <domain>${NC}`)
      console.log(`${C}     - Custom               : SSL_KEY=... SSL_CERT=...${NC}`)
      console.log(``)
      console.log(`${B}${G}  ✅ HTTP   →  http://localhost:${HTTP_PORT}${NC}`)
      console.log(`${C}  Press Ctrl+C to stop${NC}\n`)
    })
  }
}

start().catch((err) => {
  console.error(`${R}❌ Gagal start server: ${err.message}${NC}`)
  process.exit(1)
})
