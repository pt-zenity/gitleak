import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono()

app.use('/api/*', cors())

// ─── Sensitive Data Detection Patterns ───────────────────────────────────────
const SECRET_PATTERNS: {
  id: string
  label: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  pattern: RegExp
  description: string
  icon: string
}[] = [
  // AWS
  {
    id: 'aws_access_key',
    label: 'AWS Access Key ID',
    category: 'Cloud Credentials',
    severity: 'critical',
    pattern: /(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)/gm,
    description: 'Amazon Web Services Access Key ID',
    icon: '☁️',
  },
  {
    id: 'aws_secret_key',
    label: 'AWS Secret Access Key',
    category: 'Cloud Credentials',
    severity: 'critical',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gim,
    description: 'Amazon Web Services Secret Access Key',
    icon: '☁️',
  },
  // OpenAI
  {
    id: 'openai_key',
    label: 'OpenAI API Key',
    category: 'AI Service Keys',
    severity: 'critical',
    pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{50,}/g,
    description: 'OpenAI API secret key',
    icon: '🤖',
  },
  // Google
  {
    id: 'google_api_key',
    label: 'Google API Key',
    category: 'Cloud Credentials',
    severity: 'high',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    description: 'Google API Key',
    icon: '🔍',
  },
  {
    id: 'google_oauth',
    label: 'Google OAuth Token',
    category: 'OAuth Tokens',
    severity: 'high',
    pattern: /ya29\.[0-9A-Za-z\-_]+/g,
    description: 'Google OAuth 2.0 access token',
    icon: '🔐',
  },
  // GitHub
  {
    id: 'github_token',
    label: 'GitHub Token',
    category: 'VCS Tokens',
    severity: 'critical',
    pattern: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}/g,
    description: 'GitHub personal access or OAuth token',
    icon: '🐙',
  },
  {
    id: 'github_classic_token',
    label: 'GitHub Classic Token',
    category: 'VCS Tokens',
    severity: 'critical',
    pattern: /[a-zA-Z0-9_-]*github[a-zA-Z0-9_-]*\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    description: 'GitHub classic personal access token (hex 40)',
    icon: '🐙',
  },
  // Stripe
  {
    id: 'stripe_secret',
    label: 'Stripe Secret Key',
    category: 'Payment Keys',
    severity: 'critical',
    pattern: /sk_live_[0-9A-Za-z]{24,}/g,
    description: 'Stripe live secret API key',
    icon: '💳',
  },
  {
    id: 'stripe_restricted',
    label: 'Stripe Restricted Key',
    category: 'Payment Keys',
    severity: 'high',
    pattern: /rk_live_[0-9A-Za-z]{24,}/g,
    description: 'Stripe restricted API key',
    icon: '💳',
  },
  // Slack
  {
    id: 'slack_token',
    label: 'Slack Token',
    category: 'Messaging Tokens',
    severity: 'high',
    pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/g,
    description: 'Slack Bot/App/User/Workspace token',
    icon: '💬',
  },
  {
    id: 'slack_webhook',
    label: 'Slack Webhook URL',
    category: 'Messaging Tokens',
    severity: 'medium',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    description: 'Slack Incoming Webhook URL',
    icon: '💬',
  },
  // RSA / SSH Private Keys
  {
    id: 'rsa_private_key',
    label: 'RSA Private Key',
    category: 'Cryptographic Keys',
    severity: 'critical',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    description: 'RSA or PKCS8 private key block',
    icon: '🔑',
  },
  {
    id: 'ssh_private_key',
    label: 'SSH Private Key (OpenSSH)',
    category: 'Cryptographic Keys',
    severity: 'critical',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    description: 'OpenSSH private key block',
    icon: '🔑',
  },
  {
    id: 'ec_private_key',
    label: 'EC Private Key',
    category: 'Cryptographic Keys',
    severity: 'critical',
    pattern: /-----BEGIN EC PRIVATE KEY-----/g,
    description: 'Elliptic Curve private key block',
    icon: '🔑',
  },
  {
    id: 'dsa_private_key',
    label: 'DSA Private Key',
    category: 'Cryptographic Keys',
    severity: 'critical',
    pattern: /-----BEGIN DSA PRIVATE KEY-----/g,
    description: 'DSA private key block',
    icon: '🔑',
  },
  // TLS/SSL Certificates
  {
    id: 'certificate',
    label: 'TLS/SSL Certificate',
    category: 'Certificates',
    severity: 'medium',
    pattern: /-----BEGIN CERTIFICATE-----/g,
    description: 'X.509 TLS/SSL certificate block',
    icon: '📜',
  },
  {
    id: 'certificate_request',
    label: 'Certificate Signing Request',
    category: 'Certificates',
    severity: 'low',
    pattern: /-----BEGIN CERTIFICATE REQUEST-----/g,
    description: 'X.509 certificate signing request',
    icon: '📄',
  },
  {
    id: 'pkcs12',
    label: 'PKCS#12 / PFX Certificate',
    category: 'Certificates',
    severity: 'critical',
    pattern: /-----BEGIN PKCS12-----/g,
    description: 'PKCS#12 bundle with private key + certificate',
    icon: '🔐',
  },
  // Database Credentials
  {
    id: 'db_password',
    label: 'Database Password',
    category: 'Database Credentials',
    severity: 'high',
    pattern: /(?:db_password|database_password|DB_PASSWORD|DATABASE_PASSWORD|mysql_password|MYSQL_PASSWORD|postgres_password|POSTGRES_PASSWORD|PGPASSWORD)\s*[=:]\s*["']?([^\s"';<>{}\[\]]{6,})["']?/gi,
    description: 'Database password in environment variable or config',
    icon: '🗃️',
  },
  {
    id: 'db_connection_string',
    label: 'Database Connection String',
    category: 'Database Credentials',
    severity: 'critical',
    pattern: /(?:mongodb(?:\+srv)?|mysql|postgresql|postgres|mssql|sqlserver):\/\/[^:]+:[^@]+@[^\s"']+/gi,
    description: 'Database URI with embedded credentials',
    icon: '🗃️',
  },
  // Generic Passwords
  {
    id: 'generic_password',
    label: 'Generic Password',
    category: 'Passwords',
    severity: 'medium',
    pattern: /(?:^|[^a-z])(?:password|passwd|pwd|secret|pass)\s*[=:]\s*["']([^"'\s]{6,})["']/gim,
    description: 'Generic password assignment in code or config',
    icon: '🔒',
  },
  {
    id: 'generic_secret',
    label: 'Generic Secret / Token',
    category: 'Passwords',
    severity: 'medium',
    pattern: /(?:secret_key|SECRET_KEY|app_secret|APP_SECRET|client_secret|CLIENT_SECRET|auth_token|AUTH_TOKEN)\s*[=:]\s*["']([^"'\s]{8,})["']/gim,
    description: 'Generic secret key or token assignment',
    icon: '🔒',
  },
  // JWT
  {
    id: 'jwt_token',
    label: 'JWT Token',
    category: 'Auth Tokens',
    severity: 'high',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    description: 'JSON Web Token (JWT)',
    icon: '🎫',
  },
  // Twilio
  {
    id: 'twilio_sid',
    label: 'Twilio Account SID',
    category: 'Messaging Tokens',
    severity: 'high',
    pattern: /AC[a-z0-9]{32}/g,
    description: 'Twilio Account SID',
    icon: '📱',
  },
  {
    id: 'twilio_token',
    label: 'Twilio Auth Token',
    category: 'Messaging Tokens',
    severity: 'critical',
    pattern: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["']?([a-z0-9]{32})["']?/gi,
    description: 'Twilio authentication token',
    icon: '📱',
  },
  // SendGrid
  {
    id: 'sendgrid_key',
    label: 'SendGrid API Key',
    category: 'Email Service Keys',
    severity: 'high',
    pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
    description: 'SendGrid API key',
    icon: '📧',
  },
  // Azure
  {
    id: 'azure_storage_key',
    label: 'Azure Storage Account Key',
    category: 'Cloud Credentials',
    severity: 'critical',
    pattern: /AccountKey=[A-Za-z0-9+/]{86}==/g,
    description: 'Azure Storage Account access key',
    icon: '🔵',
  },
  // Heroku
  {
    id: 'heroku_api_key',
    label: 'Heroku API Key',
    category: 'Cloud Credentials',
    severity: 'high',
    pattern: /[hH]eroku[a-zA-Z0-9_\-]*\s*[=:]\s*["']?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["']?/g,
    description: 'Heroku platform API key (UUID format)',
    icon: '🟣',
  },
  // NPM token
  {
    id: 'npm_token',
    label: 'NPM Access Token',
    category: 'Package Registry Tokens',
    severity: 'high',
    pattern: /npm_[A-Za-z0-9]{36,}/g,
    description: 'NPM registry access token',
    icon: '📦',
  },
  // Discord
  {
    id: 'discord_token',
    label: 'Discord Bot Token',
    category: 'Messaging Tokens',
    severity: 'high',
    pattern: /[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27,}/g,
    description: 'Discord bot authentication token',
    icon: '🎮',
  },
  // Telegram
  {
    id: 'telegram_token',
    label: 'Telegram Bot Token',
    category: 'Messaging Tokens',
    severity: 'high',
    pattern: /\d{8,10}:[A-Za-z0-9_\-]{35}/g,
    description: 'Telegram bot API token',
    icon: '✈️',
  },
  // Firebase
  {
    id: 'firebase_key',
    label: 'Firebase API Key',
    category: 'Cloud Credentials',
    severity: 'high',
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    description: 'Firebase Cloud Messaging server key',
    icon: '🔥',
  },
  // Private key password / passphrase
  {
    id: 'private_key_passphrase',
    label: 'Private Key Passphrase',
    category: 'Cryptographic Keys',
    severity: 'high',
    pattern: /(?:key_passphrase|KEY_PASSPHRASE|private_key_password|PRIVATE_KEY_PASSWORD)\s*[=:]\s*["']([^"'\s]{6,})["']/gi,
    description: 'Passphrase protecting a private key file',
    icon: '🗝️',
  },
]

// ─── Pre-compiled patterns (compiled ONCE at startup, not per call) ──────────
const COMPILED_PATTERNS = SECRET_PATTERNS.map(def => ({
  ...def,
  compiled: new RegExp(def.pattern.source, def.pattern.flags.replace('g', '') + 'g'),
}))

// Shannon entropy — used to filter low-entropy false positives
function entropy(s: string): number {
  const freq: Record<string, number> = {}
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1
  let h = 0
  const len = s.length
  for (const f of Object.values(freq)) {
    const p = f / len
    h -= p * Math.log2(p)
  }
  return h
}

// ─── Helper: extract snippets ────────────────────────────────────────────────
interface Finding {
  patternId: string
  label: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  icon: string
  description: string
  file: string
  line: number
  snippet: string
  context: string   // surrounding lines for context
  match: string
  entropy: number
}

function scanText(content: string, filename: string): Finding[] {
  if (!content || content.length === 0) return []

  const findings: Finding[] = []
  // Pre-build line offset index for O(1) line lookup
  const lineOffsets: number[] = [0]
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') lineOffsets.push(i + 1)
  }
  const lines = content.split('\n')
  const totalLines = lines.length

  // Dedup key: patternId + file + line (avoid duplicate matches on same line)
  const seen = new Set<string>()

  for (const def of COMPILED_PATTERNS) {
    // Reset regex lastIndex for global reuse
    const regex = new RegExp(def.compiled.source, def.compiled.flags)
    let match: RegExpExecArray | null

    while ((match = regex.exec(content)) !== null) {
      // Binary search for line number using offset index
      let lo = 0, hi = lineOffsets.length - 1
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1
        if (lineOffsets[mid] <= match.index) lo = mid
        else hi = mid - 1
      }
      const lineNum = lo + 1
      const lineText = lines[lo] ?? ''

      const matchedValue = (match[1] ?? match[0]).substring(0, 100)

      // Dedup same pattern on same line
      const dedupKey = `${def.id}|${filename}|${lineNum}`
      if (seen.has(dedupKey)) continue
      seen.add(dedupKey)

      // Entropy filter: skip generic/password patterns if value looks like a placeholder
      const matchEntropy = entropy(matchedValue)
      if ((def.id === 'generic_password' || def.id === 'generic_secret') && matchEntropy < 2.5) continue
      // Skip very short matches that look like variable names
      if (matchedValue.length < 6 && def.severity !== 'critical') continue

      // Build multi-line context (1 line before + current + 1 after)
      const ctxStart = Math.max(0, lineNum - 2)
      const ctxEnd   = Math.min(totalLines - 1, lineNum)
      const contextLines = lines.slice(ctxStart, ctxEnd + 1)
        .map((l, i) => `${ctxStart + i + 1}│ ${l.substring(0, 120)}`)
        .join('\n')

      findings.push({
        patternId: def.id,
        label: def.label,
        category: def.category,
        severity: def.severity,
        icon: def.icon,
        description: def.description,
        file: filename,
        line: lineNum,
        snippet: lineText.trim().substring(0, 140),
        context: contextLines,
        match: matchedValue,
        entropy: Math.round(matchEntropy * 100) / 100,
      })

      // Prevent runaway match on zero-length patterns
      if (match[0].length === 0) regex.lastIndex++
    }
  }

  return findings
}

// ─── GitHub API helpers ───────────────────────────────────────────────────────
function parseGithubUrl(url: string): { owner: string; repo: string } | null {
  const m = url.match(/github\.com[/:]([^/]+)\/([^/.]+?)(?:\.git)?(?:\/.*)?$/)
  if (!m) return null
  return { owner: m[1], repo: m[2] }
}

// Prioritised high-value file patterns (scanned first, so critical findings surface fast)
const HIGH_VALUE_PATHS = /(\.(env|pem|key|p12|pfx|jks|cer|crt)|\.env\.|id_rsa|id_dsa|id_ecdsa|id_ed25519|credentials|secrets|\.npmrc|\.netrc|htpasswd|\.gitcredentials|database\.yml|database\.yaml|secrets\.yml|config\.yml|application\.properties|settings\.py|wp-config\.php|LocalSettings\.php|Dockerfile|\.travis\.yml|circle\.ci|\.github\/workflows)/i

const SCAN_EXTENSIONS = /\.(env|json|yaml|yml|toml|ini|cfg|conf|config|properties|xml|sh|bash|zsh|py|js|ts|jsx|tsx|rb|go|php|java|cs|cpp|c|h|tf|tfvars|pem|key|crt|cer|p12|pfx|jks|txt|md|gradle|htpasswd|npmrc|netrc|gitcredentials)$/i
const SKIP_DIRS       = /^(node_modules|\.git|dist|build|vendor|\.next|\.nuxt|coverage|__pycache__|\.venv|venv|\.cache|\.parcel-cache|target|out|\.gradle|\.mvn)\//
const MAX_FILES       = 250
const MAX_COMMITS     = 100
const MAX_FILE_SIZE   = 150_000  // skip files > 150 KB (too large to be a secret file)

async function fetchGithubTree(owner: string, repo: string): Promise<{ path: string; url: string; size: number }[]> {
  // Fetch repo info + tree in PARALLEL for speed
  const GH_HEADERS = { 'User-Agent': 'GitSecretScanner/2.0', Accept: 'application/vnd.github.v3+json' }
  const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers: GH_HEADERS })
  if (!repoRes.ok) throw new Error(`GitHub API error: ${repoRes.status} ${repoRes.statusText}`)
  const repoData: any = await repoRes.json()
  const branch = repoData.default_branch ?? 'main'

  const treeRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
    { headers: GH_HEADERS }
  )
  if (!treeRes.ok) throw new Error(`GitHub tree API error: ${treeRes.status}`)
  const treeData: any = await treeRes.json()

  const files: { path: string; url: string; size: number }[] = []
  const highValue: { path: string; url: string; size: number }[] = []

  for (const item of treeData.tree ?? []) {
    if (item.type !== 'blob') continue
    if (SKIP_DIRS.test(item.path)) continue
    if (item.size > MAX_FILE_SIZE) continue
    if (!SCAN_EXTENSIONS.test(item.path)) continue
    const entry = { path: item.path, url: item.url, size: item.size ?? 0 }
    if (HIGH_VALUE_PATHS.test(item.path)) highValue.push(entry)
    else files.push(entry)
  }

  // High-value files first so critical findings appear quickly
  return [...highValue, ...files].slice(0, MAX_FILES)
}

// Fetch raw content directly — MUCH faster than blob API (no base64 encode/decode overhead)
async function fetchRawContent(owner: string, repo: string, branch: string, path: string): Promise<string> {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'GitSecretScanner/2.0' } })
    if (!res.ok) return ''
    const text = await res.text()
    // Detect binary content (many null bytes) and skip
    const sample = text.substring(0, 512)
    if ((sample.match(/\x00/g) ?? []).length > 10) return ''
    return text.substring(0, MAX_FILE_SIZE)
  } catch {
    return ''
  }
}

async function fetchCommitMessages(owner: string, repo: string): Promise<{ sha: string; msg: string }[]> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/commits?per_page=${MAX_COMMITS}`,
    { headers: { 'User-Agent': 'GitSecretScanner/2.0', Accept: 'application/vnd.github.v3+json' } }
  )
  if (!res.ok) return []
  const data: any = await res.json()
  return (data as any[]).map((c: any) => ({ sha: c.sha, msg: c.commit?.message ?? '' }))
}


// ─── API Routes ───────────────────────────────────────────────────────────────

// Scan GitHub URL
app.post('/api/scan/github', async (c) => {
  try {
    const body = await c.req.json()
    const { url } = body as { url: string }
    if (!url) return c.json({ error: 'URL is required' }, 400)

    const parsed = parseGithubUrl(url)
    if (!parsed) return c.json({ error: 'Invalid GitHub URL. Use: https://github.com/owner/repo' }, 400)

    const { owner, repo } = parsed
    const startTime = Date.now()

    // Fetch repo meta + tree simultaneously
    const GH_HEADERS = { 'User-Agent': 'GitSecretScanner/2.0', Accept: 'application/vnd.github.v3+json' }
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers: GH_HEADERS })
    if (!repoRes.ok) throw new Error(`GitHub API error: ${repoRes.status} ${repoRes.statusText}`)
    const repoData: any = await repoRes.json()
    const branch: string = repoData.default_branch ?? 'main'

    // Tree + commits fetched in parallel
    const [files, commits] = await Promise.all([
      fetchGithubTree(owner, repo),
      fetchCommitMessages(owner, repo),
    ])

    const allFindings: Finding[] = []
    const scannedFiles: string[] = []

    // Fetch raw file content in large parallel batches (20 concurrent)
    const BATCH = 20
    for (let i = 0; i < files.length; i += BATCH) {
      const batch = files.slice(i, i + BATCH)
      const results = await Promise.all(
        batch.map(async (f) => {
          const content = await fetchRawContent(owner, repo, branch, f.path)
          if (!content) return []
          scannedFiles.push(f.path)
          return scanText(content, f.path)
        })
      )
      results.forEach((r) => allFindings.push(...r))
    }

    // Scan commit messages in parallel (no network, pure regex)
    const commitFindings = commits.flatMap(cm =>
      scanText(cm.msg, `[commit:${cm.sha.substring(0, 7)}]`)
    )
    allFindings.push(...commitFindings)

    // Global dedup across all findings (same pattern + file + line)
    const globalSeen = new Set<string>()
    const deduped = allFindings.filter(f => {
      const k = `${f.patternId}|${f.file}|${f.line}`
      if (globalSeen.has(k)) return false
      globalSeen.add(k)
      return true
    })

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
    return c.json({
      success: true,
      meta: {
        repo: `${owner}/${repo}`,
        branch,
        scannedFiles: scannedFiles.length,
        totalFiles: files.length,
        totalFindings: deduped.length,
        commits: commits.length,
        elapsed,
        platform: 'github',
      },
      findings: deduped,
    })
  } catch (err: any) {
    return c.json({ error: err?.message ?? 'Unknown error' }, 500)
  }
})

// Scan pasted text / file content
app.post('/api/scan/text', async (c) => {
  try {
    const body = await c.req.json()
    const { content, filename } = body as { content: string; filename?: string }

    if (!content) return c.json({ error: 'Content is required' }, 400)

    const startTime = Date.now()
    const findings = scanText(content, filename ?? 'pasted-content')
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2)

    return c.json({
      success: true,
      meta: {
        scannedFiles: 1,
        totalFindings: findings.length,
        elapsed,
      },
      findings,
    })
  } catch (err: any) {
    return c.json({ error: err?.message ?? 'Unknown error' }, 500)
  }
})

// ─── ZIP Scan endpoint ────────────────────────────────────────────────────────
// Receives: { files: [{name, content}][] } — content is plain text
// Returns same shape as other scan endpoints
app.post('/api/scan/zip', async (c) => {
  try {
    const body = await c.req.json() as { files: { name: string; content: string }[] }
    if (!body?.files?.length) return c.json({ error: 'No files provided' }, 400)

    const MAX_FILES  = 300
    const MAX_BYTES  = 500_000          // skip files > 500 KB
    const startTime  = Date.now()
    const allFindings: Finding[] = []
    const scannedFiles: string[] = []
    const skipped: string[] = []

    const SCAN_EXT = /\.(env|json|yaml|yml|toml|ini|cfg|conf|config|properties|xml|sh|bash|zsh|py|js|ts|jsx|tsx|rb|go|php|java|cs|cpp|c|h|tf|tfvars|pem|key|crt|cer|p12|pfx|jks|txt|md|gradle|Makefile|Dockerfile|htpasswd|npmrc|netrc|gitcredentials)$/i
    const SKIP_PATH = /^(node_modules|\.git|dist|build|vendor|\.next|__pycache__|\.venv|venv)\//

    let processed = 0
    for (const file of body.files) {
      if (processed >= MAX_FILES) { skipped.push(file.name); continue }
      if (SKIP_PATH.test(file.name)) { skipped.push(file.name); continue }
      if (!SCAN_EXT.test(file.name) && !/\.(env)$/i.test(file.name)) {
        // also allow files with no extension that look like dotfiles
        if (!file.name.match(/^\.?(env|npmrc|netrc|gitconfig|htpasswd|bashrc|zshrc|profile|credentials|secrets)$/i)) {
          skipped.push(file.name); continue
        }
      }
      if (file.content.length > MAX_BYTES) { skipped.push(file.name + ' (too large)'); continue }

      const findings = scanText(file.content, file.name)
      allFindings.push(...findings)
      scannedFiles.push(file.name)
      processed++
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2)
    return c.json({
      success: true,
      meta: {
        scannedFiles: scannedFiles.length,
        skippedFiles: skipped.length,
        totalFiles: body.files.length,
        totalFindings: allFindings.length,
        elapsed,
        platform: 'zip',
      },
      findings: allFindings,
      scannedList: scannedFiles,
      skippedList: skipped,
    })
  } catch (err: any) {
    return c.json({ error: err?.message ?? 'Unknown error' }, 500)
  }
})

// List pattern definitions
app.get('/api/patterns', (c) => {
  return c.json(
    SECRET_PATTERNS.map((p) => ({
      id: p.id,
      label: p.label,
      category: p.category,
      severity: p.severity,
      icon: p.icon,
      description: p.description,
    }))
  )
})

// ─── Telegram Notification Helpers ───────────────────────────────────────────
async function sendTelegram(botToken: string, chatId: string, text: string): Promise<{ ok: boolean; description?: string }> {
  try {
    const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    })
    const data: any = await res.json()
    return { ok: data.ok === true, description: data.description }
  } catch (e: any) {
    return { ok: false, description: e?.message ?? 'Network error' }
  }
}

function buildTelegramReport(findings: Finding[], meta: Record<string, any>): string {
  const sevEmoji: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' }
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>
  findings.forEach(f => counts[f.severity] = (counts[f.severity] ?? 0) + 1)

  const repoLabel = meta.repo ? `\n📦 <b>Target:</b> ${meta.repo}` : ''
  const branchLabel = meta.branch ? ` (${meta.branch})` : ''
  const platformLabel = meta.platform ? ` [${meta.platform}]` : ''

  let msg = `🔍 <b>GitLeakHunter Scan Report</b>${repoLabel}${branchLabel}${platformLabel}\n`
  msg += `📁 Files scanned: <b>${meta.scannedFiles ?? 1}</b>\n`
  if (meta.commits) msg += `💾 Commits analyzed: <b>${meta.commits}</b>\n`
  msg += `⏱ Elapsed: <b>${meta.elapsed}s</b>\n`
  msg += `\n<b>📊 Summary:</b>\n`
  msg += `${sevEmoji.critical} Critical: <b>${counts.critical}</b>   ${sevEmoji.high} High: <b>${counts.high}</b>   ${sevEmoji.medium} Medium: <b>${counts.medium}</b>   ${sevEmoji.low} Low: <b>${counts.low}</b>\n`
  msg += `\n<b>Total findings: ${findings.length}</b>\n`

  if (findings.length === 0) {
    msg += `\n✅ No secrets detected. Repository looks clean!`
    return msg
  }

  // Group by severity, show top 15 findings max
  const sevOrder = ['critical', 'high', 'medium', 'low']
  const sorted = [...findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))
  const shown = sorted.slice(0, 15)

  msg += `\n<b>🚨 Findings (top ${shown.length}):</b>\n`
  for (const f of shown) {
    const redacted = f.match && f.match.length > 8
      ? f.match.substring(0, 4) + '••••' + f.match.substring(f.match.length - 4)
      : '***'
    msg += `\n${sevEmoji[f.severity]} <b>${f.label}</b>\n`
    msg += `   📄 <code>${f.file}</code> · line ${f.line}\n`
    msg += `   🔑 <code>${redacted}</code>\n`
  }

  if (findings.length > 15) {
    msg += `\n... and <b>${findings.length - 15}</b> more findings (export JSON for full report).`
  }

  return msg
}

// Test Telegram connection
app.post('/api/telegram/test', async (c) => {
  try {
    const { botToken, chatId } = await c.req.json() as { botToken: string; chatId: string }
    if (!botToken || !chatId) return c.json({ ok: false, error: 'botToken and chatId are required' }, 400)

    const text = `✅ <b>GitLeakHunter</b> — Telegram connection test successful!\n\nYour notifications are configured correctly. Scan results will be sent to this chat.`
    const result = await sendTelegram(botToken, chatId, text)
    if (!result.ok) return c.json({ ok: false, error: result.description ?? 'Telegram API error' })
    return c.json({ ok: true, message: 'Test message sent successfully!' })
  } catch (e: any) {
    return c.json({ ok: false, error: e?.message ?? 'Unknown error' }, 500)
  }
})

// Send scan result to Telegram
app.post('/api/telegram/notify', async (c) => {
  try {
    const { botToken, chatId, findings, meta } = await c.req.json() as {
      botToken: string
      chatId: string
      findings: Finding[]
      meta: Record<string, any>
    }
    if (!botToken || !chatId) return c.json({ ok: false, error: 'botToken and chatId are required' }, 400)
    if (!Array.isArray(findings)) return c.json({ ok: false, error: 'findings array required' }, 400)

    const text = buildTelegramReport(findings, meta ?? {})
    const result = await sendTelegram(botToken, chatId, text)
    if (!result.ok) return c.json({ ok: false, error: result.description ?? 'Telegram API error' })
    return c.json({ ok: true, message: `Report sent (${findings.length} findings)` })
  } catch (e: any) {
    return c.json({ ok: false, error: e?.message ?? 'Unknown error' }, 500)
  }
})

// Favicon
app.get('/favicon.ico', (c) => {
  // Simple SVG shield favicon as data
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🔍</text></svg>`
  return new Response(svg, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } })
})

// ─── Frontend ─────────────────────────────────────────────────────────────────
app.get('/', (c) => {
  return c.html(/* html */ `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>GitLeakHunter — Git Secret Scanner</title>
<link rel="icon" href="/favicon.ico" type="image/svg+xml"/>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css"/>
<script src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
  *{box-sizing:border-box;}
  body{font-family:'Inter',sans-serif;background:#0d1117;}
  .mono{font-family:'JetBrains Mono',monospace;}
  .glass{background:rgba(22,27,34,0.85);backdrop-filter:blur(12px);border:1px solid rgba(48,54,61,0.8);}
  .glow-green{box-shadow:0 0 20px rgba(46,160,67,0.3);}
  .glow-red{box-shadow:0 0 20px rgba(248,81,73,0.3);}
  .glow-yellow{box-shadow:0 0 20px rgba(210,153,34,0.3);}
  .glow-blue{box-shadow:0 0 20px rgba(88,166,255,0.3);}
  .terminal-bg{background:#0d1117;border:1px solid #30363d;}
  .scan-line{animation:scanline 2s linear infinite;}
  @keyframes scanline{0%{transform:translateY(-100%);}100%{transform:translateY(100vh);}}
  .pulse-dot{animation:pulse-dot 1.5s ease-in-out infinite;}
  @keyframes pulse-dot{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.5;transform:scale(0.8);}}
  .finding-card{transition:all 0.2s ease;border-left:4px solid transparent;}
  .finding-card:hover{transform:translateX(4px);}
  .severity-critical{border-left-color:#f85149!important;background:rgba(248,81,73,0.05);}
  .severity-high{border-left-color:#f0883e!important;background:rgba(240,136,62,0.05);}
  .severity-medium{border-left-color:#d2a520!important;background:rgba(210,165,32,0.05);}
  .severity-low{border-left-color:#3fb950!important;background:rgba(63,185,80,0.05);}
  .tab-btn.active{background:rgba(88,166,255,0.15);border-color:#58a6ff;color:#58a6ff;}
  .copy-btn:active{transform:scale(0.95);}
  .copy-btn.copied{color:#4ade80 !important;border-color:rgba(74,222,128,0.4) !important;}
  .copy-group{display:flex;align-items:center;gap:0.375rem;flex-wrap:wrap;}
  .progress-bar{transition:width 0.3s ease;}
  .hero-gradient{background:linear-gradient(135deg,rgba(13,17,23,1) 0%,rgba(22,27,34,1) 50%,rgba(13,17,23,1) 100%);}
  .badge-critical{background:rgba(248,81,73,0.15);color:#f85149;border:1px solid rgba(248,81,73,0.3);}
  .badge-high{background:rgba(240,136,62,0.15);color:#f0883e;border:1px solid rgba(240,136,62,0.3);}
  .badge-medium{background:rgba(210,165,32,0.15);color:#d2a520;border:1px solid rgba(210,165,32,0.3);}
  .badge-low{background:rgba(63,185,80,0.15);color:#3fb950;border:1px solid rgba(63,185,80,0.3);}
  .spinner{animation:spin 1s linear infinite;}
  @keyframes spin{from{transform:rotate(0deg);}to{transform:rotate(360deg);}}
  ::-webkit-scrollbar{width:6px;height:6px;}
  ::-webkit-scrollbar-track{background:#0d1117;}
  ::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px;}
  ::-webkit-scrollbar-thumb:hover{background:#484f58;}
  .matrix-bg{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;opacity:0.03;z-index:0;}
  .content{position:relative;z-index:1;}
  .highlight-match{background:rgba(248,81,73,0.25);color:#ff7b72;padding:1px 3px;border-radius:2px;font-weight:600;}
  #toast{transition:all 0.3s ease;}
  .category-chip{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:500;}
  /* ZIP Upload */
  .drop-zone{border:2px dashed #30363d;transition:all 0.25s ease;}
  .drop-zone.drag-over{border-color:#8b5cf6;background:rgba(139,92,246,0.07);box-shadow:0 0 24px rgba(139,92,246,0.15);}
  .drop-zone:hover{border-color:#484f58;}
  .file-tree-item{transition:background 0.15s;}
  .file-tree-item:hover{background:rgba(255,255,255,0.04);}
  .zip-progress-fill{transition:width 0.2s ease;}
  @keyframes file-pop{0%{opacity:0;transform:translateY(4px);}100%{opacity:1;transform:translateY(0);}}
  .file-pop{animation:file-pop 0.2s ease forwards;}
  /* Telegram */
  .tg-panel{background:rgba(13,17,23,0.97);border:1px solid rgba(41,182,246,0.25);box-shadow:0 0 40px rgba(41,182,246,0.08);}
  .tg-input{background:#0d1117;border:1px solid #30363d;color:#fff;transition:border-color 0.2s;}
  .tg-input:focus{outline:none;border-color:#29b6f6;box-shadow:0 0 0 2px rgba(41,182,246,0.15);}
  .tg-toggle{width:44px;height:24px;background:#30363d;border-radius:12px;position:relative;cursor:pointer;transition:background 0.2s;}
  .tg-toggle.on{background:#29b6f6;}
  .tg-toggle::after{content:'';position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#fff;transition:transform 0.2s;}
  .tg-toggle.on::after{transform:translateX(20px);}
  @keyframes tg-slide-in{from{opacity:0;transform:translateY(-8px);}to{opacity:1;transform:translateY(0);}}
  .tg-slide{animation:tg-slide-in 0.2s ease;}
  /* Folder / Android Scan */
  .folder-drop{border:2px dashed #30363d;transition:all 0.25s ease;}
  .folder-drop.drag-over{border-color:#22c55e;background:rgba(34,197,94,0.06);box-shadow:0 0 20px rgba(34,197,94,0.12);}
  .folder-drop:hover{border-color:#484f58;}
  .android-profile{border:1px solid #30363d;cursor:pointer;transition:all 0.2s;}
  .android-profile:hover{border-color:#22c55e;background:rgba(34,197,94,0.06);}
  .android-profile.selected{border-color:#22c55e;background:rgba(34,197,94,0.1);box-shadow:0 0 12px rgba(34,197,94,0.15);}
  .folder-file-item{transition:background 0.15s;}
  .folder-file-item:hover{background:rgba(255,255,255,0.03);}
  @keyframes count-up{from{opacity:0;transform:scale(0.8);}to{opacity:1;transform:scale(1);}}
  .count-up{animation:count-up 0.3s ease;}
</style>
</head>
<body class="min-h-screen text-gray-100">

<!-- Matrix canvas background -->
<canvas id="matrix" class="matrix-bg"></canvas>

<div class="content">

<!-- Toast notification -->
<div id="toast" class="fixed top-4 right-4 z-50 hidden px-4 py-2 rounded-lg text-sm font-medium glass border border-green-500/30 text-green-400"></div>

<!-- Header -->
<header class="border-b border-[#30363d] glass sticky top-0 z-40">
  <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <div class="relative">
        <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-red-600 to-orange-500 flex items-center justify-center shadow-lg">
          <i class="fas fa-shield-halved text-white text-sm"></i>
        </div>
        <div class="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full pulse-dot border-2 border-[#0d1117]"></div>
      </div>
      <div>
        <h1 class="text-base font-bold text-white leading-none">GitLeakHunter</h1>
        <p class="text-xs text-gray-500 mt-0.5">Git Secret Scanner</p>
      </div>
    </div>
    <div class="flex items-center gap-4">
      <span class="text-xs text-gray-500 hidden sm:flex items-center gap-1.5">
        <span class="w-2 h-2 bg-green-500 rounded-full pulse-dot"></span>
        Scanner Online
      </span>
      <a href="#patterns-section" class="text-xs text-gray-400 hover:text-white transition-colors hidden sm:block">
        <i class="fas fa-list mr-1"></i>Pattern Library
      </a>
      <button id="tg-settings-btn" onclick="toggleTgPanel()" 
        class="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border border-[#30363d] text-gray-400 hover:text-[#29b6f6] hover:border-[#29b6f6]/40 transition-all">
        <i class="fab fa-telegram text-sm"></i>
        <span class="hidden sm:inline">Telegram</span>
        <span id="tg-dot" class="hidden w-2 h-2 bg-[#29b6f6] rounded-full pulse-dot"></span>
      </button>
    </div>
  </div>

  <!-- Telegram Settings Panel -->
  <div id="tg-panel" class="hidden tg-panel tg-slide border-t border-[#29b6f6]/20">
    <div class="max-w-7xl mx-auto px-4 py-4">
      <div class="flex flex-wrap items-start gap-6">
        <!-- Left: Title -->
        <div class="flex items-center gap-3 min-w-[180px]">
          <div class="w-9 h-9 rounded-xl bg-[#29b6f6]/10 border border-[#29b6f6]/20 flex items-center justify-center shrink-0">
            <i class="fab fa-telegram text-[#29b6f6] text-lg"></i>
          </div>
          <div>
            <p class="text-sm font-semibold text-white">Telegram Notify</p>
            <p class="text-xs text-gray-500">Send scan results to chat</p>
          </div>
        </div>
        <!-- Middle: Inputs -->
        <div class="flex flex-wrap gap-3 flex-1">
          <div class="flex flex-col gap-1 min-w-[200px] flex-1">
            <label class="text-xs text-gray-500 font-medium">Bot Token</label>
            <input id="tg-bot-token" type="password" placeholder="1234567890:ABCdefGHI..." 
              class="tg-input rounded-lg px-3 py-2 text-sm mono w-full"
              oninput="saveTgConfig()"/>
          </div>
          <div class="flex flex-col gap-1 min-w-[140px]">
            <label class="text-xs text-gray-500 font-medium">Chat ID</label>
            <input id="tg-chat-id" type="text" placeholder="-1001234567890" 
              class="tg-input rounded-lg px-3 py-2 text-sm mono w-full"
              oninput="saveTgConfig()"/>
          </div>
        </div>
        <!-- Right: Controls -->
        <div class="flex flex-wrap items-center gap-3">
          <!-- Auto-notify toggle -->
          <div class="flex items-center gap-2">
            <span class="text-xs text-gray-400">Auto-notify</span>
            <div id="tg-auto-toggle" class="tg-toggle" onclick="toggleAutoNotify()" title="Auto-send after every scan"></div>
          </div>
          <!-- Test button -->
          <button id="tg-test-btn" onclick="testTelegram()"
            class="flex items-center gap-1.5 px-4 py-2 bg-[#29b6f6]/10 hover:bg-[#29b6f6]/20 border border-[#29b6f6]/30 hover:border-[#29b6f6]/60 text-[#29b6f6] text-xs font-medium rounded-lg transition-all">
            <i class="fas fa-paper-plane"></i> Test
          </button>
          <!-- Send now button (only visible when there are results) -->
          <button id="tg-send-now-btn" onclick="sendResultsToTelegram()" 
            class="hidden items-center gap-1.5 px-4 py-2 bg-[#29b6f6] hover:bg-[#0ea5e9] text-white text-xs font-semibold rounded-lg transition-all shadow-lg hover:shadow-[#29b6f6]/25">
            <i class="fas fa-share"></i> Send Results
          </button>
        </div>
      </div>
      <!-- Status message -->
      <div id="tg-status" class="hidden mt-3 text-xs rounded-lg px-3 py-2"></div>
      <!-- Help hint -->
      <p class="mt-2 text-xs text-gray-700">
        <i class="fas fa-circle-info mr-1"></i>
        Create a bot via <a href="https://t.me/BotFather" target="_blank" class="text-[#29b6f6]/60 hover:text-[#29b6f6]">@BotFather</a> · 
        Get Chat ID via <a href="https://t.me/userinfobot" target="_blank" class="text-[#29b6f6]/60 hover:text-[#29b6f6]">@userinfobot</a> or add 
        <a href="https://t.me/getmyid_bot" target="_blank" class="text-[#29b6f6]/60 hover:text-[#29b6f6]">@getmyid_bot</a> to your group · 
        Config saved in localStorage
      </p>
    </div>
  </div>
</header>

<!-- Hero Section -->
<section class="hero-gradient py-14 px-4 border-b border-[#30363d] relative overflow-hidden">
  <div class="absolute inset-0 opacity-5">
    <div class="absolute top-0 left-1/4 w-96 h-96 bg-red-500 rounded-full filter blur-3xl"></div>
    <div class="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500 rounded-full filter blur-3xl"></div>
  </div>
  <div class="max-w-4xl mx-auto text-center relative z-10">
    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-medium mb-6">
      <i class="fas fa-radiation text-xs"></i>
      Deep Scan Mode — Full Commit History Analysis
    </div>
    <h2 class="text-4xl sm:text-5xl font-black text-white mb-4 leading-tight">
      Hunt Secrets in<br/>
      <span class="bg-gradient-to-r from-red-400 via-orange-400 to-yellow-400 bg-clip-text text-transparent">Git Repositories</span>
    </h2>
    <p class="text-gray-400 text-lg max-w-2xl mx-auto mb-8">
      Scan GitHub repositories for leaked API keys, passwords, private keys, certificates, 
      and database credentials — before attackers find them.
    </p>
    <!-- Stats row -->
    <div class="flex flex-wrap justify-center gap-6 text-center">
      <div class="glass px-5 py-3 rounded-xl">
        <div class="text-2xl font-black text-white" id="stat-patterns">35</div>
        <div class="text-xs text-gray-500 mt-0.5">Detection Patterns</div>
      </div>
      <div class="glass px-5 py-3 rounded-xl">
        <div class="text-2xl font-black text-white">10+</div>
        <div class="text-xs text-gray-500 mt-0.5">Secret Categories</div>
      </div>
      <div class="glass px-5 py-3 rounded-xl">
        <div class="text-2xl font-black text-white">100%</div>
        <div class="text-xs text-gray-500 mt-0.5">History Traversal</div>
      </div>
      <div class="glass px-5 py-3 rounded-xl">
        <div class="text-2xl font-black text-white">Free</div>
        <div class="text-xs text-gray-500 mt-0.5">No API Key Needed</div>
      </div>
    </div>
  </div>
</section>

<!-- Main Scanner -->
<main class="max-w-7xl mx-auto px-4 py-8">

  <!-- Scan Input Tabs -->
  <div class="glass rounded-2xl p-6 mb-8">
    <div class="flex flex-wrap gap-2 mb-6">
      <button id="tab-github" class="tab-btn active flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-[#30363d] transition-all" onclick="switchTab('github')">
        <i class="fab fa-github"></i> GitHub URL
      </button>
      <button id="tab-zip" class="tab-btn flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-[#30363d] text-gray-400 hover:text-white transition-all" onclick="switchTab('zip')">
        <i class="fas fa-file-zipper"></i> ZIP Upload
      </button>
      <button id="tab-folder" class="tab-btn flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-[#30363d] text-gray-400 hover:text-white transition-all" onclick="switchTab('folder')">
        <i class="fas fa-folder-open"></i> Folder Scan
      </button>
      <button id="tab-android" class="tab-btn flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-[#30363d] text-gray-400 hover:text-white transition-all" onclick="switchTab('android')">
        <i class="fab fa-android"></i> Android Scan
      </button>
      <button id="tab-text" class="tab-btn flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-[#30363d] text-gray-400 hover:text-white transition-all" onclick="switchTab('text')">
        <i class="fas fa-code"></i> Paste Code
      </button>
    </div>

    <!-- GitHub Tab -->
    <div id="panel-github">
      <label class="block text-sm font-medium text-gray-300 mb-2">
        <i class="fab fa-github mr-2 text-gray-400"></i>GitHub Repository URL
      </label>
      <div class="flex gap-3">
        <div class="flex-1 relative">
          <span class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">
            <i class="fas fa-link text-sm"></i>
          </span>
          <input id="github-url" type="url" 
            placeholder="https://github.com/owner/repository"
            class="w-full bg-[#0d1117] border border-[#30363d] rounded-xl pl-9 pr-4 py-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all mono"
          />
        </div>
        <button id="scan-github-btn" onclick="startGithubScan()" 
          class="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg hover:shadow-red-500/25">
          <i class="fas fa-search"></i> Scan
        </button>
      </div>
      <p class="text-xs text-gray-600 mt-2">
        <i class="fas fa-info-circle mr-1"></i>
        Scans up to 250 source files + 100 recent commits. High-value files (env, keys, certs) prioritised. No auth required for public repos.
      </p>
      <!-- Example repos -->
      <div class="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span class="text-xs text-gray-500 font-medium flex items-center gap-1">
          <i class="fas fa-flask text-gray-600"></i>Try example:
        </span>
        <button onclick="setExample('https://github.com/trufflesecurity/test_keys')" class="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 bg-blue-500/5 hover:bg-blue-500/10 border border-blue-500/20 hover:border-blue-500/40 px-2.5 py-1 rounded-lg transition-all">
          <i class="fab fa-github text-xs"></i>trufflesecurity/test_keys
        </button>
        <button onclick="setExample('https://github.com/dxa4481/truffleHog')" class="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 bg-blue-500/5 hover:bg-blue-500/10 border border-blue-500/20 hover:border-blue-500/40 px-2.5 py-1 rounded-lg transition-all">
          <i class="fab fa-github text-xs"></i>dxa4481/truffleHog
        </button>
        <button onclick="setExample('https://github.com/torvalds/linux')" class="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 bg-blue-500/5 hover:bg-blue-500/10 border border-blue-500/20 hover:border-blue-500/40 px-2.5 py-1 rounded-lg transition-all">
          <i class="fab fa-github text-xs"></i>torvalds/linux
        </button>
        <button onclick="setExample('https://github.com/nicowillis/gitrob-test')" class="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 bg-blue-500/5 hover:bg-blue-500/10 border border-blue-500/20 hover:border-blue-500/40 px-2.5 py-1 rounded-lg transition-all">
          <i class="fab fa-github text-xs"></i>nicowillis/gitrob-test
        </button>
        <button onclick="loadDemoText()" class="inline-flex items-center gap-1.5 text-xs text-orange-400 hover:text-orange-300 bg-orange-500/5 hover:bg-orange-500/10 border border-orange-500/20 hover:border-orange-500/40 px-2.5 py-1 rounded-lg transition-all">
          <i class="fas fa-vial text-xs"></i>Demo Secrets (offline)
        </button>
      </div>
    </div>

    <!-- ZIP Upload Tab -->
    <div id="panel-zip" class="hidden">
      <label class="block text-sm font-medium text-gray-300 mb-3">
        <i class="fas fa-file-zipper mr-2 text-violet-400"></i>Upload ZIP / Archive File
      </label>

      <!-- Drop Zone -->
      <div id="zip-drop-zone"
        class="drop-zone rounded-2xl px-6 py-10 text-center cursor-pointer relative"
        onclick="document.getElementById('zip-file-input').click()"
        ondragover="handleDragOver(event)"
        ondragleave="handleDragLeave(event)"
        ondrop="handleDrop(event)">
        <input id="zip-file-input" type="file" class="hidden" accept=".zip,.jar,.war,.ear,.apk,.ipa" onchange="handleZipFile(event)"/>
        <div id="zip-drop-idle">
          <div class="w-16 h-16 rounded-2xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center mx-auto mb-4">
            <i class="fas fa-file-zipper text-violet-400 text-3xl"></i>
          </div>
          <p class="text-white font-semibold mb-1">Drop ZIP file here or click to browse</p>
          <p class="text-gray-500 text-sm mb-3">Supports .zip, .jar, .war, .ear, .apk, .ipa</p>
          <div class="flex flex-wrap justify-center gap-3 text-xs text-gray-600">
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> Max 200 MB</span>
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> Up to 300 files scanned</span>
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> All secret patterns</span>
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> Entire directory tree</span>
          </div>
        </div>
        <!-- File loaded state (hidden initially) -->
        <div id="zip-drop-loaded" class="hidden">
          <div class="w-14 h-14 rounded-xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-3">
            <i class="fas fa-circle-check text-green-400 text-2xl"></i>
          </div>
          <p class="text-white font-semibold mb-1" id="zip-filename-label">file.zip</p>
          <p class="text-gray-500 text-sm" id="zip-fileinfo-label">0 files inside</p>
          <button onclick="resetZip(event)" class="mt-3 text-xs text-gray-500 hover:text-red-400 transition-colors">
            <i class="fas fa-xmark mr-1"></i>Remove file
          </button>
        </div>
      </div>

      <!-- Extraction progress bar (hidden) -->
      <div id="zip-extract-progress" class="hidden mt-4 glass rounded-xl p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm font-medium text-white flex items-center gap-2">
            <i class="fas fa-circle-notch spinner text-violet-400"></i>
            <span id="zip-extract-label">Extracting archive...</span>
          </span>
          <span class="text-xs text-gray-500 mono" id="zip-extract-pct">0%</span>
        </div>
        <div class="w-full bg-[#21262d] rounded-full h-2">
          <div id="zip-extract-fill" class="zip-progress-fill h-2 rounded-full bg-gradient-to-r from-violet-500 to-purple-500" style="width:0%"></div>
        </div>
        <div class="mt-2 text-xs text-gray-600 mono truncate" id="zip-extract-file">Reading...</div>
      </div>

      <!-- File tree preview (populated after extract) -->
      <div id="zip-tree-section" class="hidden mt-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-medium text-gray-400 uppercase tracking-wide flex items-center gap-1.5">
            <i class="fas fa-folder-tree text-violet-400"></i>Files to Scan
          </span>
          <div class="flex items-center gap-3">
            <span class="text-xs text-gray-600" id="zip-tree-counts"></span>
            <button id="scan-zip-btn" onclick="startZipScan()"
              class="flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg hover:shadow-violet-500/25">
              <i class="fas fa-shield-halved"></i> Scan for Secrets
            </button>
          </div>
        </div>
        <div id="zip-file-tree" class="terminal-bg rounded-xl p-3 max-h-52 overflow-y-auto text-xs mono space-y-0.5"></div>
        <div class="mt-2 flex flex-wrap gap-2 items-center">
          <span class="text-xs text-gray-600">Skipped (binary/vendor/build):</span>
          <span class="text-xs text-gray-500" id="zip-skipped-label">0 files</span>
        </div>
      </div>
    </div>

    <!-- Text/File Tab -->
    <div id="panel-text" class="hidden">
      <!-- Folder Scan Tab -->
    <div id="panel-folder" class="hidden">
      <label class="block text-sm font-medium text-gray-300 mb-3">
        <i class="fas fa-folder-open mr-2 text-green-400"></i>Folder / Directory Scan
      </label>
      <p class="text-xs text-gray-500 mb-4">
        <i class="fas fa-circle-info mr-1 text-green-400/60"></i>
        Select any folder from your device — all supported files inside will be read and scanned locally in the browser. Works on desktop and Android file managers that support folder selection.
      </p>

      <!-- Folder picker area -->
      <div id="folder-drop-zone"
        class="folder-drop rounded-2xl px-6 py-10 text-center cursor-pointer relative"
        onclick="document.getElementById('folder-file-input').click()"
        ondragover="handleFolderDragOver(event)"
        ondragleave="handleFolderDragLeave(event)"
        ondrop="handleFolderDrop(event)">
        <input id="folder-file-input" type="file" class="hidden" webkitdirectory multiple onchange="handleFolderSelect(event)"/>
        <div id="folder-idle-state">
          <div class="w-16 h-16 rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-4">
            <i class="fas fa-folder-open text-green-400 text-3xl"></i>
          </div>
          <p class="text-white font-semibold mb-1">Click to select folder or drag & drop</p>
          <p class="text-gray-500 text-sm mb-3">Reads all files recursively from the selected folder</p>
          <div class="flex flex-wrap justify-center gap-4 text-xs text-gray-600">
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> No upload — 100% local</span>
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> Recursive subfolders</span>
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> Up to 500 files</span>
            <span class="flex items-center gap-1"><i class="fas fa-check text-green-500"></i> All 33 patterns</span>
          </div>
        </div>
        <div id="folder-loaded-state" class="hidden">
          <div class="w-14 h-14 rounded-xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-3">
            <i class="fas fa-circle-check text-green-400 text-2xl"></i>
          </div>
          <p class="text-white font-semibold mb-1" id="folder-name-label">folder</p>
          <p class="text-gray-500 text-sm" id="folder-info-label">0 scannable files</p>
          <button onclick="resetFolder(event)" class="mt-3 text-xs text-gray-500 hover:text-red-400 transition-colors">
            <i class="fas fa-xmark mr-1"></i>Change folder
          </button>
        </div>
      </div>

      <!-- Stats row (hidden until loaded) -->
      <div id="folder-stats-row" class="hidden mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="glass rounded-xl p-3 text-center">
          <div class="text-xl font-black text-white count-up" id="fstat-total">0</div>
          <div class="text-xs text-gray-500 mt-0.5">Total files</div>
        </div>
        <div class="glass rounded-xl p-3 text-center">
          <div class="text-xl font-black text-green-400 count-up" id="fstat-scannable">0</div>
          <div class="text-xs text-gray-500 mt-0.5">Scannable</div>
        </div>
        <div class="glass rounded-xl p-3 text-center">
          <div class="text-xl font-black text-yellow-400 count-up" id="fstat-skipped">0</div>
          <div class="text-xs text-gray-500 mt-0.5">Skipped</div>
        </div>
        <div class="glass rounded-xl p-3 text-center">
          <div class="text-xl font-black text-blue-400 count-up" id="fstat-size">0 KB</div>
          <div class="text-xs text-gray-500 mt-0.5">Total size</div>
        </div>
      </div>

      <!-- File tree + scan button -->
      <div id="folder-tree-section" class="hidden mt-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-medium text-gray-400 uppercase tracking-wide flex items-center gap-1.5">
            <i class="fas fa-folder-tree text-green-400"></i>Files to Scan
          </span>
          <div class="flex items-center gap-3">
            <span class="text-xs text-gray-600" id="folder-tree-counts"></span>
            <button id="scan-folder-btn" onclick="startFolderScan()"
              class="flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg hover:shadow-green-500/25">
              <i class="fas fa-shield-halved"></i> Scan Folder
            </button>
          </div>
        </div>
        <div id="folder-file-tree" class="terminal-bg rounded-xl p-3 max-h-52 overflow-y-auto text-xs mono space-y-0.5"></div>
      </div>
    </div>

    <!-- Android Scan Tab -->
    <div id="panel-android" class="hidden">
      <label class="block text-sm font-medium text-gray-300 mb-1">
        <i class="fab fa-android mr-2 text-green-400"></i>Android Device / Storage Scan
      </label>
      <p class="text-xs text-gray-500 mb-4">
        <i class="fas fa-circle-info mr-1 text-green-400/60"></i>
        Select your Android device's storage folder from your PC (via USB/MTP), or browse the Android file manager on-device. 
        Choose a scan profile below or select any folder manually.
      </p>

      <!-- Scan Profiles -->
      <div class="mb-5">
        <p class="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-2">
          <i class="fas fa-sliders text-green-400"></i>Quick Scan Profiles
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3" id="android-profiles-grid">
          <!-- profiles rendered by JS -->
        </div>
      </div>

      <!-- Manual folder picker -->
      <div class="glass rounded-xl p-4 mb-4">
        <p class="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-2">
          <i class="fas fa-folder-plus text-green-400"></i>Or Select Folder Manually
        </p>
        <div class="flex items-center gap-3">
          <div id="android-folder-drop"
            class="folder-drop flex-1 rounded-xl px-4 py-3 flex items-center gap-3 cursor-pointer"
            onclick="document.getElementById('android-folder-input').click()">
            <input id="android-folder-input" type="file" class="hidden" webkitdirectory multiple onchange="handleAndroidFolderSelect(event)"/>
            <i class="fas fa-folder-open text-green-400 text-lg shrink-0"></i>
            <div>
              <p class="text-sm text-white font-medium" id="android-folder-label">Click to select Android folder</p>
              <p class="text-xs text-gray-500" id="android-folder-sub">Connect phone via USB/MTP or use Android file manager</p>
            </div>
          </div>
          <button id="scan-android-btn" onclick="startAndroidScan()" class="hidden flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg hover:shadow-green-500/25">
            <i class="fas fa-shield-halved"></i> Scan
          </button>
        </div>
      </div>

      <!-- File tree after selection -->
      <div id="android-tree-section" class="hidden mt-2">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-medium text-gray-400 uppercase tracking-wide flex items-center gap-1.5">
            <i class="fab fa-android text-green-400"></i>Detected Files
            <span class="text-gray-600 font-normal normal-case" id="android-profile-badge"></span>
          </span>
          <span class="text-xs text-gray-600" id="android-tree-counts"></span>
        </div>
        <div id="android-file-tree" class="terminal-bg rounded-xl p-3 max-h-52 overflow-y-auto text-xs mono space-y-0.5"></div>
      </div>

      <!-- Android Tips -->
      <div class="mt-4 glass rounded-xl p-4 border border-green-500/10">
        <p class="text-xs font-semibold text-gray-400 mb-2 flex items-center gap-2"><i class="fas fa-lightbulb text-yellow-400"></i>Tips for Android Scanning</p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-gray-500">
          <div class="flex items-start gap-2"><i class="fas fa-usb text-blue-400 mt-0.5 shrink-0"></i><span><b class="text-gray-400">USB/MTP:</b> Connect phone → enable file transfer → open phone storage in file manager → select folder</span></div>
          <div class="flex items-start gap-2"><i class="fab fa-android text-green-400 mt-0.5 shrink-0"></i><span><b class="text-gray-400">On-device:</b> Open browser → tap Folder Scan tab → select storage folder from file picker</span></div>
          <div class="flex items-start gap-2"><i class="fas fa-folder text-yellow-400 mt-0.5 shrink-0"></i><span><b class="text-gray-400">Key paths:</b> <code class="bg-[#21262d] px-1 rounded">/sdcard/</code>, <code class="bg-[#21262d] px-1 rounded">/storage/emulated/0/</code></span></div>
          <div class="flex items-start gap-2"><i class="fas fa-shield-halved text-red-400 mt-0.5 shrink-0"></i><span><b class="text-gray-400">Scans for:</b> tokens in apps, backup files, config JSONs, .env files, private keys</span></div>
        </div>
      </div>
    </div>

    <!-- Text/File Tab original placeholder (kept) -->
    <div id="panel-text-inner">
      <label class="block text-sm font-medium text-gray-300 mb-2">
        <i class="fas fa-file-code mr-2 text-gray-400"></i>Paste Code or File Content
      </label>
      <div class="relative mb-3">
        <textarea id="text-content" rows="10"
          placeholder="Paste your code, configuration file, .env file, or any text content here..."
          class="w-full bg-[#0d1117] border border-[#30363d] rounded-xl px-4 py-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all mono resize-none"
        ></textarea>
      </div>
      <div class="flex items-center gap-3">
        <input id="file-input" type="file" class="hidden" accept=".env,.json,.yaml,.yml,.toml,.ini,.cfg,.conf,.properties,.xml,.sh,.bash,.py,.js,.ts,.rb,.go,.php,.pem,.key,.crt,.tf,.tfvars,.txt" onchange="loadFile(event)"/>
        <button onclick="document.getElementById('file-input').click()" class="flex items-center gap-2 px-4 py-2 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-gray-300 text-sm rounded-lg transition-colors">
          <i class="fas fa-upload"></i> Load File
        </button>
        <span id="file-name" class="text-xs text-gray-500"></span>
        <div class="flex-1"></div>
        <button id="scan-text-btn" onclick="startTextScan()" 
          class="flex items-center gap-2 px-6 py-2 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white text-sm font-semibold rounded-xl transition-all">
          <i class="fas fa-search"></i> Scan Content
        </button>
      </div>
    </div>
  </div>

  <!-- Progress Bar (hidden initially) -->
  <div id="progress-section" class="hidden mb-6 glass rounded-2xl p-5">
    <div class="flex items-center justify-between mb-3">
      <div class="flex items-center gap-3">
        <div class="w-5 h-5 border-2 border-orange-500 border-t-transparent rounded-full spinner"></div>
        <span class="text-sm font-medium text-white" id="progress-label">Initializing scan...</span>
      </div>
      <span class="text-xs text-gray-500" id="progress-pct">0%</span>
    </div>
    <div class="w-full bg-[#21262d] rounded-full h-2">
      <div id="progress-fill" class="progress-bar h-2 bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 rounded-full" style="width:0%"></div>
    </div>
    <div class="mt-3 text-xs text-gray-500 font-mono" id="progress-file">Connecting to GitHub API...</div>
  </div>

  <!-- Results Section -->
  <div id="results-section" class="hidden">

    <!-- Summary Cards -->
    <div id="summary-cards" class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6"></div>

    <!-- Meta info bar -->
    <div id="meta-bar" class="glass rounded-xl px-5 py-3 mb-6 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-gray-400"></div>

    <!-- Filter & Sort Controls -->
    <div class="glass rounded-xl p-4 mb-4 flex flex-wrap items-center gap-3">
      <div class="flex items-center gap-2 flex-1 min-w-[200px]">
        <i class="fas fa-filter text-gray-500 text-sm"></i>
        <input id="filter-input" type="text" placeholder="Filter by file, category, label..."
          class="flex-1 bg-transparent text-sm text-white placeholder-gray-600 focus:outline-none"
          oninput="renderFindings()"/>
      </div>
      <div class="flex gap-2 flex-wrap">
        <button onclick="filterSeverity('all')" id="f-all" class="sev-filter active-filter px-3 py-1 rounded-lg text-xs font-medium bg-[#21262d] border border-[#30363d] text-white transition-colors">All</button>
        <button onclick="filterSeverity('critical')" id="f-critical" class="sev-filter px-3 py-1 rounded-lg text-xs font-medium bg-[#21262d] border border-[#30363d] text-gray-400 hover:text-white transition-colors">🔴 Critical</button>
        <button onclick="filterSeverity('high')" id="f-high" class="sev-filter px-3 py-1 rounded-lg text-xs font-medium bg-[#21262d] border border-[#30363d] text-gray-400 hover:text-white transition-colors">🟠 High</button>
        <button onclick="filterSeverity('medium')" id="f-medium" class="sev-filter px-3 py-1 rounded-lg text-xs font-medium bg-[#21262d] border border-[#30363d] text-gray-400 hover:text-white transition-colors">🟡 Medium</button>
        <button onclick="filterSeverity('low')" id="f-low" class="sev-filter px-3 py-1 rounded-lg text-xs font-medium bg-[#21262d] border border-[#30363d] text-gray-400 hover:text-white transition-colors">🟢 Low</button>
      </div>
      <div class="flex items-center gap-2">
        <button onclick="copyAllFindings()" class="copy-btn flex items-center gap-1.5 px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-blue-400 hover:text-blue-300 text-xs rounded-lg transition-colors" title="Copy all visible findings as plain text">
          <i class="fas fa-copy"></i> Copy All
        </button>
        <button onclick="exportResults()" class="flex items-center gap-1.5 px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-gray-300 text-xs rounded-lg transition-colors">
          <i class="fas fa-download"></i> Export JSON
        </button>
      </div>
    </div>

    <!-- Findings list -->
    <div id="findings-container" class="space-y-3"></div>

    <!-- Empty state -->
    <div id="no-findings" class="hidden glass rounded-2xl p-12 text-center">
      <div class="w-16 h-16 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
        <i class="fas fa-shield-check text-green-400 text-2xl"></i>
      </div>
      <h3 class="text-lg font-semibold text-white mb-2">No Secrets Detected</h3>
      <p class="text-gray-500 text-sm">No sensitive data patterns were found matching the active filters.</p>
    </div>
  </div>

  <!-- Error state -->
  <div id="error-section" class="hidden glass rounded-2xl p-8 text-center border border-red-500/20">
    <div class="w-12 h-12 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
      <i class="fas fa-circle-exclamation text-red-400 text-xl"></i>
    </div>
    <h3 class="text-base font-semibold text-white mb-2">Scan Failed</h3>
    <p id="error-msg" class="text-gray-400 text-sm"></p>
  </div>

  <!-- Pattern Library -->
  <section id="patterns-section" class="mt-12">
    <div class="flex items-center gap-3 mb-6">
      <div class="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
        <i class="fas fa-list text-blue-400 text-sm"></i>
      </div>
      <h3 class="text-xl font-bold text-white">Pattern Library</h3>
      <span class="text-xs text-gray-500 bg-[#21262d] border border-[#30363d] px-2 py-0.5 rounded-full" id="pattern-count">Loading...</span>
    </div>
    <div id="patterns-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3"></div>
  </section>

</main>

<!-- Footer -->
<footer class="mt-16 border-t border-[#30363d] py-8 px-4 text-center">
  <div class="text-gray-600 text-sm">
    <p class="mb-1">
      <i class="fas fa-shield-halved mr-1 text-red-500"></i>
      <strong class="text-gray-400">GitLeakHunter</strong> — Open source secret detection for Git repositories
    </p>
    <p class="text-xs text-gray-700">For educational and security purposes only. Always obtain proper authorization before scanning repositories.</p>
  </div>
</footer>

</div><!-- /content -->

<script>
// ─── Global State ─────────────────────────────────────────────────────────────
let scanResults = null;
let currentSeverityFilter = 'all';
let currentTab = 'github';
let scannedFilename = 'pasted-content';
let allPatterns = [];

// ─── Telegram Config ──────────────────────────────────────────────────────────
let tgConfig = { botToken: '', chatId: '', autoNotify: false };

function loadTgConfig(){
  try {
    const saved = localStorage.getItem('gitleakhunter_tg');
    if(saved) tgConfig = { ...tgConfig, ...JSON.parse(saved) };
  } catch {}
  const tokenEl = document.getElementById('tg-bot-token');
  const chatEl  = document.getElementById('tg-chat-id');
  if(tokenEl) tokenEl.value = tgConfig.botToken || '';
  if(chatEl)  chatEl.value  = tgConfig.chatId  || '';
  updateTgToggleUI();
  updateTgDot();
}

function saveTgConfig(){
  tgConfig.botToken = document.getElementById('tg-bot-token').value.trim();
  tgConfig.chatId   = document.getElementById('tg-chat-id').value.trim();
  localStorage.setItem('gitleakhunter_tg', JSON.stringify(tgConfig));
  updateTgDot();
}

function updateTgDot(){
  const dot = document.getElementById('tg-dot');
  if(!dot) return;
  if(tgConfig.botToken && tgConfig.chatId){
    dot.classList.remove('hidden');
  } else {
    dot.classList.add('hidden');
  }
}

function updateTgToggleUI(){
  const tog = document.getElementById('tg-auto-toggle');
  if(!tog) return;
  tog.classList.toggle('on', !!tgConfig.autoNotify);
}

function toggleTgPanel(){
  const panel = document.getElementById('tg-panel');
  panel.classList.toggle('hidden');
  if(!panel.classList.contains('hidden')){
    panel.classList.add('tg-slide');
    setTimeout(() => panel.classList.remove('tg-slide'), 300);
    loadTgConfig();
  }
}

function toggleAutoNotify(){
  tgConfig.autoNotify = !tgConfig.autoNotify;
  localStorage.setItem('gitleakhunter_tg', JSON.stringify(tgConfig));
  updateTgToggleUI();
  showTgStatus(tgConfig.autoNotify ? '✅ Auto-notify enabled — results will be sent after each scan' : '🔕 Auto-notify disabled', tgConfig.autoNotify ? 'success' : 'info');
}

function showTgStatus(msg, type='success'){
  const el = document.getElementById('tg-status');
  if(!el) return;
  const colors = { success:'text-green-400 bg-green-500/10 border border-green-500/20', error:'text-red-400 bg-red-500/10 border border-red-500/20', info:'text-blue-400 bg-blue-500/10 border border-blue-500/20', loading:'text-gray-300 bg-gray-500/10 border border-gray-500/20' };
  el.className = 'mt-3 text-xs rounded-lg px-3 py-2 ' + (colors[type] || colors.info);
  el.textContent = msg;
  el.classList.remove('hidden');
  if(type !== 'loading') setTimeout(() => el.classList.add('hidden'), 5000);
}

async function testTelegram(){
  const token = document.getElementById('tg-bot-token').value.trim();
  const chatId = document.getElementById('tg-chat-id').value.trim();
  if(!token || !chatId){
    showTgStatus('⚠️ Please enter Bot Token and Chat ID first', 'error'); return;
  }
  const btn = document.getElementById('tg-test-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-circle-notch spinner"></i> Testing...';
  showTgStatus('⏳ Sending test message to Telegram...', 'loading');
  try {
    const resp = await fetch('/api/telegram/test', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ botToken: token, chatId })
    });
    const data = await resp.json();
    if(data.ok){
      showTgStatus('✅ ' + data.message, 'success');
      // Save config after successful test
      tgConfig.botToken = token;
      tgConfig.chatId = chatId;
      localStorage.setItem('gitleakhunter_tg', JSON.stringify(tgConfig));
      updateTgDot();
    } else {
      showTgStatus('❌ ' + (data.error || 'Telegram API error'), 'error');
    }
  } catch(e){
    showTgStatus('❌ Network error: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-paper-plane"></i> Test';
  }
}

async function sendResultsToTelegram(autoMode=false){
  if(!scanResults) {
    if(!autoMode) showTgStatus('⚠️ No scan results to send yet', 'error');
    return;
  }
  const token = tgConfig.botToken;
  const chatId = tgConfig.chatId;
  if(!token || !chatId){
    if(!autoMode){
      // open panel if closed
      const panel = document.getElementById('tg-panel');
      if(panel.classList.contains('hidden')) toggleTgPanel();
      showTgStatus('⚠️ Please configure Bot Token and Chat ID first', 'error');
    }
    return;
  }
  const sendBtn = document.getElementById('tg-send-now-btn');
  if(sendBtn){ sendBtn.disabled=true; sendBtn.innerHTML='<i class="fas fa-circle-notch spinner"></i> Sending...'; }
  if(!autoMode) showTgStatus('⏳ Sending report to Telegram...', 'loading');
  try {
    const resp = await fetch('/api/telegram/notify', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ botToken: token, chatId, findings: scanResults.findings, meta: scanResults.meta })
    });
    const data = await resp.json();
    if(data.ok){
      const msg = '✅ ' + data.message;
      showTgStatus(msg, 'success');
      if(autoMode) showToast('📨 ' + data.message + ' (Telegram)', 'success');
    } else {
      showTgStatus('❌ ' + (data.error || 'Failed to send'), 'error');
    }
  } catch(e){
    showTgStatus('❌ Network error: ' + e.message, 'error');
  } finally {
    if(sendBtn){ sendBtn.disabled=false; sendBtn.innerHTML='<i class="fas fa-share"></i> Send Results'; }
  }
}

function showSendNowBtn(){
  const btn = document.getElementById('tg-send-now-btn');
  if(btn) btn.classList.replace('hidden','flex');
}

function maybeAutoNotify(){
  if(tgConfig.autoNotify && tgConfig.botToken && tgConfig.chatId){
    sendResultsToTelegram(true);
  }
}

// ─── Matrix rain background ────────────────────────────────────────────────────
(function initMatrix(){
  const canvas = document.getElementById('matrix');
  const ctx = canvas.getContext('2d');
  let W = canvas.width = window.innerWidth;
  let H = canvas.height = window.innerHeight;
  const chars = 'アイウエオカキクケコサシスセソタチツテトABCDEFGHIJKLMNOP0123456789@#$%';
  const cols = Math.floor(W/16);
  const drops = Array(cols).fill(1);
  function draw(){
    ctx.fillStyle='rgba(13,17,23,0.05)';
    ctx.fillRect(0,0,W,H);
    ctx.fillStyle='#0f3';
    ctx.font='14px monospace';
    for(let i=0;i<drops.length;i++){
      ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*16,drops[i]*16);
      if(drops[i]*16>H&&Math.random()>0.975)drops[i]=0;
      drops[i]++;
    }
  }
  setInterval(draw,50);
  window.addEventListener('resize',()=>{W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;});
})();

// ─── Tab switching ────────────────────────────────────────────────────────────
function switchTab(tab){
  currentTab = tab;
  ['github','zip','text'].forEach(p => {
    document.getElementById('panel-'+p).classList.toggle('hidden', tab !== p);
    const btn = document.getElementById('tab-'+p);
    if(btn){
      btn.classList.toggle('active', tab === p);
      btn.classList.toggle('text-gray-400', tab !== p);
    }
  });
}

function setExample(url){
  document.getElementById('github-url').value = url;
  document.getElementById('github-url').focus();
}

// ─── ZIP Upload Logic ────────────────────────────────────────────────────────
let zipExtractedFiles = [];   // [{name, content}]
let zipRawFile = null;

function handleDragOver(e){
  e.preventDefault(); e.stopPropagation();
  document.getElementById('zip-drop-zone').classList.add('drag-over');
}
function handleDragLeave(e){
  e.preventDefault();
  document.getElementById('zip-drop-zone').classList.remove('drag-over');
}
function handleDrop(e){
  e.preventDefault(); e.stopPropagation();
  document.getElementById('zip-drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if(file) processZipFile(file);
}
function handleZipFile(event){
  const file = event.target.files[0];
  if(file) processZipFile(file);
}
function resetZip(e){
  if(e){ e.preventDefault(); e.stopPropagation(); }
  zipExtractedFiles = [];
  zipRawFile = null;
  document.getElementById('zip-file-input').value = '';
  document.getElementById('zip-drop-idle').classList.remove('hidden');
  document.getElementById('zip-drop-loaded').classList.add('hidden');
  document.getElementById('zip-tree-section').classList.add('hidden');
  document.getElementById('zip-extract-progress').classList.add('hidden');
}

async function processZipFile(file){
  const MAX_MB = 200;
  if(file.size > MAX_MB * 1024 * 1024){
    showToast('File too large. Max ' + MAX_MB + ' MB.', 'error'); return;
  }
  if(!window.JSZip){
    showToast('JSZip library not loaded. Check your connection.', 'error'); return;
  }

  zipRawFile = file;
  zipExtractedFiles = [];

  // Show extraction progress
  document.getElementById('zip-extract-progress').classList.remove('hidden');
  document.getElementById('zip-tree-section').classList.add('hidden');
  document.getElementById('zip-drop-idle').classList.add('hidden');
  document.getElementById('zip-drop-loaded').classList.add('hidden');

  const setExtPct = (p, label, f) => {
    document.getElementById('zip-extract-fill').style.width = p + '%';
    document.getElementById('zip-extract-pct').textContent = Math.round(p) + '%';
    if(label) document.getElementById('zip-extract-label').textContent = label;
    if(f) document.getElementById('zip-extract-file').textContent = f;
  };

  try {
    setExtPct(5, 'Reading archive...', file.name);
    const arrayBuf = await file.arrayBuffer();

    setExtPct(20, 'Parsing ZIP structure...', '');
    const zip = await JSZip.loadAsync(arrayBuf);

    const allEntries = [];
    zip.forEach((relativePath, zipEntry) => {
      if(!zipEntry.dir) allEntries.push({ path: relativePath, entry: zipEntry });
    });

    setExtPct(30, 'Filtering files...', allEntries.length + ' entries found');

    // Determine scannable files (same logic as backend)
    const SCAN_EXT = new RegExp('\\.(env|json|yaml|yml|toml|ini|cfg|conf|config|properties|xml|sh|bash|zsh|py|js|ts|jsx|tsx|rb|go|php|java|cs|cpp|c|h|tf|tfvars|pem|key|crt|cer|txt|md|gradle|Makefile|Dockerfile|htpasswd|npmrc|netrc|gitcredentials)$', 'i');
    const SKIP_PATH = new RegExp('^(node_modules|\\.git|dist|build|vendor|__pycache__|\\.venv|venv)\\/');
    const DOTFILE   = new RegExp('^.*(\\.(env|npmrc|netrc|gitconfig|htpasswd|bashrc|zshrc|credentials|secrets))$', 'i');
    const BINARY_EXT = new RegExp('\\.(png|jpg|jpeg|gif|ico|bmp|svg|woff|woff2|ttf|eot|otf|mp4|mp3|wav|avi|mov|pdf|docx|xlsx|pptx|class|pyc|so|dll|exe|bin|zip|tar|gz|7z|rar|jar|war)$', 'i');
    const MAX_FILE_BYTES = 500000;
    const MAX_SCAN = 300;

    const scannable = allEntries.filter(({path}) =>
      !SKIP_PATH.test(path) &&
      !BINARY_EXT.test(path) &&
      (SCAN_EXT.test(path) || DOTFILE.test(path))
    ).slice(0, MAX_SCAN);

    const skipped = allEntries.length - scannable.length;

    setExtPct(40, 'Extracting ' + scannable.length + ' files...', '');

    // Extract text from scannable files
    let done = 0;
    for(const {path, entry} of scannable){
      setExtPct(40 + Math.round((done / scannable.length) * 55), 'Extracting...', path);
      try {
        const buf = await entry.async('uint8array');
        if(buf.byteLength > MAX_FILE_BYTES){ done++; continue; }
        // Decode as UTF-8, ignore errors
        const text = new TextDecoder('utf-8', {fatal: false}).decode(buf);
        // Skip if looks binary (lots of null bytes)
        const nullCount = (text.match(/\x00/g) || []).length;
        if(nullCount > text.length * 0.05){ done++; continue; }
        zipExtractedFiles.push({ name: path, content: text });
      } catch {}
      done++;
    }

    setExtPct(100, 'Extraction complete!', zipExtractedFiles.length + ' files ready');
    await new Promise(r => setTimeout(r, 300));
    document.getElementById('zip-extract-progress').classList.add('hidden');

    // Show loaded state
    document.getElementById('zip-drop-loaded').classList.remove('hidden');
    document.getElementById('zip-filename-label').textContent = file.name;
    document.getElementById('zip-fileinfo-label').textContent =
      allEntries.length + ' entries — ' + zipExtractedFiles.length + ' scannable files';

    // Render file tree
    renderZipTree(zipExtractedFiles, skipped);
    document.getElementById('zip-tree-section').classList.remove('hidden');

  } catch(err){
    document.getElementById('zip-extract-progress').classList.add('hidden');
    document.getElementById('zip-drop-idle').classList.remove('hidden');
    showToast('Failed to read ZIP: ' + err.message, 'error');
  }
}

function renderZipTree(files, skippedCount){
  const container = document.getElementById('zip-file-tree');
  // Build folder groups
  const folders = {};
  files.forEach(f => {
    const parts = f.name.split('/');
    const dir = parts.length > 1 ? parts.slice(0, -1).join('/') : '(root)';
    if(!folders[dir]) folders[dir] = [];
    folders[dir].push(f.name);
  });

  const extIconMap = {
    env:'fa-gear text-yellow-400', json:'fa-brackets-curly text-blue-400',
    yaml:'fa-database text-cyan-400', yml:'fa-database text-cyan-400',
    toml:'fa-gear text-orange-400', sh:'fa-terminal text-green-400',
    bash:'fa-terminal text-green-400', py:'fa-snake text-yellow-300',
    js:'fa-js text-yellow-300', ts:'fa-code text-blue-400',
    pem:'fa-lock text-red-400', key:'fa-key text-red-400',
    crt:'fa-certificate text-orange-400', cer:'fa-certificate text-orange-400',
    tf:'fa-cloud text-purple-400', tfvars:'fa-cloud text-purple-400',
    php:'fa-code text-indigo-400', rb:'fa-gem text-red-300',
    go:'fa-code text-cyan-300', java:'fa-coffee text-orange-400',
  };
  function getExtIcon(fname){
    const ext = fname.split('.').pop().toLowerCase();
    const ic = extIconMap[ext];
    return ic ? '<i class="fas ' + ic + ' mr-1.5 text-xs shrink-0"></i>'
              : '<i class="fas fa-file-code text-gray-500 mr-1.5 text-xs shrink-0"></i>';
  }

  let html = '';
  const sortedDirs = Object.keys(folders).sort();
  sortedDirs.forEach(dir => {
    if(dir !== '(root)'){
      html += '<div class="file-pop flex items-center gap-1.5 px-2 py-0.5 text-violet-400 font-medium mt-1">'
            + '<i class="fas fa-folder-open text-xs"></i>'
            + '<span class="truncate">' + escHtml(dir) + '</span></div>';
    }
    folders[dir].forEach(fpath => {
      const fname = fpath.split('/').pop();
      html += '<div class="file-pop file-tree-item flex items-center gap-1 px-2 py-0.5 rounded text-gray-400">'
            + (dir !== '(root)' ? '<span class="text-gray-700 mr-1">│</span>' : '')
            + getExtIcon(fname)
            + '<span class="truncate text-gray-300">' + escHtml(fname) + '</span></div>';
    });
  });
  container.innerHTML = html;

  document.getElementById('zip-tree-counts').textContent = files.length + ' files queued';
  document.getElementById('zip-skipped-label').textContent = skippedCount + ' files';
}

// ─── ZIP Scan ─────────────────────────────────────────────────────────────────
async function startZipScan(){
  if(!zipExtractedFiles.length){
    showToast('Please upload a ZIP file first', 'error'); return;
  }

  hideResults(); hideError();
  showProgress('Sending ' + zipExtractedFiles.length + ' files to scanner...');
  setScanBtnLoading('scan-zip-btn', true, 'Scanning...');

  const steps = [
    [20, 'Running secret pattern detection...'],
    [45, 'Scanning configuration files...'],
    [65, 'Checking credentials & API keys...'],
    [80, 'Analyzing private keys & certificates...'],
    [93, 'Aggregating findings...'],
  ];
  let si = 0;
  const iv = setInterval(() => {
    if(si < steps.length){ const [p,l] = steps[si++]; updateProgress(p, l); }
  }, 700);

  try {
    const resp = await fetch('/api/scan/zip', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ files: zipExtractedFiles }),
    });
    clearInterval(iv);
    updateProgress(100, 'Scan complete!');
    await new Promise(r => setTimeout(r, 300));
    hideProgress();

    const data = await resp.json();
    if(!resp.ok || data.error){ showError(data.error || 'Unknown error'); return; }

    // Inject ZIP-specific meta
    data.meta = data.meta || {};
    data.meta.zipName = zipRawFile ? zipRawFile.name : 'archive.zip';
    scanResults = data;
    renderZipResults(data);
    showSendNowBtn();
    maybeAutoNotify();
  } catch(e){
    clearInterval(iv);
    hideProgress();
    showError(e.message);
  } finally {
    setScanBtnLoading('scan-zip-btn', false);
  }
}

function renderZipResults(data){
  // Add ZIP-specific info to meta then call standard render
  data.meta.repo = data.meta.zipName;
  data.meta.platform = 'zip';
  renderResults(data);

  // Inject extra stats into meta bar
  const metaBar = document.getElementById('meta-bar');
  if(data.meta.skippedFiles){
    const extra = document.createElement('span');
    extra.innerHTML = '<span class="text-gray-700">•</span><span><i class="fas fa-ban mr-1 text-gray-600"></i>'
      + data.meta.skippedFiles + ' skipped</span>';
    metaBar.appendChild(extra);
  }
}

// ─── Demo Secrets ─────────────────────────────────────────────────────────────
function loadDemoText(){
  const demo = \`# ============================================================
# DEMO FILE — Fake secrets for GitLeakHunter testing
# ============================================================

# --- AWS Credentials ---
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

# --- Database ---
DB_PASSWORD="s3cur3P@ssw0rd!2024"
DATABASE_URL=postgresql://admin:hunter2@prod-db.internal:5432/myapp
MONGO_URI=mongodb://root:topsecret@cluster0.mongodb.net/prod

# --- API Keys ---
OPENAI_API_KEY=sk-proj-[DEMO-NOT-REAL-OPENAI-KEY-FOR-TESTING-ONLY-EXAMPLE]
STRIPE_SECRET_KEY=sk_live_[DEMO-NOT-REAL-STRIPE-KEY-EXAMPLE]
SENDGRID_API_KEY=SG.[DEMO-NOT-REAL].[SENDGRID-KEY-EXAMPLE-FOR-TESTING-PURPOSES-ONLY-000]

# --- GitHub ---
GITHUB_TOKEN=ghp_[DEMO-NOT-REAL-GITHUB-TOKEN-EXAMPLE00]
GITHUB_OAUTH=gho_[DEMO-NOT-REAL-OAUTH-TOKEN-EXAMPLE000]

# --- Messaging ---
SLACK_BOT_TOKEN=xoxb-[DEMO-NOT-REAL-SLACK-TOKEN-EXAMPLE]
SLACK_WEBHOOK=https://hooks.slack.com/services/T[DEMO]/B[DEMO]/[NOT-A-REAL-WEBHOOK]
DISCORD_BOT_TOKEN=MTIzNDU2Nzg4.[DEMO].[NOT-REAL-DISCORD-TOKEN-EXAMPLE-ONLY]
TELEGRAM_TOKEN=1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ1234567890

# --- JWT ---
AUTH_TOKEN="eyJhbGciOiJERU1PIn0.eyJzdWIiOiJERU1PX05PVF9SRUFMX0pXVCIsIm5vdGUiOiJGYWtlIHRva2VuIGZvciB0ZXN0aW5nIG9ubHkifQ.DEMO_SIGNATURE_NOT_REAL"

# --- Private Key (RSA) ---
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHnPBCMfMFBbXIUmFHLERx0LKoXFnHrYwi62
-----END RSA PRIVATE KEY-----

# --- TLS Certificate ---
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXxFCCVFoH1nHBk8cELF31HFvJoswDQYJKoZIhvcNAQEL
-----END CERTIFICATE-----

# --- NPM ---
NPM_TOKEN=npm_[DEMO-NOT-REAL-NPM-TOKEN-EXAMPLE-00000]

# --- Generic ---
secret_key = "my-super-secret-key-12345"
password = "correct-horse-battery-staple"
\`;
  switchTab('text');
  scannedFilename = 'demo-secrets.env';
  document.getElementById('text-content').value = demo;
  document.getElementById('file-name').textContent = 'demo-secrets.env (fake data)';
  showToast('Demo content loaded! Click Scan Content.', 'success');
}


function loadFile(event){
  const file = event.target.files[0];
  if(!file) return;
  scannedFilename = file.name;
  document.getElementById('file-name').textContent = file.name;
  const reader = new FileReader();
  reader.onload = (e) => { document.getElementById('text-content').value = e.target.result; };
  reader.readAsText(file);
}

// ─── Progress helpers ─────────────────────────────────────────────────────────
function showProgress(label){
  document.getElementById('progress-section').classList.remove('hidden');
  document.getElementById('progress-label').textContent = label;
  document.getElementById('progress-fill').style.width = '5%';
  document.getElementById('progress-pct').textContent = '5%';
}

function updateProgress(pct, file){
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-pct').textContent = Math.round(pct) + '%';
  if(file) document.getElementById('progress-file').textContent = file;
}

function hideProgress(){
  document.getElementById('progress-section').classList.add('hidden');
}

// ─── GitHub Scan ──────────────────────────────────────────────────────────────
async function startGithubScan(){
  const url = document.getElementById('github-url').value.trim();
  if(!url){ showToast('Please enter a GitHub URL', 'error'); return; }
  
  hideResults(); hideError();
  showProgress('Connecting to GitHub API...');
  setScanBtnLoading('scan-github-btn', true);
  
  // Simulate progress updates
  const progressSteps = [
    [15, 'Fetching repository metadata...'],
    [30, 'Building file tree...'],
    [50, 'Scanning source files...'],
    [70, 'Analyzing commit history...'],
    [85, 'Running pattern detection...'],
    [95, 'Aggregating results...'],
  ];
  let stepIdx = 0;
  const progressInterval = setInterval(() => {
    if(stepIdx < progressSteps.length){
      const [pct, label] = progressSteps[stepIdx++];
      updateProgress(pct, label);
    }
  }, 700);
  
  try {
    const resp = await fetch('/api/scan/github', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ url }),
    });
    clearInterval(progressInterval);
    updateProgress(100, 'Scan complete!');
    await new Promise(r => setTimeout(r, 300));
    hideProgress();
    
    const data = await resp.json();
    if(!resp.ok || data.error){ showError(data.error || 'Unknown error'); return; }
    
    scanResults = data;
    renderResults(data);
    showSendNowBtn();
    maybeAutoNotify();
  } catch(e){
    clearInterval(progressInterval);
    hideProgress();
    showError(e.message);
  } finally {
    setScanBtnLoading('scan-github-btn', false);
  }
}

// ─── Text Scan ────────────────────────────────────────────────────────────────
async function startTextScan(){
  const content = document.getElementById('text-content').value.trim();
  if(!content){ showToast('Please paste some content to scan', 'error'); return; }
  
  hideResults(); hideError();
  showProgress('Analyzing content...');
  setScanBtnLoading('scan-text-btn', true);
  updateProgress(30, 'Running pattern matching...');
  
  try {
    const resp = await fetch('/api/scan/text', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ content, filename: scannedFilename }),
    });
    updateProgress(100, 'Done!');
    await new Promise(r => setTimeout(r, 200));
    hideProgress();
    
    const data = await resp.json();
    if(!resp.ok || data.error){ showError(data.error || 'Unknown error'); return; }
    
    scanResults = data;
    renderResults(data);
    showSendNowBtn();
    maybeAutoNotify();
  } catch(e){
    hideProgress();
    showError(e.message);
  } finally {
    setScanBtnLoading('scan-text-btn', false);
  }
}

// ─── Button loading state ────────────────────────────────────────────────────
function setScanBtnLoading(id, loading, loadingLabel){
  const btn = document.getElementById(id);
  if(!btn) return;
  const label = loadingLabel || 'Scanning...';
  if(loading){
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-circle-notch spinner"></i> ' + label;
    btn.classList.add('opacity-75','cursor-not-allowed');
  } else {
    btn.disabled = false;
    if(id === 'scan-text-btn') btn.innerHTML = '<i class="fas fa-search"></i> Scan Content';
    else if(id === 'scan-zip-btn') btn.innerHTML = '<i class="fas fa-shield-halved"></i> Scan for Secrets';
    else btn.innerHTML = '<i class="fas fa-search"></i> Scan';
    btn.classList.remove('opacity-75','cursor-not-allowed');
  }
}

// ─── Render Results ───────────────────────────────────────────────────────────
function renderResults(data){
  document.getElementById('results-section').classList.remove('hidden');
  
  const { findings, meta } = data;
  
  // Count by severity
  const counts = { critical:0, high:0, medium:0, low:0 };
  findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
  
  // Summary cards
  const cardsHtml = [
    { key:'critical', label:'Critical', color:'red', icon:'fa-skull-crossbones', glow:'glow-red' },
    { key:'high',     label:'High',     color:'orange', icon:'fa-triangle-exclamation', glow:'' },
    { key:'medium',   label:'Medium',   color:'yellow', icon:'fa-circle-exclamation', glow:'' },
    { key:'low',      label:'Low',      color:'green', icon:'fa-circle-info', glow:'glow-green' },
  ].map(s => \`
    <div class="glass rounded-xl p-4 cursor-pointer hover:border-\${s.color}-500/40 border border-transparent transition-all \${s.glow}" onclick="filterSeverity('\${s.key}')">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">\${s.label}</span>
        <i class="fas \${s.icon} text-\${s.color}-500 text-sm"></i>
      </div>
      <div class="text-3xl font-black text-white">\${counts[s.key]}</div>
      <div class="text-xs text-gray-600 mt-1">findings</div>
    </div>
  \`).join('');
  document.getElementById('summary-cards').innerHTML = cardsHtml;
  
  // Meta bar
  const metaItems = [
    \`<span><i class="fas fa-file-code mr-1 text-blue-400"></i>\${meta.scannedFiles || 1} files scanned</span>\`,
    \`<span><i class="fas fa-clock mr-1 text-gray-500"></i>\${meta.elapsed}s</span>\`,
    \`<span class="font-semibold \${findings.length > 0 ? 'text-red-400' : 'text-green-400'}">\${findings.length} total findings</span>\`,
  ];
  if(meta.commits) metaItems.splice(1, 0, \`<span><i class="fas fa-code-commit mr-1 text-purple-400"></i>\${meta.commits} commits analyzed</span>\`);
  if(meta.repo){
    const pIcons = { github:'fab fa-github', gitlab:'fab fa-gitlab text-orange-400', bitbucket:'fab fa-bitbucket text-blue-400', zip:'fas fa-file-zipper text-violet-400' };
    const pIcon = pIcons[meta.platform] || 'fas fa-globe text-gray-400';
    const prefix = meta.host ? meta.host + '/' : '';
    metaItems.unshift(\`<span class="text-white font-medium"><i class="\${pIcon} mr-1"></i>\${prefix}\${meta.repo}</span>\`);
  }
  document.getElementById('meta-bar').innerHTML = metaItems.join('<span class="text-gray-700">•</span>');
  
  currentSeverityFilter = 'all';
  document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active-filter','text-white','border-blue-500'));
  document.getElementById('f-all').classList.add('active-filter','text-white');
  
  renderFindings();
  
  // Scroll to results
  document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderFindings(){
  if(!scanResults) return;
  const { findings } = scanResults;
  const filterText = document.getElementById('filter-input').value.toLowerCase();
  
  let filtered = findings.filter(f => {
    if(currentSeverityFilter !== 'all' && f.severity !== currentSeverityFilter) return false;
    if(filterText && !f.file.toLowerCase().includes(filterText) && !f.category.toLowerCase().includes(filterText) && !f.label.toLowerCase().includes(filterText) && !f.snippet.toLowerCase().includes(filterText)) return false;
    return true;
  });
  
  // Sort: critical first
  const sevOrder = { critical:0, high:1, medium:2, low:3 };
  filtered.sort((a,b) => (sevOrder[a.severity]??4) - (sevOrder[b.severity]??4));
  
  const container = document.getElementById('findings-container');
  const noFindings = document.getElementById('no-findings');
  
  if(filtered.length === 0){
    container.innerHTML = '';
    noFindings.classList.remove('hidden');
    return;
  }
  noFindings.classList.add('hidden');
  
  // Group by file
  const byFile = {};
  filtered.forEach(f => { (byFile[f.file] = byFile[f.file]||[]).push(f); });
  
  container.innerHTML = Object.entries(byFile).map(([file, fileFindings]) => \`
    <div class="glass rounded-xl overflow-hidden">
      <div class="px-4 py-3 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between">
        <div class="flex items-center gap-2 min-w-0">
          \${getFileIcon(file)}
          <span class="text-sm font-medium text-gray-200 mono truncate">\${escHtml(file)}</span>
        </div>
        <div class="flex items-center gap-3 ml-3 shrink-0">
          <span class="text-xs text-gray-500">\${fileFindings.length} finding\${fileFindings.length>1?'s':''}</span>
          <button onclick="copyFileFindings(\${JSON.stringify(file)})" class="copy-btn text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1 px-2 py-0.5 rounded border border-[#30363d] hover:border-[#484f58] transition-all" title="Copy all findings from this file"><i class="fas fa-copy text-xs"></i> Copy file</button>
        </div>
      </div>
      <div class="divide-y divide-[#30363d]">
        \${fileFindings.map(f => findingCard(f)).join('')}
      </div>
    </div>
  \`).join('');
}

function findingCard(f){
  const sevBg = { critical:'severity-critical', high:'severity-high', medium:'severity-medium', low:'severity-low' };
  const redacted = redactSecret(f.match);
  const copySecret  = f.match || '';
  const copySnippet = f.snippet || '';
  const copyFull    = '[' + f.severity.toUpperCase() + '] ' + f.label + ' | File: ' + f.file + ' (line ' + f.line + ') | Category: ' + f.category + ' | Matched: ' + f.match + ' | Snippet: ' + f.snippet;

  return \`
    <div class="finding-card \${sevBg[f.severity]} px-4 py-3">
      <div class="flex items-start gap-3">
        <span class="text-lg shrink-0 mt-0.5">\${f.icon}</span>
        <div class="flex-1 min-w-0">
          <div class="flex flex-wrap items-center gap-2 mb-1.5">
            <span class="text-sm font-semibold text-white">\${escHtml(f.label)}</span>
            <span class="badge-\${f.severity} text-xs px-2 py-0.5 rounded-full font-medium">\${f.severity.toUpperCase()}</span>
            <span class="category-chip bg-[#21262d] border border-[#30363d] text-gray-400">\${escHtml(f.category)}</span>
            \${f.line > 0 ? \`<span class="text-xs text-gray-600 mono">line \${f.line}</span>\` : ''}
          </div>
          <p class="text-xs text-gray-500 mb-2">\${escHtml(f.description)}</p>
          <div class="terminal-bg rounded-lg px-3 py-2 mono text-xs overflow-x-auto whitespace-pre-wrap text-gray-300 relative group/snippet">
            \${f.context ? escHtml(f.context) : (f.line > 0 ? f.line + ' │ ' : '') + escHtml(f.snippet)}
            <button onclick="copyWithFeedback(this,\${JSON.stringify(copySnippet)})" class="copy-btn absolute top-1.5 right-1.5 opacity-0 group-hover/snippet:opacity-100 text-xs text-gray-500 hover:text-gray-200 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] px-2 py-0.5 rounded transition-all" title="Copy snippet"><i class="fas fa-copy"></i></button>
          </div>
          <div class="mt-2 flex items-center gap-2 flex-wrap">
            <span class="text-xs text-gray-600 shrink-0">Matched:</span>
            <code class="text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded mono flex-1 min-w-0 truncate" title="\${escHtml(f.match)}">\${escHtml(redacted)}</code>
            <div class="copy-group">
              <button onclick="copyWithFeedback(this,\${JSON.stringify(copySecret)})" class="copy-btn flex items-center gap-1 text-xs text-red-400 hover:text-red-300 bg-red-500/5 hover:bg-red-500/10 border border-red-500/20 hover:border-red-500/40 px-2 py-0.5 rounded transition-all" title="Copy full secret value"><i class="fas fa-key text-xs"></i><span>Secret</span></button>
              <button onclick="copyWithFeedback(this,\${JSON.stringify(copySnippet)})" class="copy-btn flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] px-2 py-0.5 rounded transition-all" title="Copy snippet line"><i class="fas fa-code text-xs"></i><span>Line</span></button>
              <button onclick="copyWithFeedback(this,\${JSON.stringify(copyFull)})" class="copy-btn flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] px-2 py-0.5 rounded transition-all" title="Copy full finding details"><i class="fas fa-file-lines text-xs"></i><span>Full</span></button>
            </div>
          </div>
        </div>
      </div>
    </div>
  \`;
}
function getFileIcon(file){
  if(file.startsWith('[commit:')) return '<i class="fas fa-code-commit text-purple-400 text-sm shrink-0"></i>';
  if(file.match(/\\.env/i)) return '<i class="fas fa-gear text-yellow-400 text-sm shrink-0"></i>';
  if(file.match(/\\.pem|\\.key|\\.crt|\\.cer/i)) return '<i class="fas fa-lock text-red-400 text-sm shrink-0"></i>';
  if(file.match(/\\.json/i)) return '<i class="fas fa-brackets-curly text-blue-400 text-sm shrink-0"></i>';
  if(file.match(/\\.ya?ml/i)) return '<i class="fas fa-database text-cyan-400 text-sm shrink-0"></i>';
  if(file.match(/\\.tf/i)) return '<i class="fas fa-cloud text-purple-400 text-sm shrink-0"></i>';
  if(file.match(/\\.sh|\\.bash/i)) return '<i class="fas fa-terminal text-green-400 text-sm shrink-0"></i>';
  return '<i class="fas fa-file-code text-gray-400 text-sm shrink-0"></i>';
}

function highlightSecret(snippet, match){
  if(!match || match.length < 4) return snippet;
  // Just highlight the snippet area
  return snippet;
}

function redactSecret(secret){
  if(!secret || secret.length <= 8) return '***REDACTED***';
  return secret.substring(0,4) + '•'.repeat(Math.min(secret.length-8, 20)) + secret.substring(secret.length-4);
}

// ─── Severity Filter ──────────────────────────────────────────────────────────
function filterSeverity(sev){
  currentSeverityFilter = sev;
  document.querySelectorAll('.sev-filter').forEach(b => {
    b.classList.remove('active-filter','text-white','border-blue-500/50');
    b.classList.add('text-gray-400');
  });
  const active = document.getElementById('f-' + sev);
  active.classList.add('active-filter','text-white','border-blue-500/50');
  active.classList.remove('text-gray-400');
  renderFindings();
}

// ─── Export ───────────────────────────────────────────────────────────────────
function exportResults(){
  if(!scanResults) return;
  const blob = new Blob([JSON.stringify(scanResults, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'gitleakhunter-report-' + Date.now() + '.json';
  a.click();
  showToast('Report exported!', 'success');
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(s){
  if(!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function copyToClipboard(text){
  navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard', 'success')).catch(() => {});
}

// Copy with visual feedback on the button itself
function copyWithFeedback(btn, text){
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i>';
    btn.classList.add('copied');
    showToast('Copied!', 'success');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 1500);
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); showToast('Copied!', 'success'); } catch {}
    document.body.removeChild(ta);
  });
}

// Copy all findings from a specific file
function copyFileFindings(filename){
  if(!scanResults) return;
  const fileFindings = scanResults.findings.filter(f => f.file === filename);
  if(!fileFindings.length){ showToast('No findings for this file', 'error'); return; }
  const text = fileFindings.map(f =>
    '[' + f.severity.toUpperCase() + '] ' + f.label + ' | File: ' + f.file + ' (line ' + f.line + ') | Category: ' + f.category + ' | Matched: ' + f.match + ' | Snippet: ' + f.snippet
  ).join('\\n---\\n');
  navigator.clipboard.writeText(text).then(() => showToast('Copied ' + fileFindings.length + ' finding(s) from ' + filename, 'success')).catch(() => {});
}

// Copy ALL visible findings as plain text
function copyAllFindings(){
  if(!scanResults) return;
  const filterText = document.getElementById('filter-input').value.toLowerCase();
  let filtered = scanResults.findings.filter(f => {
    if(currentSeverityFilter !== 'all' && f.severity !== currentSeverityFilter) return false;
    if(filterText && !f.file.toLowerCase().includes(filterText) && !f.category.toLowerCase().includes(filterText) && !f.label.toLowerCase().includes(filterText)) return false;
    return true;
  });
  if(!filtered.length){ showToast('No findings to copy', 'error'); return; }
  const sep = '='.repeat(60);
  const repo = (scanResults.meta && scanResults.meta.repo) ? scanResults.meta.repo : 'unknown';
  const header = 'GitLeakHunter Scan Report - ' + repo + ' | Total: ' + filtered.length + ' findings | ' + sep + ' ';
  const text = header + filtered.map(function(f,i){
    return '#' + (i+1) + ' [' + f.severity.toUpperCase() + '] ' + f.label + ' | File: ' + f.file + ' (line ' + f.line + ') | Category: ' + f.category + ' | Matched: ' + f.match + ' | Snippet: ' + f.snippet;
  }).join('\\n---\\n');
  navigator.clipboard.writeText(text).then(() => showToast('Copied ' + filtered.length + ' findings to clipboard', 'success')).catch(() => {});
}

function showToast(msg, type='success'){
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = \`fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium glass border \${type === 'error' ? 'border-red-500/30 text-red-400' : 'border-green-500/30 text-green-400'}\`;
  t.classList.remove('hidden');
  setTimeout(()=> t.classList.add('hidden'), 2500);
}

function hideResults(){
  document.getElementById('results-section').classList.add('hidden');
}

function hideError(){
  document.getElementById('error-section').classList.add('hidden');
}

function showError(msg){
  document.getElementById('error-section').classList.remove('hidden');
  document.getElementById('error-msg').textContent = msg;
  document.getElementById('error-section').scrollIntoView({behavior:'smooth', block:'center'});
}

// ─── Pattern Library ──────────────────────────────────────────────────────────
async function loadPatterns(){
  try {
    const resp = await fetch('/api/patterns');
    const patterns = await resp.json();
    allPatterns = patterns;
    document.getElementById('stat-patterns').textContent = patterns.length;
    document.getElementById('pattern-count').textContent = patterns.length + ' patterns';
    
    const sevColors = { critical:'red', high:'orange', medium:'yellow', low:'green' };
    const grid = document.getElementById('patterns-grid');
    grid.innerHTML = patterns.map(p => \`
      <div class="glass rounded-xl p-4 hover:border-[#484f58] border border-[#30363d] transition-colors group">
        <div class="flex items-start gap-3">
          <span class="text-xl shrink-0">\${p.icon}</span>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1 flex-wrap">
              <span class="text-sm font-semibold text-white">\${escHtml(p.label)}</span>
              <span class="badge-\${p.severity} text-xs px-1.5 py-0.5 rounded-full">\${p.severity}</span>
            </div>
            <p class="text-xs text-gray-500 mb-2">\${escHtml(p.description)}</p>
            <span class="category-chip bg-[#21262d] border border-[#30363d] text-gray-500">\${escHtml(p.category)}</span>
          </div>
        </div>
      </div>
    \`).join('');
  } catch(e) {
    document.getElementById('patterns-grid').innerHTML = '<p class="text-gray-500 text-sm col-span-3">Failed to load patterns</p>';
  }
}

// Enter key to scan
document.getElementById('github-url').addEventListener('keydown', e => { if(e.key === 'Enter') startGithubScan(); });

// Init
loadPatterns();
loadTgConfig();
</script>
</body>
</html>`)
})

export default app
