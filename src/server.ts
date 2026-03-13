import { serve } from '@hono/node-server'
import app from './index.js'

const PORT = Number(process.env.PORT) || 3000
const HOST = process.env.HOST || '0.0.0.0'

serve(
  {
    fetch: app.fetch,
    port: PORT,
    hostname: HOST,
  },
  (info) => {
    console.log(`\x1b[32m✅ GitLeakHunter running on http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${info.port}\x1b[0m`)
    console.log(`\x1b[36m   Press Ctrl+C to stop\x1b[0m`)
  }
)
