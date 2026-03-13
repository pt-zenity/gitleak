module.exports = {
  apps: [
    {
      name: 'gitleakhunter',
      script: 'node',
      args: 'dist/server.js',
      cwd: '/home/user/webapp',
      env: {
        NODE_ENV: 'production',
        HTTP_PORT: 80,
        HTTPS_PORT: 443,
        HOST: '0.0.0.0',
        // SSL_MODE options:
        //   'auto'        → auto-detect: Cloudflare Origin Cert → custom → Let's Encrypt → HTTP only
        //   'cloudflare'  → wajib pakai Cloudflare Origin Certificate (Full/Full Strict)
        //   'flexible'    → HTTP only, Cloudflare handle HTTPS (Flexible SSL)
        //   'letsencrypt' → pakai Let's Encrypt cert
        //   'custom'      → pakai SSL_KEY + SSL_CERT path
        SSL_MODE: 'auto',

        // Path Cloudflare Origin Certificate (default)
        // Download dari: Cloudflare Dashboard → SSL/TLS → Origin Server → Create Certificate
        CF_ORIGIN_KEY:  '/etc/ssl/cloudflare/origin.key',
        CF_ORIGIN_CERT: '/etc/ssl/cloudflare/origin.pem',

        // Uncomment jika pakai custom cert:
        // SSL_KEY:  '/path/to/privkey.pem',
        // SSL_CERT: '/path/to/fullchain.pem',

        // Uncomment jika pakai Let's Encrypt:
        // DOMAIN: 'example.com',
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 15,
      restart_delay: 3000,
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
    }
  ]
}
