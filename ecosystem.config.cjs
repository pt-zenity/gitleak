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
