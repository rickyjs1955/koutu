// backend/src/config/nginx.ts
// Nginx configuration for production deployment

export const nginxConfig = `
# /etc/nginx/sites-available/koutu-backend
# Nginx configuration for Koutu Fashion Backend API

# Rate limiting zones - customize based on your needs
limit_req_zone $binary_remote_addr zone=api:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=files:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=images:10m rate=20r/s;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=perip:10m;

# Upstream Node.js backend servers
upstream nodejs_backend {
    least_conn;
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    # Add more servers for load balancing:
    # server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    # server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# Main server configuration
server {
    listen 80;
    listen [::]:80;
    server_name your-domain.com www.your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your-domain.com www.your-domain.com;
    
    # SSL Configuration (replace with your certificate paths)
    ssl_certificate /etc/ssl/certs/your-domain.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
    
    # Hide server version
    server_tokens off;
    
    # Basic bot protection
    if ($http_user_agent ~* (bot|crawler|spider|scraper)) {
        return 429;
    }
    
    # Block common attack patterns
    location ~ /\\. {
        deny all;
    }
    
    location ~ \\.(env|git|svn|log)$ {
        deny all;
    }
    
    # Health check endpoint (bypass rate limiting)
    location = /health {
        access_log off;
        proxy_pass http://nodejs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Authentication endpoints (strict rate limiting)
    location ~ ^/api/v1/auth/ {
        limit_req zone=auth burst=3 nodelay;
        limit_conn perip 3;
        
        # Enhanced security for auth
        client_max_body_size 1M;
        client_body_timeout 10s;
        client_header_timeout 10s;
        
        proxy_pass http://nodejs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_http_version 1.1;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
    
    # File upload endpoints (moderate rate limiting, large body size)
    location ~ ^/api/v1/(files|images)/ {
        limit_req zone=files burst=5 nodelay;
        limit_conn perip 2;
        
        # File upload configuration
        client_max_body_size 50M;
        client_body_timeout 60s;
        client_header_timeout 10s;
        client_body_buffer_size 128k;
        
        # Proxy configuration for file uploads
        proxy_pass http://nodejs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_http_version 1.1;
        
        # Extended timeouts for file uploads
        proxy_connect_timeout 10s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Buffering for large uploads
        proxy_request_buffering off;
        proxy_buffering off;
    }
    
    # Image serving endpoints (higher rate limit for static content)
    location ~ ^/api/v1/files/.*\\.(jpg|jpeg|png|bmp|gif|webp)$ {
        limit_req zone=images burst=10 nodelay;
        limit_conn perip 5;
        
        # Caching for images
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options nosniff;
        
        proxy_pass http://nodejs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_cache_control;
    }
    
    # General API endpoints (standard rate limiting)
    location ~ ^/api/v1/ {
        limit_req zone=api burst=20 nodelay;
        limit_conn perip 10;
        
        # Standard API configuration
        client_max_body_size 10M;
        client_body_timeout 30s;
        client_header_timeout 10s;
        
        proxy_pass http://nodejs_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_http_version 1.1;
        
        # Standard timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    # Static file serving (if any)
    location /static/ {
        alias /var/www/koutu/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
        gzip_static on;
    }
    
    # Deny all other requests
    location / {
        return 404;
    }
    
    # Custom error pages
    error_page 429 /errors/429.html;
    error_page 500 502 503 504 /errors/50x.html;
    
    location = /errors/429.html {
        root /var/www/koutu/;
        internal;
    }
    
    location = /errors/50x.html {
        root /var/www/koutu/;
        internal;
    }
}

# Additional configuration for gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_proxied any;
gzip_comp_level 6;
gzip_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/json
    application/javascript
    application/xml+rss
    application/atom+xml
    image/svg+xml;
`;

export const nginxInstallScript = `#!/bin/bash
# Install and configure Nginx for Koutu Backend

# Install Nginx
sudo apt update
sudo apt install nginx -y

# Create directory for custom configs
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled
sudo mkdir -p /var/www/koutu/static
sudo mkdir -p /var/www/koutu/errors

# Create error pages
cat > /var/www/koutu/errors/429.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Rate Limited</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .error { color: #e74c3c; }
    </style>
</head>
<body>
    <h1 class="error">Rate Limited</h1>
    <p>Too many requests. Please try again later.</p>
</body>
</html>
EOF

cat > /var/www/koutu/errors/50x.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Server Error</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .error { color: #e74c3c; }
    </style>
</head>
<body>
    <h1 class="error">Server Error</h1>
    <p>Something went wrong. Please try again later.</p>
</body>
</html>
EOF

# Set permissions
sudo chown -R www-data:www-data /var/www/koutu
sudo chmod -R 755 /var/www/koutu

# Create the nginx config file
sudo tee /etc/nginx/sites-available/koutu-backend > /dev/null << 'EOF'
# Paste the nginxConfig content here
EOF

# Enable the site
sudo ln -sf /etc/nginx/sites-available/koutu-backend /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx

echo "Nginx configuration complete!"
echo "Remember to:"
echo "1. Update SSL certificate paths"
echo "2. Update domain name"
echo "3. Adjust rate limits based on your needs"
`;

export const nginxDockerCompose = `
# docker-compose.nginx.yml
# Docker Compose configuration for Nginx + Node.js

version: '3.8'

services:
  nginx:
    image: nginx:alpine
    container_name: koutu-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
      - ./errors:/var/www/koutu/errors:ro
    depends_on:
      - nodejs-app
    restart: unless-stopped
    
  nodejs-app:
    build: .
    container_name: koutu-backend
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
    restart: unless-stopped
    
networks:
  default:
    name: koutu-network
`;

// Configuration object for programmatic use
export const nginxConfiguration = {
  rateLimits: {
    api: { rate: '50r/s', burst: 20 },
    auth: { rate: '5r/s', burst: 3 },
    files: { rate: '10r/s', burst: 5 },
    images: { rate: '20r/s', burst: 10 }
  },
  
  connectionLimits: {
    perIP: 10,
    auth: 3,
    files: 2,
    images: 5
  },
  
  bodySizeLimits: {
    auth: '1M',
    files: '50M',
    api: '10M'
  },
  
  timeouts: {
    auth: { body: '10s', header: '10s', proxy: '10s' },
    files: { body: '60s', header: '10s', proxy: '120s' },
    api: { body: '30s', header: '10s', proxy: '30s' }
  },
  
  security: {
    hideVersion: true,
    blockBots: true,
    blockHiddenFiles: true,
    sslRedirect: true,
    hstsMaxAge: 31536000
  }
};

export default {
  nginxConfig,
  nginxInstallScript,
  nginxDockerCompose,
  nginxConfiguration
};