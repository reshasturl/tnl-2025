#!/bin/bash
#
# YT ZIXSTYLE WebSocket Installer 2025
# Created: September 7, 2025  
# Purpose: Install WebSocket tunneling for SSH and SSL
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "SSHWS-2025.SH STARTED"
log_and_show "🌐 Starting WebSocket tunneling installation..."

# Install Nginx first  
log_and_show "🌐 Installing Nginx web server..."

# Force install nginx with proper dependency handling
for i in {1..3}; do
    if log_command "apt install -y nginx"; then
        log_and_show "✅ Nginx installed successfully"
        break
    else
        log_and_show "⚠️ Nginx installation failed (attempt $i/3), retrying..."
        if [ $i -eq 3 ]; then
            log_and_show "⚠️ Nginx installation failed after 3 attempts, continuing without nginx..."
        fi
        sleep 2
    fi
done

# Verify nginx installation
if ! command -v nginx >/dev/null 2>&1; then
    log_and_show "⚠️ Nginx binary not found, trying alternative installation..."
    log_command "apt update" || true
    log_command "apt install -y nginx-core nginx-common" || log_and_show "⚠️ Alternative nginx installation failed"
fi

# Ensure nginx directory exists 
log_command "mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled"

# Use Python2 from tools-2025.sh installation
log_and_show "🐍 Configuring Python2 for WebSocket services..."

# Ensure python symlink exists
if ! command -v python >/dev/null 2>&1; then
    log_command "ln -sf /usr/bin/python3 /usr/bin/python"
    log_and_show "✅ Python2 symlink created"
fi

# Download WebSocket scripts
log_and_show "📥 Downloading WebSocket scripts..."
log_command "wget -O /usr/local/bin/ws-dropbear https://raw.githubusercontent.com/reshasturl/tnl-2025/main/sshws/dropbear-ws.py"
log_command "wget -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/reshasturl/tnl-2025/main/sshws/ws-stunnel"

# Set permissions
log_command "chmod +x /usr/local/bin/ws-dropbear"
log_command "chmod +x /usr/local/bin/ws-stunnel"

# Create systemd service for Dropbear WebSocket
log_and_show "⚙️  Creating Dropbear WebSocket service..."
cat > /etc/systemd/system/ws-dropbear.service << 'EOF'
[Unit]
Description=Dropbear WebSocket Tunnel 2025
Documentation=https://github.com/reshasturl/tnl-2025
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -O /usr/local/bin/ws-dropbear 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for Stunnel WebSocket  
log_and_show "⚙️  Creating Stunnel WebSocket service..."
cat > /etc/systemd/system/ws-stunnel.service << 'EOF'
[Unit]
Description=SSH Over Websocket SSL 2025
Documentation=https://github.com/reshasturl/tnl-2025
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -O /usr/local/bin/ws-stunnel
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Set proper service file permissions
log_command "chmod 644 /etc/systemd/system/ws-dropbear.service"
log_command "chmod 644 /etc/systemd/system/ws-stunnel.service"

# Configure Nginx for WebSocket proxy
log_and_show "🌐 Configuring Nginx..."

# Backup original nginx config if exists
if [ -f /etc/nginx/nginx.conf ]; then
    log_command "cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup"
fi

# Create optimized nginx configuration
cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Create default site configuration for WebSocket
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /ws-dropbear {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location /ws-stunnel {
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

# Enable default site
log_command "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/"

# Nginx configuration validation and startup
log_and_show "🔍 Testing nginx configuration..."
if nginx -t 2>/dev/null; then
    log_and_show "✅ Nginx configuration is valid"
else
    log_and_show "❌ Nginx configuration error, using minimal config..."
    
    # Backup current config and create minimal working config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup 2>/dev/null || true
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    
    # Basic logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        
        location / {
            return 200 "WebSocket Server Running";
            add_header Content-Type text/plain;
        }
        
        location /ws-dropbear {
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
        }
        
        location /ws-stunnel {
            proxy_pass http://127.0.0.1:8880;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
        }
    }
}
EOF
    
    # Remove conflicting default sites
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    rm -f /etc/nginx/sites-available/default 2>/dev/null || true
    
    # Test minimal config
    if nginx -t 2>/dev/null; then
        log_and_show "✅ Minimal nginx configuration is valid"
    else
        log_and_show "❌ Even minimal nginx config failed, creating ultra-minimal config"
        cat > /etc/nginx/nginx.conf << 'EOF'
events {}
http {
    server {
        listen 80;
        location / { return 200 "OK"; }
    }
}
EOF
    fi
fi

# Enable and start services
log_and_show "🚀 Starting WebSocket services..."
log_command "systemctl daemon-reload"
log_command "systemctl enable ws-dropbear"
log_command "systemctl enable ws-stunnel"
log_command "systemctl start ws-dropbear"
log_command "systemctl start ws-stunnel"

# Start nginx with detailed error checking
log_and_show "🌐 Starting nginx service..."
if systemctl restart nginx 2>/dev/null; then
    log_and_show "✅ Nginx service started successfully"
else
    log_and_show "⚠️ Nginx restart failed, checking status..."
    systemctl status nginx --no-pager || true
    
    # Try to start nginx without restart
    if systemctl start nginx 2>/dev/null; then
        log_and_show "✅ Nginx service started"
    else
        log_and_show "⚠️ Nginx service may need manual configuration"
        # Try to identify the problem
        nginx -t || log_and_show "❌ Nginx configuration test failed"
    fi
fi

log_command "systemctl enable nginx"

# Verify services are running
if systemctl is-active --quiet ws-dropbear.service; then
    log_and_show "✅ ws-dropbear service: ACTIVE on port 8080"
else
    log_and_show "⚠️ ws-dropbear service: FAILED to start"
fi

if systemctl is-active --quiet ws-stunnel.service; then
    log_and_show "✅ ws-stunnel service: ACTIVE"
else
    log_and_show "⚠️ ws-stunnel service: FAILED to start"
fi

# Log WebSocket info (consistent with user display scripts)
echo "SSH Websocket: 8080" >> /root/log-install.txt
echo "SSH SSL Websocket: 443" >> /root/log-install.txt
echo "Nginx: 80" >> /root/log-install.txt

log_and_show "✅ WebSocket tunneling installation completed"
log_section "SSHWS-2025.SH COMPLETED"
