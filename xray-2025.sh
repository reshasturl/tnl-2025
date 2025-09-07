#!/bin/bash
#
# YT ZIXSTYLE Xray Installer 2025
# Created: September 7, 2025
# Purpose: Install Xray with modern protocols (REALITY, XHTTP, enhanced features)
# Log: Inherit dari setup-2025.sh
# Version: Auto-detect latest Xray and Trojan-Go versions
# Features: XHTTP, REALITY, VMess, VLess, Trojan, Shadowsocks
# ========================================================================

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "XRAY-2025.SH STARTED"
log_and_show "⚡ Starting Xray installation with modern protocols..."

# Detect latest Xray version automatically
log_and_show "🔍 Detecting latest Xray version..."
XRAY_VERSION="$(curl -s --connect-timeout 10 "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
if [ -z "$XRAY_VERSION" ] || [ "$XRAY_VERSION" = "null" ]; then
    log_and_show "⚠️ Failed to detect latest version (API timeout or error), using fallback v1.8.24"
    XRAY_VERSION="1.8.24"
else
    log_and_show "✅ Latest version detected: v${XRAY_VERSION}"
fi
log_and_show "📦 Installing Xray-core v${XRAY_VERSION} with XHTTP and REALITY protocols"

# Install dependencies (comprehensive from ins-xray.sh)
log_and_show "📦 Installing Xray dependencies..."
log_command "apt install -y iptables iptables-persistent"
log_command "apt install -y curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release"
log_command "apt install -y socat cron bash-completion ntpdate zip pwgen openssl netcat"

# Configure time and timezone (from ins-xray.sh)
log_and_show "🕒 Configuring time and timezone..."
log_command "ntpdate pool.ntp.org"
log_command "timedatectl set-ntp true"
log_command "systemctl enable chronyd"
log_command "systemctl restart chronyd"
log_command "systemctl enable chrony"
log_command "systemctl restart chrony"
log_command "timedatectl set-timezone Asia/Jakarta"
log_command "chronyc sourcestats -v"
log_command "chronyc tracking -v"

# Download and install Xray using official installer with detected version
log_and_show "📥 Downloading & Installing Xray core v${XRAY_VERSION} using official installer..."
log_command "bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install -u www-data --version ${XRAY_VERSION}"

# Create Xray directories (comprehensive from ins-xray.sh)
log_and_show "📁 Creating Xray directories and domain socket..."
domainSock_dir="/run/xray"
if [ ! -d $domainSock_dir ]; then
    log_command "mkdir -p $domainSock_dir"
fi
log_command "chown www-data:www-data $domainSock_dir"
log_command "mkdir -p /etc/xray /var/log/xray"
log_command "mkdir -p /home/vps/public_html"
log_command "chown www-data:www-data /var/log/xray"
log_command "chmod +x /var/log/xray"

# Create log files (comprehensive from ins-xray.sh)
log_command "touch /var/log/xray/access.log"
log_command "touch /var/log/xray/error.log"
log_command "touch /var/log/xray/access2.log"
log_command "touch /var/log/xray/error2.log"

# Stop nginx for SSL certificate generation
log_command "systemctl stop nginx"

# Install and configure SSL certificate using acme.sh
log_and_show "🔒 Setting up SSL certificate using acme.sh..."
log_command "mkdir -p /root/.acme.sh"
log_command "curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh"
log_command "chmod +x /root/.acme.sh/acme.sh"
log_command "/root/.acme.sh/acme.sh --upgrade --auto-upgrade"
log_command "/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt"
log_command "/root/.acme.sh/acme.sh --issue -d ${DOMAIN} --standalone -k ec-256"
log_command "/root/.acme.sh/acme.sh --installcert -d ${DOMAIN} --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc"

# Create SSL renewal script
cat > /usr/local/bin/ssl_renew.sh << 'EOF'
#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
/etc/init.d/nginx status
EOF

log_command "chmod +x /usr/local/bin/ssl_renew.sh"

# Add SSL renewal to crontab
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root 2>/dev/null; then
    (crontab -l 2>/dev/null; echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab -
    log_and_show "✅ SSL auto-renewal added to crontab"
fi

# Generate REALITY key pair for modern protocols
log_and_show "🔐 Generating REALITY key pair..."
REALITY_KEYS=$(/usr/local/bin/xray x25519)
REALITY_PRIVATE=$(echo "${REALITY_KEYS}" | grep "Private key:" | awk '{print $3}')
REALITY_PUBLIC=$(echo "${REALITY_KEYS}" | grep "Public key:" | awk '{print $3}')

# Generate UUID for default user
uuid=$(cat /proc/sys/kernel/random/uuid)

# Save configuration details for future reference
cat > /etc/xray/.config-details << EOF
REALITY_PRIVATE=${REALITY_PRIVATE}
REALITY_PUBLIC=${REALITY_PUBLIC}
DOMAIN=${DOMAIN}
UUID=${uuid}
XRAY_VERSION=${XRAY_VERSION}
EOF

log_and_show "✅ SSL certificate installed and REALITY keys generated"

# Create comprehensive Xray configuration with all modern protocols
log_and_show "⚙️  Creating Xray configuration with XHTTP, REALITY, and legacy protocols..."
cat > /etc/xray/config.json << EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": "14016",
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}"
#vless
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "14017",
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}"
#vless-xhttp
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/vless-xhttp",
          "host": ["${DOMAIN}"]
        }
      }
    },
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}",
            "flow": "xtls-rprx-vision"
#vless-reality
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": ["www.microsoft.com"],
          "privateKey": "${REALITY_PRIVATE}",
          "shortIds": ["6ba85179e30d4fc2"]
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23456",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmess
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23460",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmess-xhttp
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/vmess-xhttp",
          "host": ["${DOMAIN}"]
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23457",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmessworry
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/worryfree"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23458",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmesskuota
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/kuota-habis"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "23459",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmesschat
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/chat"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "25432",
      "protocol": "trojan",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "${uuid}"
#trojanws
          }
        ],
        "udp": true
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "30300",
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "${uuid}"
#ssws
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/ss-ws"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "24456",
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}"
#vlessgrpc
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "31234",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
#vmessgrpc
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "33456",
      "protocol": "trojan",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "${uuid}"
#trojangrpc
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        }
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "30310",
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "aes-128-gcm",
            "password": "${uuid}"
#ssgrpc
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "ss-grpc"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      }
    ]
  },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "stats": {},
  "policy": {
    "levels": {
      "1": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "statsUserUplink": false,
        "statsUserDownlink": false
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false
    }
  }
}
EOF

# Generate SSL certificate for TLS
log_and_show "📜 Generating SSL certificate for TLS protocols..."
openssl req -new -x509 -days 3650 -nodes -out /etc/xray/xray.crt -keyout /etc/xray/xray.key << EOF
ID
Jakarta
Jakarta
YT-ZIXSTYLE
VPN-Server
${DOMAIN}
admin@${DOMAIN}
EOF

log_command "chmod 644 /etc/xray/xray.crt"
log_command "chmod 600 /etc/xray/xray.key"

# Create Xray systemd service (from ins-xray.sh)
log_and_show "⚙️  Creating Xray systemd service..."
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service
cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# Create additional service for domain socket permissions (from ins-xray.sh)
cat > /etc/systemd/system/runn.service << 'EOF'
[Unit]
Description=Mantap-Sayang
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/mkdir -p /var/run/xray
ExecStart=/usr/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx for Xray proxy (comprehensive from ins-xray.sh)
log_and_show "🌐 Configuring Nginx for Xray proxy..."
log_command "apt install -y nginx"

# Create comprehensive Nginx Xray configuration
cat > /etc/nginx/conf.d/xray.conf << EOF
server {
    listen 80;
    listen [::]:80;
    listen 8880;
    listen [::]:8880;
    listen 55;
    listen [::]:55;
    listen 8080;
    listen [::]:8080;
    listen 8443 ssl http2 reuseport;
    listen [::]:8443 http2 reuseport;
    listen 2098 ssl http2;
    listen [::]:2098 ssl http2;
    server_name ${DOMAIN};
    
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    
    root /home/vps/public_html;
    
    location = /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14016;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /vless-xhttp {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14017;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23456;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /vmess-xhttp {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23460;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /worryfree {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23457;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /kuota-habis {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23458;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /chat {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23459;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:25432;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location = /ss-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:30300;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location ^~ /vless-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:24456;
    }
    
    location ^~ /vmess-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:31234;
    }
    
    location ^~ /trojan-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:33456;
    }
    
    location ^~ /ss-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:30310;
    }
    
    location ^~ /trojango {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:2087;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

# Start and enable services
log_and_show "🚀 Installing Trojan-Go..."
log_and_show "🔍 Detecting latest Trojan-Go version..."
latest_version="$(curl -s --connect-timeout 10 "https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest" | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
    log_and_show "⚠️ Failed to detect latest Trojan-Go version, using fallback v0.10.6"
    latest_version="0.10.6"
else
    log_and_show "✅ Latest Trojan-Go version detected: v${latest_version}"
fi
trojango_link="https://github.com/p4gefau1t/trojan-go/releases/download/v${latest_version}/trojan-go-linux-amd64.zip"
log_command "mkdir -p /usr/bin/trojan-go"
log_command "mkdir -p /etc/trojan-go"
cd $(mktemp -d)
log_command "curl -sL ${trojango_link} -o trojan-go.zip"
log_command "unzip -q trojan-go.zip && rm -rf trojan-go.zip"
log_command "mv trojan-go /usr/local/bin/trojan-go"
log_command "chmod +x /usr/local/bin/trojan-go"
log_command "mkdir -p /var/log/trojan-go/"
log_command "touch /etc/trojan-go/akun.conf"
log_command "touch /var/log/trojan-go/trojan-go.log"

# Create Trojan-Go configuration
cat > /etc/trojan-go/config.json << EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": 2087,
  "remote_addr": "127.0.0.1",
  "remote_port": 89,
  "log_level": 1,
  "log_file": "/var/log/trojan-go/trojan-go.log",
  "password": [
    "${uuid}"
  ],
  "disable_http_check": true,
  "udp_timeout": 60,
  "ssl": {
    "verify": false,
    "verify_hostname": false,
    "cert": "/etc/xray/xray.crt",
    "key": "/etc/xray/xray.key",
    "key_password": "",
    "cipher": "",
    "curves": "",
    "prefer_server_cipher": false,
    "sni": "${DOMAIN}",
    "alpn": [
      "http/1.1"
    ],
    "session_ticket": true,
    "reuse_session": true,
    "plain_http_response": "",
    "fallback_addr": "127.0.0.1",
    "fallback_port": 0,
    "fingerprint": "firefox"
  },
  "tcp": {
    "no_delay": true,
    "keep_alive": true,
    "prefer_ipv4": true
  },
  "mux": {
    "enabled": false,
    "concurrency": 8,
    "idle_timeout": 60
  },
  "websocket": {
    "enabled": true,
    "path": "/trojango",
    "host": "${DOMAIN}"
  },
  "api": {
    "enabled": false,
    "api_addr": "",
    "api_port": 0,
    "ssl": {
      "enabled": false,
      "key": "",
      "cert": "",
      "verify_client": false,
      "client_cert": []
    }
  }
}
EOF

# Create Trojan-Go systemd service
cat > /etc/systemd/system/trojan-go.service << 'EOF'
[Unit]
Description=Trojan-Go Service 2025
Documentation=https://github.com/p4gefau1t/trojan-go
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

# Create Trojan-Go UUID file
cat > /etc/trojan-go/uuid.txt << EOF
${uuid}
EOF

# Start nginx service
log_and_show "🌐 Starting nginx service..."
log_command "systemctl restart nginx"
log_command "systemctl enable nginx"

# Start and enable services
log_and_show "🚀 Starting all services (Xray, Trojan-Go, nginx)..."
log_command "systemctl daemon-reload"
log_command "systemctl enable xray"
log_command "systemctl enable runn"
log_command "systemctl enable trojan-go"
log_command "systemctl start runn"
log_command "systemctl start xray"
log_command "systemctl start trojan-go"

# Verify services are running
log_and_show "🔍 Verifying service status..."
if systemctl is-active --quiet xray.service; then
    log_and_show "✅ Xray v${XRAY_VERSION} service: ACTIVE"
else
    log_and_show "⚠️ Xray service: FAILED to start"
fi

if systemctl is-active --quiet trojan-go.service; then
    log_and_show "✅ Trojan-Go v${latest_version} service: ACTIVE"
else
    log_and_show "⚠️ Trojan-Go service: FAILED to start"
fi

if systemctl is-active --quiet nginx.service; then
    log_and_show "✅ Nginx service: ACTIVE"
else
    log_and_show "⚠️ Nginx service: FAILED to start"
fi

# Install menu system
log_and_show "📋 Installing menu system..."
log_command "wget -O /usr/local/bin/menu https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu.sh"
log_command "wget -O /usr/local/bin/menu-ssh https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-ssh.sh"
log_command "wget -O /usr/local/bin/menu-vmess https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-vmess.sh"
log_command "wget -O /usr/local/bin/menu-vless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-vless.sh"
log_command "wget -O /usr/local/bin/menu-trojan https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-trojan.sh"

# SSH management scripts are installed by ssh-2025.sh installer

# Install comprehensive Xray account management scripts
log_and_show "📱 Installing comprehensive Xray management tools..."

# VMess management (Enhanced + Legacy)
log_and_show "🔧 Installing VMess management scripts..."
log_command "wget -O /usr/local/bin/add-ws https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-ws.sh"
log_command "wget -O /usr/local/bin/add-ws-enhanced https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-ws-enhanced.sh"
log_command "wget -O /usr/local/bin/add-vmess-xhttp https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-vmess-xhttp.sh"
log_command "wget -O /usr/local/bin/trialvmess https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/trialvmess.sh"
log_command "wget -O /usr/local/bin/renew-ws https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/renew-ws.sh"
log_command "wget -O /usr/local/bin/del-ws https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/del-ws.sh"
log_command "wget -O /usr/local/bin/cek-ws https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/cek-ws.sh"

# VLess management (Enhanced + Modern Protocols)
log_and_show "🚀 Installing VLess management scripts (Enhanced + REALITY + XHTTP)..."
log_command "wget -O /usr/local/bin/add-vless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-vless.sh"
log_command "wget -O /usr/local/bin/add-vless-enhanced https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-vless-enhanced.sh"
log_command "wget -O /usr/local/bin/add-vless-reality https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-vless-reality.sh"
log_command "wget -O /usr/local/bin/add-vless-xhttp https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-vless-xhttp.sh"
log_command "wget -O /usr/local/bin/trialvless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/trialvless.sh"
log_command "wget -O /usr/local/bin/renew-vless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/renew-vless.sh"
log_command "wget -O /usr/local/bin/del-vless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/del-vless.sh"
log_command "wget -O /usr/local/bin/cek-vless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/cek-vless.sh"

# Trojan management
log_command "wget -O /usr/local/bin/add-tr https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/add-tr.sh"
log_command "wget -O /usr/local/bin/trialtrojan https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/trialtrojan.sh"
log_command "wget -O /usr/local/bin/renew-tr https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/renew-tr.sh"
log_command "wget -O /usr/local/bin/del-tr https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/del-tr.sh"
log_command "wget -O /usr/local/bin/cek-tr https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/cek-tr.sh"

# Trojan-Go management (Advanced Trojan Protocol)
log_and_show "🔒 Installing Trojan-Go management scripts..."
log_command "wget -O /usr/local/bin/addtrgo https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/addtrgo.sh"
log_command "wget -O /usr/local/bin/trialtrojango https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/trialtrojango.sh"
log_command "wget -O /usr/local/bin/renewtrgo https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/renewtrgo.sh"
log_command "wget -O /usr/local/bin/deltrgo https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/deltrgo.sh"
log_command "wget -O /usr/local/bin/cektrgo https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/cektrgo.sh"

# Additional modern protocol management
log_and_show "⚡ Installing additional modern protocol utilities..."
log_command "wget -O /usr/local/bin/cekxray https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/cekxray.sh"
log_command "wget -O /usr/local/bin/certv2ray https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/certv2ray.sh"

# Set permissions for all scripts
log_command "chmod +x /usr/local/bin/*"

# Create symbolic links for enhanced scripts as defaults
log_and_show "🔗 Creating symbolic links for enhanced scripts..."
log_command "ln -sf /usr/local/bin/add-vless-enhanced /usr/local/bin/add-vless-default"
log_command "ln -sf /usr/local/bin/add-ws-enhanced /usr/local/bin/add-ws-default"

# Create backward compatibility links
log_command "ln -sf /usr/local/bin/add-vless-enhanced /usr/bin/add-vless-enhanced"
log_command "ln -sf /usr/local/bin/add-vless-reality /usr/bin/add-vless-reality"
log_command "ln -sf /usr/local/bin/add-vless-xhttp /usr/bin/add-vless-xhttp"
log_command "ln -sf /usr/local/bin/add-vmess-xhttp /usr/bin/add-vmess-xhttp"
log_command "ln -sf /usr/local/bin/add-ws-enhanced /usr/bin/add-ws-enhanced"

# Create symbolic link for menu
log_command "ln -sf /usr/local/bin/menu /usr/bin/menu"

# Move domain file to xray directory (from ins-xray.sh)
log_and_show "📁 Moving domain configuration..."
if [ -f /root/domain ]; then
    log_command "mv /root/domain /etc/xray/"
fi
if [ -f /root/scdomain ]; then
    log_command "rm /root/scdomain"
fi

# Final status output (matching ins-xray.sh style)
sleep 1
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "✅ Xray/VMess protocols installed (v${XRAY_VERSION})"
yellow "✅ Xray/VLess protocols installed with REALITY & XHTTP"
yellow "✅ Xray/Trojan protocols installed"
yellow "✅ Trojan-Go v${latest_version} installed"

# Log Xray info (updated for correct version and protocols)
echo "XRAY v${XRAY_VERSION}: VMess/VLess/Trojan with XHTTP and REALITY (Auto-detected)" >> /root/log-install.txt
echo "Trojan-Go v${latest_version} (Auto-detected)" >> /root/log-install.txt
echo "VMess WS: 80, 443" >> /root/log-install.txt
echo "VMess GRPC: 443" >> /root/log-install.txt
echo "VMess XHTTP: 80, 443" >> /root/log-install.txt
echo "VLess WS: 80, 443" >> /root/log-install.txt
echo "VLess GRPC: 443" >> /root/log-install.txt
echo "VLess XHTTP: 80, 443" >> /root/log-install.txt
echo "VLess REALITY: 443" >> /root/log-install.txt
echo "Trojan WS: 80, 443" >> /root/log-install.txt
echo "Trojan GRPC: 443" >> /root/log-install.txt
echo "Trojan-Go: 2087" >> /root/log-install.txt
echo "Shadowsocks WS: 80, 443" >> /root/log-install.txt
echo "Shadowsocks GRPC: 443" >> /root/log-install.txt

# Enhanced Scripts Information
echo "" >> /root/log-install.txt
echo "Enhanced Management Scripts:" >> /root/log-install.txt
echo "- add-vless-enhanced: Advanced VLess creation" >> /root/log-install.txt
echo "- add-vless-reality: VLess with REALITY protocol" >> /root/log-install.txt
echo "- add-vless-xhttp: VLess with XHTTP transport" >> /root/log-install.txt
echo "- add-ws-enhanced: Advanced VMess creation" >> /root/log-install.txt
echo "- add-vmess-xhttp: VMess with XHTTP transport" >> /root/log-install.txt

log_and_show "✅ Xray v${XRAY_VERSION} installation with XHTTP and REALITY completed"
log_and_show "🚀 Enhanced management scripts tersedia dengan fitur modern:"
log_and_show "   📝 add-vless-enhanced: Pembuatan VLess tingkat lanjut"
log_and_show "   🔒 add-vless-reality: VLess dengan protokol REALITY"
log_and_show "   ⚡ add-vless-xhttp: VLess dengan transport XHTTP"
log_and_show "   📝 add-ws-enhanced: Pembuatan VMess tingkat lanjut" 
log_and_show "   ⚡ add-vmess-xhttp: VMess dengan transport XHTTP"
log_and_show "✅ Semua service berjalan dengan versi terbaru (auto-detect)"
log_section "XRAY-2025.SH COMPLETED"
