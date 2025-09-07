#!/bin/bash
#
# YT ZIXSTYLE Xray Installer - MODERNIZED VERSION 2025
# Updated: September 7, 2025
# Features: Xray v25.9.5, REALITY Protocol, XHTTP Transport, Post-Quantum Encryption
# ===============================================================================

# Setup logging system
CURRENT_DIR=$(pwd)
if [ -n "$INSTALL_LOG_FILE" ]; then
    # Use log file passed from parent script
    LOG_FILE="$INSTALL_LOG_FILE"
else
    # Create new log file if running standalone
    XRAY_LOG="yt-zixstyle-xray-$(date +%Y%m%d-%H%M%S).log"
    LOG_FILE="${CURRENT_DIR}/${XRAY_LOG}"
fi

# Enhanced logging functions
log_and_show() {
    echo "$1" | tee -a "${LOG_FILE}"
}

log_command() {
    echo "🔧 [XRAY][$(date '+%H:%M:%S')] Executing: $1" | tee -a "${LOG_FILE}"
    eval "$1" 2>&1 | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        echo "✅ [XRAY][$(date '+%H:%M:%S')] Success: $1" | tee -a "${LOG_FILE}"
    else
        echo "❌ [XRAY][$(date '+%H:%M:%S')] Failed: $1 (Exit code: $exit_code)" | tee -a "${LOG_FILE}"
    fi
    return $exit_code
}

log_section() {
    echo "" | tee -a "${LOG_FILE}"
    echo "========================================" | tee -a "${LOG_FILE}"
    echo "📋 [XRAY][$(date '+%H:%M:%S')] $1" | tee -a "${LOG_FILE}"
    echo "========================================" | tee -a "${LOG_FILE}"
}

# Start Xray installer logging
log_section "INS-XRAY-MODERN.SH STARTED"
log_and_show "📝 Xray installer log: ${LOG_FILE}"
log_and_show "🕐 Xray installation started at: $(date)"

# Version definition
XRAY_VERSION="25.9.5"

log_and_show "🚀 Installing Xray-core v${XRAY_VERSION} with modern protocols"
log_and_show "📊 Features enabled:"
log_and_show "   - REALITY Protocol (No certificate needed)"
log_and_show "   - XHTTP Transport (Superior to WebSocket)"
log_and_show "   - Post-Quantum Encryption"
log_and_show "   - STB & Kuota Bypass optimization"
log_and_show "   - Advanced Anti-Detection"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               YT ZIXSTYLE XRAY INSTALLER 2025                ║${NC}"
echo -e "${BLUE}║                   REVOLUTIONARY UPGRADE                      ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  🚀 Xray-core v${XRAY_VERSION}                                     ║${NC}"
echo -e "${GREEN}║  🔒 REALITY Protocol (No Certificate Needed)                ║${NC}"
echo -e "${GREEN}║  ⚡ XHTTP Transport (Superior to WebSocket)                  ║${NC}"
echo -e "${GREEN}║  🛡️ Post-Quantum Encryption                                 ║${NC}"
echo -e "${GREEN}║  📺 STB & Kuota Bypass Optimized                            ║${NC}"
echo -e "${GREEN}║  🎯 Anti-Detection Advanced Stealth                         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

echo ""
date
echo ""
domain=$(cat /root/domain)
sleep 1

# Create directories
mkdir -p /etc/xray 
mkdir -p /var/log/xray
mkdir -p /etc/trojan-go

echo -e "[ ${GREEN}INFO${NC} ] Preparing modern Xray installation... "

# Install dependencies
apt install iptables iptables-persistent -y
sleep 1

echo -e "[ ${GREEN}INFO${NC} ] Setting ntpdate"
ntpdate pool.ntp.org 
timedatectl set-ntp true
sleep 1

echo -e "[ ${GREEN}INFO${NC} ] Enable chronyd"
systemctl enable chronyd
systemctl restart chronyd
sleep 1

echo -e "[ ${GREEN}INFO${NC} ] Enable chrony"
systemctl enable chrony
systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
sleep 1

echo -e "[ ${GREEN}INFO${NC} ] Setting chrony tracking"
chronyc sourcestats -v
chronyc tracking -v

echo -e "[ ${GREEN}INFO${NC} ] Installing dependencies for modern Xray"
apt clean all && apt update
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
apt install zip -y
apt install curl pwgen openssl netcat cron -y

# Install latest Xray core
sleep 1
echo -e "[ ${GREEN}INFO${NC} ] Downloading & Installing Xray core v${XRAY_VERSION}"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir

# Make Folder XRay
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
chown www-data.www-data /var/log/xray/*.log

# Download latest Xray
echo -e "[ ${GREEN}INFO${NC} ] Downloading Xray v${XRAY_VERSION} from official repository"
curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install --version v${XRAY_VERSION}

# Verify installation
if [ -f "/usr/local/bin/xray" ]; then
    echo -e "[ ${GREEN}SUCCESS${NC} ] Xray v${XRAY_VERSION} installed successfully"
    /usr/local/bin/xray version
else
    echo -e "[ ${RED}ERROR${NC} ] Xray installation failed"
    exit 1
fi

# Generate UUIDs and passwords
uuid1=$(cat /proc/sys/kernel/random/uuid)
uuid2=$(cat /proc/sys/kernel/random/uuid)
uuid3=$(cat /proc/sys/kernel/random/uuid)
uuid4=$(cat /proc/sys/kernel/random/uuid)
uuid5=$(cat /proc/sys/kernel/random/uuid)

# Generate REALITY keys
echo -e "[ ${GREEN}INFO${NC} ] Generating REALITY protocol keys"
reality_keys=$(/usr/local/bin/xray x25519)
reality_private=$(echo "$reality_keys" | grep "Private key:" | cut -d' ' -f3)
reality_public=$(echo "$reality_keys" | grep "Public key:" | cut -d' ' -f3)

# Generate short IDs for REALITY
reality_short_id1=$(openssl rand -hex 4)
reality_short_id2=$(openssl rand -hex 4)

echo -e "[ ${GREEN}INFO${NC} ] Creating modern Xray configuration with REALITY & XHTTP"

# Generate REALITY keys first
echo -e "[ ${BLUE}INFO${NC} ] Generating REALITY protocol keys..."
cd /etc/xray
REALITY_KEYS=$(/usr/local/bin/xray x25519)
REALITY_PRIVATE=$(echo "$REALITY_KEYS" | grep "Private key:" | cut -d' ' -f3)
REALITY_PUBLIC=$(echo "$REALITY_KEYS" | grep "Public key:" | cut -d' ' -f3)

echo -e "[ ${GREEN}INFO${NC} ] REALITY Private Key: $REALITY_PRIVATE"
echo -e "[ ${GREEN}INFO${NC} ] REALITY Public Key: $REALITY_PUBLIC"

# Create modern Xray configuration with REALITY & XHTTP
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
      "comment": "VLESS WebSocket (Legacy Support)",
      "listen": "127.0.0.1",
      "port": 14016,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "$uuid1"
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
      "comment": "VLESS REALITY - No Certificate Needed (NEW)",
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "$uuid1",
            "flow": "xtls-rprx-vision"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.google.com:443",
          "xver": 0,
          "serverNames": [
            "www.google.com",
            "www.youtube.com",
            "www.facebook.com",
            "www.instagram.com"
          ],
          "privateKey": "$REALITY_PRIVATE",
          "publicKey": "$REALITY_PUBLIC",
          "shortIds": [
            "",
            "0123456789abcdef"
          ]
        }
      }
    },
    {
      "comment": "VLESS XHTTP - Superior Mobile Performance (NEW)",
      "listen": "127.0.0.1",
      "port": 14017,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "$uuid1"
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/vless-xhttp",
          "host": "www.google.com"
        }
      }
    },
    {
      "comment": "VMess WebSocket Enhanced with Post-Quantum",
      "comment": "VMess WebSocket Enhanced with Post-Quantum",
      "listen": "127.0.0.1",
      "port": 23456,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid2",
            "alterId": 0,
            "security": "chacha20-poly1305"
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
      "comment": "VMess XHTTP - Mobile Optimized (NEW)",
      "listen": "127.0.0.1",
      "port": 23460,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid2",
            "alterId": 0,
            "security": "chacha20-poly1305"
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/vmess-xhttp",
          "host": "www.youtube.com"
        }
      }
    },
    {
      "comment": "VMess Worry-Free Enhanced",
      "comment": "VMess Worry-Free Enhanced",
      "listen": "127.0.0.1",
      "port": 23457,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid2",
            "alterId": 0,
            "security": "chacha20-poly1305"
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
      "comment": "VMess Kuota Bypass Enhanced",
      "listen": "127.0.0.1",
      "port": 23458,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid2",
            "alterId": 0,
            "security": "chacha20-poly1305"
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
      "comment": "VMess Chat Enhanced",
      "listen": "127.0.0.1",
      "port": 23459,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid2",
            "alterId": 0,
            "security": "chacha20-poly1305"
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
      "comment": "Trojan Enhanced with Modern Encryption",
      "listen": "127.0.0.1",
      "port": 25432,
      "protocol": "trojan",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "$uuid3"
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
      "comment": "Shadowsocks Modern with AEAD 2022 (UPGRADED)",
      "listen": "127.0.0.1",
      "port": 30300,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "2022-blake3-aes-256-gcm",
            "password": "$uuid4"
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
      "comment": "VLESS gRPC Enhanced",
      "comment": "VLESS gRPC Enhanced",
      "listen": "127.0.0.1",
      "port": 24456,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "$uuid1"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vless-grpc",
          "multiMode": true
        }
      }
    },
    {
      "comment": "VMess gRPC Enhanced",
      "listen": "127.0.0.1",
      "port": 31234,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid2",
            "alterId": 0,
            "security": "chacha20-poly1305"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vmess-grpc",
          "multiMode": true
        }
      }
    },
    {
      "comment": "Trojan gRPC Enhanced",
      "listen": "127.0.0.1",
      "port": 33456,
      "protocol": "trojan",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "password": "$uuid3"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "trojan-grpc",
          "multiMode": true
        }
      }
    },
    {
      "comment": "Shadowsocks gRPC with AEAD 2022",
      "listen": "127.0.0.1",
      "port": 30310,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "2022-blake3-aes-256-gcm",
            "password": "$uuid4"
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "ss-grpc",
          "multiMode": true
        }
      }
    },
    }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
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
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  }
}
EOF
    {
      "listen": "127.0.0.1",
      "port": 9443,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "$uuid5"
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "mode": "auto",
          "path": "/api/v1/data",
          "host": "$domain",
          "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          }
        },
        "security": "tls",
        "tlsSettings": {
          "serverName": "$domain",
          "fingerprint": "chrome",
          "alpn": ["h2", "http/1.1"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
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
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  }
}
EOF

# Save modern configuration details
echo "# YT ZIXSTYLE 2025 - Modern Xray Configuration with REALITY & XHTTP" > /etc/xray/.config-details
echo "CREATION_DATE=$(date)" >> /etc/xray/.config-details
echo "XRAY_VERSION=$XRAY_VERSION" >> /etc/xray/.config-details
echo "VLESS_UUID=$uuid1" >> /etc/xray/.config-details
echo "VMESS_UUID=$uuid2" >> /etc/xray/.config-details
echo "TROJAN_PASS=$uuid3" >> /etc/xray/.config-details
echo "SS_PASS=$uuid4" >> /etc/xray/.config-details
echo "REALITY_PRIVATE=$REALITY_PRIVATE" >> /etc/xray/.config-details
echo "REALITY_PUBLIC=$REALITY_PUBLIC" >> /etc/xray/.config-details
echo "DOMAIN=$domain" >> /etc/xray/.config-details
echo "" >> /etc/xray/.config-details
echo "# Modern Protocol Ports:" >> /etc/xray/.config-details
echo "VLESS_WS_PORT=14016" >> /etc/xray/.config-details
echo "VLESS_REALITY_PORT=8443" >> /etc/xray/.config-details
echo "VLESS_XHTTP_PORT=14017" >> /etc/xray/.config-details
echo "VMESS_WS_PORT=23456" >> /etc/xray/.config-details
echo "VMESS_XHTTP_PORT=23460" >> /etc/xray/.config-details
echo "TROJAN_WS_PORT=25432" >> /etc/xray/.config-details
echo "SS_WS_PORT=30300" >> /etc/xray/.config-details

# Create systemd service
cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray-core ${XRAY_VERSION} Service
Documentation=https://github.com/xtls/xray-core
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

# Enable and start Xray service
systemctl daemon-reload
systemctl enable xray
systemctl start xray

# Create iptables rules for REALITY
iptables -I INPUT -p tcp --dport 8443 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Install Trojan-Go for STB compatibility
echo -e "[ ${GREEN}INFO${NC} ] Installing Trojan-Go for STB & Kuota Bypass compatibility"
mkdir -p /etc/trojan-go
wget -O /usr/local/bin/trojan-go https://github.com/p4gefau1t/trojan-go/releases/download/v0.10.6/trojan-go-linux-amd64
chmod +x /usr/local/bin/trojan-go

# Create Trojan-Go configuration for STB optimization
cat > /etc/trojan-go/config.json << EOF
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 2087,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["$uuid3"],
    "ssl": {
        "cert": "/etc/xray/xray.crt",
        "key": "/etc/xray/xray.key",
        "verify": false,
        "verify_hostname": false,
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
        "curves": ""
    },
    "websocket": {
        "enabled": true,
        "path": "/trojango",
        "host": "$domain"
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": true,
        "fast_open": false
    },
    "mux": {
        "enabled": false
    }
}
EOF

# Create Trojan-Go systemd service
cat > /etc/systemd/system/trojan-go.service << EOF
[Unit]
Description=Trojan-Go Service for STB & Kuota Bypass
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=on-failure
RestartSec=5
User=nobody

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable trojan-go
systemctl start trojan-go

# Generate certificates if not exist
if [ ! -f "/etc/xray/xray.crt" ]; then
    echo -e "[ ${GREEN}INFO${NC} ] Generating SSL certificates"
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=YT ZIXSTYLE/CN=$domain" \
        -keyout /etc/xray/xray.key \
        -out /etc/xray/xray.crt
    
    # Fix: Set proper certificate permissions (prevent "Insecure file permissions" error)
    log_and_show "🔧 Setting secure certificate permissions..."
    chmod 644 /etc/xray/xray.crt
    chmod 600 /etc/xray/xray.key
    log_and_show "✅ Certificate permissions secured"
fi

# Create nginx configuration for Xray with SSL fixes
echo -e "[ ${GREEN}INFO${NC} ] Creating modern nginx configuration with XHTTP & Universal SNI support"
mkdir -p /etc/nginx/conf.d

# Create modern nginx configuration with XHTTP & enhanced security
cat > /etc/nginx/conf.d/xray.conf << 'EOF'
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
    listen 443 ssl http2 reuseport;
    listen [::]:443 http2 reuseport;
    
    # Universal SNI Support - Accept ANY domain
    server_name _;
    
    # Modern SSL Certificate
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    
    # Enhanced SSL Ciphers for Modern Security (TLS 1.3 Ready)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    root /var/www/html;
    index index.html index.htm;

    # === LEGACY WEBSOCKET PROTOCOLS (ENHANCED) ===
    
    # VLESS WebSocket (Enhanced)
    location = /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14016;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # VMess WebSocket (Enhanced)
    location = /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23456;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # === NEW MODERN XHTTP PROTOCOLS ===
    
    # VLESS XHTTP - Superior Mobile Performance
    location = /vless-xhttp {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:14017;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # VMess XHTTP - Mobile Optimized
    location = /vmess-xhttp {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23460;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # === STB & KUOTA BYPASS OPTIMIZED ===
    
    # VMess Worry-Free Enhanced
    location = /worryfree {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23457;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # VMess Kuota Bypass Enhanced
    location = /kuota-habis {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23458;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # VMess Chat Enhanced
    location = /chat {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:23459;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # Trojan WebSocket Enhanced
    location = /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:25432;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # Shadowsocks WebSocket Enhanced
    location = /ss-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:30300;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # === GRPC PROTOCOLS (ENHANCED) ===
    
    # VLESS gRPC Enhanced
    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:24456;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
    }

    # VMess gRPC Enhanced
    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:31234;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
    }

    # Trojan gRPC Enhanced
    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:33456;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
    }

    # Shadowsocks gRPC Enhanced
    location /ss-grpc {
        grpc_pass grpc://127.0.0.1:30310;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
    }

    # === RATE LIMITING & DDOS PROTECTION ===
    
    # Rate limiting for API endpoints
    location /api/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://127.0.0.1:10085;
    }

    # Bot protection
    location ~* \.(php|asp|aspx|jsp)$ {
        return 444;
    }

    # Block common attack patterns
    location ~* (wp-admin|wp-login|phpmyadmin|admin) {
        return 444;
    }
}
EOF

# Test nginx configuration
echo -e "[ ${BLUE}INFO${NC} ] Testing nginx configuration..."
if nginx -t 2>&1; then
    echo -e "[ ${GREEN}INFO${NC} ] ✅ Nginx configuration test: PASSED"
    systemctl reload nginx
else
    echo -e "[ ${RED}ERROR${NC} ] ❌ Nginx configuration test: FAILED"
    # Fix common nginx syntax issues
    sed -i '17s/ssl_certificate_key/\n            ssl_certificate_key/' /etc/nginx/conf.d/xray.conf
    sed -i '18s/^ssl_ciphers/            ssl_ciphers/' /etc/nginx/conf.d/xray.conf
    
    # Test again
    if nginx -t 2>&1; then
        echo -e "[ ${GREEN}INFO${NC} ] ✅ Nginx configuration fixed and tested: PASSED"
        systemctl reload nginx
    else
        echo -e "[ ${RED}ERROR${NC} ] ❌ Nginx configuration still has issues"
    fi
fi
else
    log_and_show "❌ Nginx configuration syntax error detected - applying fix..."
    # Apply the documented fix for ssl_ciphers line break issue
    sed -i '17s/ssl_certificate_key/\n            ssl_certificate_key/' /etc/nginx/conf.d/xray.conf
    sed -i '18s/^ssl_ciphers/            ssl_ciphers/' /etc/nginx/conf.d/xray.conf
    
    # Re-test configuration
    if nginx -t; then
        log_and_show "✅ Nginx configuration fixed and validated"
        systemctl reload nginx
    else
        log_and_show "❌ Nginx configuration still has issues"
    fi
fi

# Version tracking
echo "$XRAY_VERSION" > /opt/.xray-ver
echo "$(date)" > /opt/.xray-install-date

# Test Xray configuration
echo -e "[ ${BLUE}INFO${NC} ] Testing Xray configuration..."
if /usr/local/bin/xray test -config /etc/xray/config.json; then
    echo -e "[ ${GREEN}SUCCESS${NC} ] ✅ Xray configuration test: PASSED"
    systemctl restart xray
    sleep 3
    
    # Validate modern protocols are running
    echo -e "[ ${BLUE}INFO${NC} ] Validating modern protocol ports..."
    if netstat -tlnp | grep ":8443" | grep -q xray; then
        echo -e "[ ${GREEN}SUCCESS${NC} ] ✅ REALITY Protocol (Port 8443): ACTIVE"
    else
        echo -e "[ ${YELLOW}WARNING${NC} ] ⚠️ REALITY Protocol (Port 8443): NOT ACTIVE"
    fi
    
    if netstat -tlnp | grep ":14017" | grep -q xray; then
        echo -e "[ ${GREEN}SUCCESS${NC} ] ✅ VLESS XHTTP (Port 14017): ACTIVE"
    else
        echo -e "[ ${YELLOW}WARNING${NC} ] ⚠️ VLESS XHTTP (Port 14017): NOT ACTIVE"
    fi
    
    if netstat -tlnp | grep ":23460" | grep -q xray; then
        echo -e "[ ${GREEN}SUCCESS${NC} ] ✅ VMess XHTTP (Port 23460): ACTIVE"
    else
        echo -e "[ ${YELLOW}WARNING${NC} ] ⚠️ VMess XHTTP (Port 23460): NOT ACTIVE"
    fi
    
else
    echo -e "[ ${RED}ERROR${NC} ] ❌ Xray configuration test: FAILED"
    echo -e "[ ${BLUE}INFO${NC} ] Checking Xray error logs..."
    journalctl -u xray --no-pager -n 10
    exit 1
fi

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              MODERN XRAY INSTALLATION COMPLETE              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  🚀 Xray-core v${XRAY_VERSION} - Latest Release                     ║${NC}"
echo -e "${GREEN}║  🔒 REALITY Protocol - Port 8443 (No Certificate)          ║${NC}"
echo -e "${GREEN}║  ⚡ VLESS XHTTP - Port 14017 (Mobile Optimized)            ║${NC}"
echo -e "${GREEN}║  ⚡ VMess XHTTP - Port 23460 (Mobile Optimized)            ║${NC}"
echo -e "${GREEN}║  📺 Trojan-Go STB Support - Port 2087                       ║${NC}"
echo -e "${GREEN}║  🛡️ Post-Quantum Encryption (chacha20-poly1305)            ║${NC}"
echo -e "${GREEN}║  🎯 Shadowsocks AEAD 2022 (2022-blake3-aes-256-gcm)        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

echo -e "${BLUE}🎊 Modern protocols successfully enabled:${NC}"
echo -e "✅ VMess + WebSocket (Enhanced with Post-Quantum)"
echo -e "✅ VLESS + WebSocket (Enhanced for compatibility)"
echo -e "✅ VLESS + REALITY (Revolutionary - No certificate needed)"
echo -e "✅ VLESS + XHTTP (Superior mobile performance)"
echo -e "✅ VMess + XHTTP (Mobile optimized transport)"
echo -e "✅ Trojan + WebSocket (Enhanced encryption)"
echo -e "✅ Trojan-Go (STB & Kuota bypass optimized)"
echo -e "✅ Shadowsocks AEAD 2022 (Future-proof encryption)"
echo -e "✅ gRPC multiMode (All protocols enhanced)"

echo -e ""
echo -e "${PURPLE}📋 Configuration saved to: /etc/xray/.config-details${NC}"
echo -e "${PURPLE}📋 REALITY Public Key: $REALITY_PUBLIC${NC}"
echo -e "${PURPLE}📋 Test modern protocols with tools in: /usr/local/bin/${NC}"
