#!/bin/bash
#
# YT ZIXSTYLE Tools Installer 2025
# Created: September 7, 2025
# Purpose: Install system tools, dependencies, and basic configurations
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Prevent interactive prompts during package installation
export DEBIAN_FRONTEND=noninteractive

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "TOOLS-2025.SH STARTED"
log_and_show "🛠️  Starting system tools installation..."

# Color functions for compatibility
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }

# OS Detection
if [[ -e /etc/debian_version ]]; then
    source /etc/os-release
    OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
    source /etc/os-release
    OS=centos
fi

# Get network interface
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}')
if [ -z "$NET" ]; then
    NET=$(ip route | awk '/default/ { print $5 }' | head -n1)
fi

log_and_show "📦 Updating system packages..."
log_command "apt update -y"
log_command "apt dist-upgrade -y"
log_command "apt-get remove --purge ufw firewalld -y"
log_command "apt-get remove --purge exim4 -y"

# Install comprehensive package list (based on tools.sh - updated for Ubuntu 24.04)
log_and_show "📦 Installing comprehensive package list..."
log_command "apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop \
 htop zip unzip net-tools sed gnupg gnupg1 \
 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof \
 openssl openvpn easy-rsa fail2ban tmux \
 stunnel4 vnstat squid \
 dropbear libsqlite3-dev \
 socat cron bash-completion ntpdate xz-utils \
 gnupg2 dnsutils lsb-release chrony"

# VPN Development Libraries (updated for Ubuntu 24.04 - removed pptpd, fixed libcurl4)
log_and_show "🔧 Installing VPN development libraries..."
log_command "apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-openssl-dev flex bison make libnss3-tools libevent-dev xl2tpd"

# Network utilities and monitoring
log_and_show "🌐 Installing network utilities..."
log_command "apt install -y speedtest-cli dnsutils netcat-openbsd iperf3 mtr-tiny tcpdump"
log_command "apt install -y iptables iptables-persistent netfilter-persistent >/dev/null 2>&1"

# Install Node.js 16.x (exact version from tools.sh)
log_and_show "🟢 Installing Node.js 16.x..."
log_command "curl -sSL https://deb.nodesource.com/setup_16.x | bash -"
log_command "apt-get install nodejs -y"

# Python environment
log_and_show "🐍 Setting up Python environment..."
log_command "apt install -y python3 python3-pip python2 python2-dev"
if ! command -v python >/dev/null 2>&1; then
    log_command "ln -sf /usr/bin/python3 /usr/bin/python"
    log_and_show "✅ Python symlink created"
fi

# Install vnstat from source (Enhanced version 2.9 with hardened service)
log_and_show "📊 Installing vnstat 2.9 from source with enhanced security..."
cd /tmp
log_command "wget -q https://humdi.net/vnstat/vnstat-2.9.tar.gz"
if [[ -f vnstat-2.9.tar.gz ]]; then
    log_command "tar zxvf vnstat-2.9.tar.gz"
    cd vnstat-2.9
    log_command "./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1"
    cd /
    log_command "rm -f /tmp/vnstat-2.9.tar.gz >/dev/null 2>&1"
    log_command "rm -rf /tmp/vnstat-2.9 >/dev/null 2>&1"
    log_and_show "✅ vnstat 2.9 installed from source"
fi

# Configure vnstat with enhanced security
log_and_show "⚙️ Configuring vnstat with enhanced security..."
log_command "vnstat -u -i $NET"
# Fix vnstat.conf interface configuration
log_command "sed -i 's/Interface \"eth0\"/Interface \"$NET\"/g' /etc/vnstat.conf"
log_command "chown vnstat:vnstat /var/lib/vnstat -R"

# Create hardened vnstat systemd service
log_and_show "🔒 Creating hardened vnstat systemd service..."
cat > /etc/systemd/system/vnstat.service << 'EOF'
[Unit]
Description=vnStat network traffic monitor
Documentation=man:vnstatd(8) man:vnstat(1) man:vnstat.conf(5)
After=network.target network-online.target nss-lookup.target time-sync.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/vnstat/vnstat.pid
ExecStartPre=/bin/mkdir -p /var/run/vnstat
ExecStartPre=/bin/chown vnstat:vnstat /var/run/vnstat
ExecStart=/usr/bin/vnstatd -d
ExecReload=/bin/kill -HUP $MAINPID
User=vnstat
Group=vnstat

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vnstat /var/run/vnstat
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

log_command "systemctl daemon-reload"
log_command "systemctl enable vnstat"
log_command "systemctl start vnstat"
log_and_show "✅ vnstat configured with hardened systemd service"

# Enhanced security tools with nginx DDoS protection
log_and_show "🛡️ Configuring enhanced security tools with nginx DDoS protection..."
log_command "apt install -y ufw fail2ban"

# Configure fail2ban with nginx-specific rules
log_and_show "🔒 Setting up fail2ban with nginx DDoS protection..."

# Create nginx-ddos filter
log_and_show "📝 Creating nginx-ddos fail2ban filter..."
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/nginx-ddos.conf << 'EOF'
# Fail2Ban filter for nginx DDoS protection
[Definition]
failregex = <HOST> -.*- .*HTTP/1.* .* .*$
ignoreregex =
EOF

# Create nginx-specific jail configuration  
log_and_show "� Creating nginx-specific fail2ban jail..."
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/fail2ban-nginx.conf << 'EOF'
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
findtime = 600
bantime = 3600

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
findtime = 600
bantime = 3600

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-ddos]
enabled = true
port = http,https
filter = nginx-ddos
logpath = /var/log/nginx/access.log
maxretry = 50
findtime = 60
bantime = 600

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 3600
EOF

log_command "systemctl enable fail2ban"
log_command "systemctl restart fail2ban"
log_and_show "✅ fail2ban configured with nginx DDoS protection"

# Performance tools
log_and_show "⚡ Installing performance optimization tools..."
log_command "apt install -y haveged rng-tools"
log_command "systemctl enable haveged"
log_command "systemctl start haveged"

# Development tools (updated to avoid conflicts)
log_and_show "🔧 Installing additional development tools..."
log_command "apt install -y autoconf automake libtool"
log_command "apt install -y libssl-dev zlib1g-dev"

# Create necessary directories
log_and_show "📁 Creating system directories..."
log_command "mkdir -p /etc/xray /etc/v2ray /usr/local/bin"

# System optimizations
log_and_show "⚙️ Applying system optimizations..."
log_command "sysctl -w net.core.default_qdisc=fq"
log_command "sysctl -w net.ipv4.tcp_congestion_control=bbr"

log_section "TOOLS-2025.SH COMPLETED"
log_and_show "✅ System tools installation completed successfully!"
log_command "mkdir -p /home/vps/public_html"
log_command "mkdir -p /var/log/xray"

# Set timezone
log_and_show "🕐 Configuring timezone..."
log_command "timedatectl set-timezone Asia/Jakarta"

# Final status message (matching tools.sh style)
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "Dependencies successfully installed..."
log_and_show "⏳ Waiting 3 seconds..."
sleep 3

# Log tools installation
echo "Tools: System packages, Python, network utilities" >> /root/log-install.txt
echo "Development: gcc, make, build tools" >> /root/log-install.txt
echo "Performance: haveged, rng-tools" >> /root/log-install.txt
echo "vnStat: Version 2.9 with hardened systemd service" >> /root/log-install.txt
echo "fail2ban: Enhanced with nginx DDoS protection rules" >> /root/log-install.txt
echo "Security: SystemCallArchitectures, PrivateTmp, ProtectSystem" >> /root/log-install.txt

log_and_show "✅ System tools installation completed"
log_section "TOOLS-2025.SH COMPLETED"
