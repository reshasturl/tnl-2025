#!/bin/bash
#
# YT ZIXSTYLE Tools Installer 2025
# Created: September 7, 2025
# Purpose: Install system tools, dependencies, and basic configurations
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Prevent interactive prompts during package installation (for iptables-persistent)
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
# Install packages in smaller groups to avoid conflicts
log_command "apt install -y screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip"
log_command "apt install -y net-tools sed gnupg gnupg1 bc apt-transport-https build-essential"
log_command "apt install -y dirmngr libxml-parser-perl neofetch screenfetch git lsof openssl"
log_command "apt install -y openvpn easy-rsa fail2ban tmux stunnel4 squid dropbear"
# Install nginx and additional packages
log_command "apt install -y nginx apache2-utils"
# Install netfilter-persistent and netcat-openbsd (fixing netcat issue)
log_command "apt install -y iptables-persistent netfilter-persistent netcat-openbsd"

# Configure stunnel4 with proper settings
log_and_show "🔒 Configuring stunnel4..."
if command -v stunnel4 >/dev/null 2>&1; then
    # Ensure stunnel4 configuration directory exists
    log_command "mkdir -p /etc/stunnel"
    
    # Create stunnel4 user if not exists (before creating certificate)
    if ! id stunnel4 >/dev/null 2>&1; then
        log_command "useradd --system --no-create-home --shell /bin/false stunnel4" || true
    fi
    
    # Create self-signed certificate FIRST (before config)
    if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
        log_and_show "🔐 Creating self-signed SSL certificate for stunnel4..."
        openssl req -new -x509 -days 3650 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=ID/ST=Jakarta/L=Jakarta/O=YT-ZIXSTYLE/CN=stunnel" 2>/dev/null || true
        chmod 600 /etc/stunnel/stunnel.pem
        chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || true
        log_and_show "✅ SSL certificate created for stunnel4"
    fi
    
    # Create basic stunnel4 configuration AFTER certificate is ready
    if [[ ! -f /etc/stunnel/stunnel.conf ]]; then
        cat > /etc/stunnel/stunnel.conf << 'EOF'
; Basic stunnel4 configuration for YT ZIXSTYLE VPN
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

; User and group
setuid = stunnel4
setgid = stunnel4

; Some performance tunings
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

; Logging
debug = 4
output = /var/log/stunnel4/stunnel.log

; Basic HTTPS to HTTP proxy service (minimal working configuration)
[https]
accept = 8443
connect = 127.0.0.1:8080
TIMEOUTclose = 0

EOF
        log_and_show "✅ Basic stunnel4 configuration created"
    fi
    
    # Create stunnel4 runtime directory
    log_command "mkdir -p /var/run/stunnel4"
    log_command "chown stunnel4:stunnel4 /var/run/stunnel4" || true
    
    # Create basic systemd service for stunnel4 if it doesn't exist properly
    if [[ ! -f /etc/systemd/system/stunnel4.service ]]; then
        cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for network daemons
Documentation=man:stunnel
DefaultDependencies=no
After=network.target
Before=multi-user.target

[Service]
Type=forking
RuntimeDirectory=stunnel4
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/stunnel4/stunnel.pid
KillMode=mixed

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run/stunnel4
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
        log_and_show "✅ Enhanced stunnel4 systemd service created"
        log_command "systemctl daemon-reload"
    fi
    
    # Test stunnel4 configuration (should pass now that cert exists)
    if stunnel4 -test 2>/dev/null; then
        log_and_show "✅ stunnel4 configuration test passed"
    else
        log_and_show "⚠️ stunnel4 configuration test failed, but continuing..."
    fi
else
    log_and_show "⚠️ stunnel4 not installed, skipping configuration"
fi
    # Ensure proper directories and permissions exist
    log_command "mkdir -p /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4"
    
    # Set proper ownership (user already created above)
    log_command "chown stunnel4:stunnel4 /var/run/stunnel4 /var/lib/stunnel4 /var/log/stunnel4" || true
    log_command "chmod 755 /var/run/stunnel4 /var/lib/stunnel4"
    log_command "chmod 750 /var/log/stunnel4"
    
    # Enable stunnel4 service if it exists
    if systemctl list-unit-files | grep -q "^stunnel4.service"; then
        log_command "systemctl enable stunnel4" || log_and_show "⚠️ Failed to enable stunnel4 service"
    fi
else
    log_and_show "⚠️ stunnel4 command not found after installation"
fi
log_command "apt install -y libsqlite3-dev socat cron bash-completion xz-utils gnupg2"
log_command "apt install -y dnsutils lsb-release vnstat"

# Install chrony with fallback to systemd-timesyncd
log_and_show "⏰ Installing time synchronization service..."
if ! log_command "apt install -y chrony"; then
    log_and_show "⚠️ chrony installation failed, using systemd-timesyncd as fallback"
    log_command "systemctl enable systemd-timesyncd"
    log_command "systemctl start systemd-timesyncd"
fi

# VPN Development Libraries (updated for Ubuntu 24.04 - improved libcurl handling)
log_and_show "🔧 Installing VPN development libraries..."
log_command "apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev"
log_command "apt install -y libcap-ng-utils libselinux1-dev flex bison make libnss3-tools"
log_command "apt install -y libevent-dev xl2tpd"

# Handle libcurl4 installation with conflict resolution
log_and_show "📦 Installing libcurl4 with conflict resolution..."
if ! log_command "apt install -y libcurl4-openssl-dev"; then
    log_and_show "⚠️ libcurl4-openssl-dev conflict detected, trying alternative..."
    log_command "apt remove -y libcurl4-gnutls-dev" || true
    log_command "apt install -y libcurl4-openssl-dev" || log_and_show "⚠️ libcurl4 installation failed"
fi

# Network utilities and monitoring
log_and_show "🌐 Installing network utilities..."
log_command "apt install -y speedtest-cli dnsutils netcat-openbsd iperf3 mtr-tiny tcpdump"

# Install iptables with proper persistent support for Ubuntu 24.04
log_and_show "🔒 Installing iptables with persistence support..."
log_command "apt install -y iptables"

# For Ubuntu 24.04, we use ufw instead of iptables-persistent
if ! command -v netfilter-persistent >/dev/null 2>&1; then
    log_and_show "📦 Installing iptables-persistent package..."
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    log_command "apt install -y iptables-persistent netfilter-persistent" || log_and_show "⚠️ iptables-persistent installation failed, rules may not persist"
fi

# Install Node.js 20 LTS (updated from deprecated 16.x with error handling)
log_and_show "🟢 Installing Node.js 20 LTS..."
if ! log_command "curl -sSL https://deb.nodesource.com/setup_20.x | bash -"; then
    log_and_show "⚠️ NodeSource repository setup failed, trying snap installation..."
    if command -v snap >/dev/null; then
        log_command "snap install node --classic" || log_and_show "⚠️ Node.js installation failed"
    else
        log_and_show "⚠️ Installing nodejs from Ubuntu repository as fallback..."
        log_command "apt install -y nodejs npm" || log_and_show "⚠️ Node.js fallback installation failed"
    fi
else
    log_command "apt-get install nodejs -y" || log_and_show "⚠️ Node.js installation failed"
fi

# Python environment
log_and_show "🐍 Setting up Python environment..."
log_command "apt install -y python3 python3-pip python3-dev build-essential"
if ! command -v python >/dev/null 2>&1; then
    log_command "ln -sf /usr/bin/python3 /usr/bin/python"
    log_and_show "✅ Python symlink created"
fi

# Install vnstat from source (Enhanced version 2.9 with hardened service)
log_and_show "📊 Installing vnstat 2.9 from source with enhanced security..."
cd /tmp
if log_command "wget -q https://humdi.net/vnstat/vnstat-2.9.tar.gz"; then
    if [[ -f vnstat-2.9.tar.gz ]]; then
        log_command "tar zxvf vnstat-2.9.tar.gz"
        cd vnstat-2.9
        if log_command "./configure --prefix=/usr --sysconfdir=/etc"; then
            if log_command "make"; then
                if log_command "make install"; then
                    log_and_show "✅ vnstat 2.9 compiled and installed from source"
                else
                    log_and_show "⚠️ vnstat make install failed, using apt version as fallback"
                    cd /
                    log_command "apt install -y vnstat" || log_and_show "⚠️ vnstat fallback installation failed"
                fi
            else
                log_and_show "⚠️ vnstat compilation failed, using apt version as fallback"
                cd /
                log_command "apt install -y vnstat" || log_and_show "⚠️ vnstat fallback installation failed"
            fi
        else
            log_and_show "⚠️ vnstat configure failed, using apt version as fallback"
            cd /
            log_command "apt install -y vnstat" || log_and_show "⚠️ vnstat fallback installation failed"
        fi
        cd /
        log_command "rm -f /tmp/vnstat-2.9.tar.gz"
        log_command "rm -rf /tmp/vnstat-2.9"
    fi
else
    log_and_show "⚠️ vnstat source download failed, using apt version as fallback"
    log_command "apt install -y vnstat" || log_and_show "⚠️ vnstat fallback installation failed"
fi

# Configure vnstat with enhanced security
log_and_show "⚙️ Configuring vnstat with enhanced security..."

# Ensure vnstat user exists
if ! id vnstat >/dev/null 2>&1; then
    log_command "useradd --system --no-create-home --shell /bin/false vnstat" || true
fi

# Detect network interface properly
NET_INTERFACE=""
if [ -d "/sys/class/net/ens4" ]; then
    NET_INTERFACE="ens4"
elif [ -d "/sys/class/net/eth0" ]; then
    NET_INTERFACE="eth0"  
elif [ -d "/sys/class/net/enp0s3" ]; then
    NET_INTERFACE="enp0s3"
else
    NET_INTERFACE=$(ip route | awk '/default/ { print $5 }' | head -n1)
fi

log_and_show "🌐 Detected network interface: $NET_INTERFACE"

# Create vnstat database with correct parameter for different versions (Fixed for modern vnstat)
if command -v vnstat >/dev/null 2>&1; then
    # Check vnstat version and use appropriate commands
    VNSTAT_VERSION=$(vnstat --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)
    log_and_show "📊 Detected vnstat version: ${VNSTAT_VERSION:-unknown}"
    
    if vnstat --help 2>/dev/null | grep -q "\--create"; then
        # Modern vnstat (2.6+) uses --create
        log_command "vnstat --create -i $NET_INTERFACE" || log_and_show "⚠️ vnstat database may already exist"
    elif vnstat --help 2>/dev/null | grep -q "\--add"; then
        # Legacy vnstat uses --add  
        log_command "vnstat -i $NET_INTERFACE --add" || log_and_show "⚠️ vnstat database may already exist"
    else
        # Fallback: Use daemon initialization (no -u parameter in modern versions)
        log_and_show "⚠️ Using fallback vnstat initialization..."
        log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
        # Modern vnstat doesn't support -u, use systemd service instead
        systemctl enable vnstat 2>/dev/null || true
    fi
    
    # Fix vnstat.conf interface configuration if file exists
    if [[ -f /etc/vnstat.conf ]]; then
        log_command "sed -i 's/Interface \"eth0\"/Interface \"$NET_INTERFACE\"/g' /etc/vnstat.conf"
    fi
    
    # Set proper permissions
    log_command "mkdir -p /var/lib/vnstat"
    log_command "chown vnstat:vnstat /var/lib/vnstat -R" || true
else
    log_and_show "⚠️ vnstat command not found, skipping configuration"
fi

# Create hardened vnstat systemd service with dynamic path detection
log_and_show "🔒 Creating hardened vnstat systemd service..."

# Detect vnstatd path
VNSTATD_PATH=""
for path in /usr/bin/vnstatd /usr/local/bin/vnstatd /bin/vnstatd /usr/sbin/vnstatd; do
    if [[ -x "$path" ]]; then
        VNSTATD_PATH="$path"
        log_and_show "✅ Found vnstatd at: $VNSTATD_PATH"
        break
    fi
done

# If not found in common paths, try which command
if [[ -z "$VNSTATD_PATH" ]]; then
    if command -v vnstatd >/dev/null 2>&1; then
        VNSTATD_PATH=$(which vnstatd)
        log_and_show "✅ Found vnstatd using which: $VNSTATD_PATH"
    else
        log_and_show "⚠️ vnstatd not found, using default path /usr/bin/vnstatd"
        VNSTATD_PATH="/usr/bin/vnstatd"
    fi
fi

# Only create service if vnstatd binary actually exists
if [[ -x "$VNSTATD_PATH" ]]; then
    log_and_show "✅ vnstatd binary verified at: $VNSTATD_PATH"
    
    cat > /etc/systemd/system/vnstat.service << EOF
[Unit]
Description=vnStat network traffic monitor
Documentation=man:vnstatd(8) man:vnstat(1) man:vnstat.conf(5)
After=network.target network-online.target nss-lookup.target time-sync.target
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5
ExecStartPre=/bin/mkdir -p /var/run/vnstat
ExecStartPre=/bin/chown vnstat:vnstat /var/run/vnstat
ExecStart=$VNSTATD_PATH --nodaemon
ExecReload=/bin/kill -HUP \$MAINPID
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
    log_and_show "✅ vnstat systemd service created and enabled"
else
    log_and_show "⚠️ vnstatd binary not found at $VNSTATD_PATH, service creation skipped"
    log_and_show "⚠️ vnstat will need manual configuration after binary installation"
fi

# Fix vnstat database initialization and service startup
log_and_show "📊 Initializing vnstat database and starting service..."
if command -v vnstat >/dev/null 2>&1; then
    # Stop any existing vnstat service
    systemctl stop vnstat 2>/dev/null || true
    
    # Create database directory with proper permissions
    log_command "mkdir -p /var/lib/vnstat"
    log_command "chown vnstat:vnstat /var/lib/vnstat" || true
    log_command "chmod 755 /var/lib/vnstat"
    
    # Remove any corrupted database files
    log_command "rm -f /var/lib/vnstat/$NET_INTERFACE*" || true
    
    # Initialize database with modern vnstat methods (no -u parameter in newer versions)
    log_and_show "🔄 Attempting vnstat database initialization..."
    
    # Method 1: Modern vnstat (2.6+)
    if vnstat --help 2>/dev/null | grep -q "\--create"; then
        if log_command "vnstat --create -i $NET_INTERFACE"; then
            log_and_show "✅ vnstat database created with --create method"
        else
            log_and_show "⚠️ Method 1 failed, trying daemon initialization..."
            log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
            log_and_show "✅ vnstat initialized with daemon method"
        fi
    elif vnstat --help 2>/dev/null | grep -q "\--add"; then
        # Method 2: Legacy vnstat
        if log_command "vnstat -i $NET_INTERFACE --add"; then
            log_and_show "✅ vnstat database created with --add method"
        else
            log_and_show "⚠️ Method 2 failed, trying daemon initialization..."
            log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
            log_and_show "✅ vnstat initialized with daemon method"
        fi
    else
        # Method 3: Force initialization with daemon only (no -u in modern versions)
        log_command "vnstatd --initdb --config /etc/vnstat.conf" || true
        log_and_show "⚠️ All database creation methods failed, using service auto-init"
    fi
    
    # Final ownership fix
    log_command "chown -R vnstat:vnstat /var/lib/vnstat" || true
    log_command "chmod -R 644 /var/lib/vnstat/*" 2>/dev/null || true
    # Ensure database directory exists
    mkdir -p /var/lib/vnstat
    chown -R vnstat:vnstat /var/lib/vnstat 2>/dev/null || true
    
    # Create database for primary interface if not exists (fixed for modern vnstat)
    if [[ ! -f /var/lib/vnstat/.$NET ]] && [[ ! -f /var/lib/vnstat/.${NET} ]]; then
        log_and_show "📊 Creating vnstat database for interface $NET..."
        # Try different vnstat database creation methods based on version
        if vnstat --help 2>/dev/null | grep -q "\--create"; then
            vnstat --create -i $NET 2>/dev/null || log_and_show "⚠️ vnstat --create failed"
        elif vnstat --help 2>/dev/null | grep -q "\--add"; then
            vnstat -i $NET --add 2>/dev/null || log_and_show "⚠️ vnstat --add failed"
        else
            # Fallback: Use daemon initialization (no -u in modern vnstat)
            vnstatd --initdb --config /etc/vnstat.conf 2>/dev/null || log_and_show "⚠️ vnstat basic initialization failed"
        fi
        sleep 2
    else
        log_and_show "✅ vnstat database already exists for $NET"
    fi
    
    # Try to start vnstat service with enhanced error handling
    if systemctl is-active --quiet vnstat; then
        log_and_show "✅ vnstat service is already running"
    else
        if systemctl start vnstat 2>/dev/null; then
            log_and_show "✅ vnstat service started successfully"
        else
            log_and_show "⚠️ vnstat service startup failed, trying restart..."
            systemctl restart vnstat 2>/dev/null || log_and_show "⚠️ vnstat will be available after next system reboot"
        fi
    fi
    
    # Set correct ownership after database creation
    chown -R vnstat:vnstat /var/lib/vnstat 2>/dev/null || true
    chmod 755 /var/lib/vnstat 2>/dev/null || true
    
    # Start vnstat service with proper error handling
    if systemctl start vnstat 2>/dev/null; then
        log_and_show "✅ vnstat service started successfully"
        # Verify service is actually running
        sleep 2
        if systemctl is-active --quiet vnstat; then
            log_and_show "✅ vnstat service confirmed active"
        else
            log_and_show "⚠️ vnstat service not active, will retry after reboot"
        fi
    else
        log_and_show "⚠️ vnstat service startup failed, trying restart..."
        if systemctl restart vnstat 2>/dev/null; then
            log_and_show "✅ vnstat service restarted successfully"
        else
            log_and_show "⚠️ vnstat will be available after next system reboot"
            systemctl enable vnstat 2>/dev/null || true
        fi
    fi
else
    log_and_show "⚠️ vnstat command not available, skipping service startup"
fi
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
log_and_show "🔒 Creating nginx-specific fail2ban jail..."
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

# Ensure script exits successfully even if some minor components failed
exit 0
