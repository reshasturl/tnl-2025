#!/bin/bash
#
# YT ZIXSTYLE Tools Installer 2025
# Created: September 7, 2025
# Purpose: Install system tools, dependencies, and basic configurations
# Log: Inherit dari setup-2025.sh
# ===============================================================================

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

# Install comprehensive package list (based on tools.sh)
log_and_show "📦 Installing comprehensive package list..."
log_command "apt install -y screen rsyslog iftop htop net-tools zip curl wget vim nano"
log_command "apt install -y neofetch screenfetch lsof iptables openssl easy-rsa dnsutils"
log_command "apt install -y bc math-calc build-essential gcc g++ automake cmake git make tmux"
log_command "apt install -y vnstat software-properties-common apt-transport-https ca-certificates"
log_command "apt install -y squid3 libsqlite3-dev bzip2 gzip coreutils socat chrony"

# Additional packages from original tools.sh
log_and_show "📦 Installing additional packages from tools.sh..."
log_command "apt install -y jq unzip sed gnupg gnupg1 dirmngr libxml-parser-perl"
log_command "apt install -y openvpn stunnel4 dropbear cron bash-completion ntpdate xz-utils"
log_command "apt install -y gnupg2 lsb-release"

# VPN Development Libraries
log_and_show "🔧 Installing VPN development libraries..."
log_command "apt install -y libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev"
log_command "apt install -y libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison"
log_command "apt install -y libnss3-tools libevent-dev xl2tpd pptpd make"

# Network utilities and monitoring
log_and_show "🌐 Installing network utilities..."
log_command "apt install -y speedtest-cli dnsutils netcat-openbsd iperf3 mtr-tiny tcpdump"
log_command "apt install -y iptables iptables-persistent netfilter-persistent"

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

# Install vnstat from source (latest version - exact from tools.sh)
log_and_show "📊 Installing vnstat from source..."
cd /tmp
log_command "wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz"
if [[ -f vnstat-2.6.tar.gz ]]; then
    log_command "tar zxvf vnstat-2.6.tar.gz"
    cd vnstat-2.6
    log_command "./configure --prefix=/usr --sysconfdir=/etc"
    log_command "make && make install"
    cd /
    log_command "rm -f /tmp/vnstat-2.6.tar.gz"
    log_command "rm -rf /tmp/vnstat-2.6"
    log_and_show "✅ vnstat installed from source"
fi

# Configure vnstat
log_and_show "⚙️ Configuring vnstat..."
log_command "vnstat -u -i $NET"
# Fix vnstat.conf interface configuration
log_command "sed -i 's/Interface \"eth0\"/Interface \"$NET\"/g' /etc/vnstat.conf"
log_command "chown vnstat:vnstat /var/lib/vnstat -R"
log_command "systemctl enable vnstat"
log_command "systemctl start vnstat"
log_command "/etc/init.d/vnstat restart"

# Network tools (removed redundant iptables - already installed above)
log_and_show "🛡️ Configuring security tools..."
log_command "apt install -y ufw fail2ban"

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

log_and_show "✅ System tools installation completed"
log_section "TOOLS-2025.SH COMPLETED"
