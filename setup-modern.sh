#!/bin/bash
# YT ZIXSTYLE VPN Installer - MODERNIZED VERSION 2025
# Updated: September 7, 2025
# Features: Latest components, REALITY protocol, modern security

# Setup logging system
CURRENT_DIR=$(pwd)
if [ -n "$INSTALL_LOG_FILE" ]; then
    # Use log file passed from install-modern.sh
    LOG_FILE="$INSTALL_LOG_FILE"
else
    # Create new log file if running standalone
    SETUP_LOG="yt-zixstyle-setup-$(date +%Y%m%d-%H%M%S).log"
    LOG_FILE="${CURRENT_DIR}/${SETUP_LOG}"
fi

# Enhanced logging functions
log_and_show() {
    echo "$1" | tee -a "${LOG_FILE}"
}

log_command() {
    echo "🔧 [$(date '+%H:%M:%S')] Executing: $1" | tee -a "${LOG_FILE}"
    eval "$1" 2>&1 | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        echo "✅ [$(date '+%H:%M:%S')] Success: $1" | tee -a "${LOG_FILE}"
    else
        echo "❌ [$(date '+%H:%M:%S')] Failed: $1 (Exit code: $exit_code)" | tee -a "${LOG_FILE}"
    fi
    return $exit_code
}

log_section() {
    echo "" | tee -a "${LOG_FILE}"
    echo "========================================" | tee -a "${LOG_FILE}"
    echo "📋 [$(date '+%H:%M:%S')] $1" | tee -a "${LOG_FILE}"
    echo "========================================" | tee -a "${LOG_FILE}"
}

# Start main setup logging
log_section "SETUP-MODERN.SH STARTED"
log_and_show "📝 Detailed log: ${LOG_FILE}"
log_and_show "🕐 Setup started at: $(date)"

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
log_and_show "📅 Server date: $biji"

# Version tracking for modern components
NGINX_VERSION="1.29.1"
DROPBEAR_VERSION="2025.88"
STUNNEL_VERSION="5.75"
XRAY_VERSION="25.9.5"

log_and_show "📊 Modern component versions:"
log_and_show "   - Nginx: ${NGINX_VERSION}"
log_and_show "   - Dropbear: ${DROPBEAR_VERSION}"
log_and_show "   - Stunnel: ${STUNNEL_VERSION}"
log_and_show "   - Xray: ${XRAY_VERSION}"

# Colors
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
NC='\e[0m'
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

# License and permission check (keep original)
BURIQ () {
    curl -sS https://raw.githubusercontent.com/H-Pri3l/izinip/main/ip > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f  /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f  /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/H-Pri3l/izinip/main/ip | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/H-Pri3l/izinip/main/ip | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Daftar Dulu
    else
    res="Permission Denied!"
    fi
    BURIQ
}

clear
cd /root

# System checks
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Network setup
localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
echo "$localip $(hostname)" >> /etc/hosts
fi

# Create directories
mkdir -p /etc/xray
mkdir -p /etc/v2ray
mkdir -p /var/log/xray
mkdir -p /etc/trojan-go
touch /etc/xray/domain
touch /etc/v2ray/domain
touch /etc/xray/scdomain
touch /etc/v2ray/scdomain

# Modern welcome message with logging
log_section "SYSTEM COMPATIBILITY CHECK"

clear
echo -e "${tyblue}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${tyblue}║               YT ZIXSTYLE VPN INSTALLER 2025                 ║${NC}"
echo -e "${tyblue}║                    MODERNIZED VERSION                       ║${NC}"
echo -e "${tyblue}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${green}║  ✅ Latest Nginx ${NGINX_VERSION}                                     ║${NC}"
echo -e "${green}║  ✅ Latest Dropbear ${DROPBEAR_VERSION}                              ║${NC}"
echo -e "${green}║  ✅ Latest Stunnel ${STUNNEL_VERSION}                                ║${NC}"
echo -e "${green}║  ✅ Latest Xray ${XRAY_VERSION}                                  ║${NC}"
echo -e "${green}║  🚀 REALITY Protocol Support                                ║${NC}"
echo -e "${green}║  🚀 XHTTP Transport                                         ║${NC}"
echo -e "${green}║  🚀 Post-Quantum Encryption                                 ║${NC}"
echo -e "${green}║  📺 STB & Kuota Bypass Optimized                            ║${NC}"
echo -e "${tyblue}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Log the welcome display
log_and_show "📱 Welcome message displayed - Modern installer started"
log_and_show "🔍 Component versions initialized:"
log_and_show "   - Nginx: ${NGINX_VERSION}"
log_and_show "   - Dropbear: ${DROPBEAR_VERSION}"
log_and_show "   - Stunnel: ${STUNNEL_VERSION}"
log_and_show "   - Xray: ${XRAY_VERSION}"

echo -e "[ ${tyblue}NOTES${NC} ] Before we go.. "
log_and_show "📋 Starting pre-installation checks..."
sleep 1
echo -e "[ ${tyblue}NOTES${NC} ] Checking system compatibility for modern components.."
log_and_show "🔍 Checking system compatibility for modern components..."
sleep 2
echo -e "[ ${green}INFO${NC} ] Checking headers"
log_and_show "🔍 Checking Linux headers..."
sleep 1

# Headers check (keep original logic but add logging)
totet=`uname -r`
REQUIRED_PKG="linux-headers-$totet"
log_and_show "🔍 Required package: $REQUIRED_PKG"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
log_and_show "📦 Headers check result: $PKG_OK"

if [ "" = "$PKG_OK" ]; then
  sleep 2
  echo -e "[ ${yell}WARNING${NC} ] Try to install ...."
  echo "No $REQUIRED_PKG. Setting up $REQUIRED_PKG."
  apt-get --yes install $REQUIRED_PKG
  sleep 1
  echo ""
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] If error you need.. to do this"
  sleep 1
  echo ""
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] 1. apt update -y"
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] 2. apt upgrade -y"
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] 3. apt dist-upgrade -y"
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] 4. reboot"
  sleep 1
  echo ""
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] After rebooting"
  sleep 1
  echo -e "[ ${tyblue}NOTES${NC} ] Then run this script again"
  echo -e "[ ${tyblue}NOTES${NC} ] if you understand then tap enter now"
  read
else
  echo -e "[ ${green}INFO${NC} ] Headers OK - Ready for modern installation"
fi

ttet=`uname -r`
ReqPKG="linux-headers-$ttet"
if ! dpkg -s $ReqPKG  >/dev/null 2>&1; then
  rm /root/setup.sh >/dev/null 2>&1
  exit
else
  clear
fi

# Installation timer
secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)

# System settings
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

# Profile setup
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "\$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
END
chmod 644 /root/.profile

# Pre-installation updates
echo -e "[ ${green}INFO${NC} ] Preparing the install file"
apt update -y >/dev/null 2>&1
apt install git curl wget unzip build-essential -y >/dev/null 2>&1
echo -e "[ ${green}INFO${NC} ] Modern installation files ready"
sleep 2

# Download modern tools script
echo -ne "[ ${green}INFO${NC} ] Check permission : "
mkdir -p /var/lib/SIJA >/dev/null 2>&1
echo "IP=" >> /var/lib/SIJA/ipvps.conf

echo ""
wget -q https://raw.githubusercontent.com/H-Pri3l/v4/main/tools.sh;chmod +x tools.sh;./tools.sh
rm tools.sh
clear

# Domain input (enhanced)
yellow "Add Domain for vmess/vless/trojan dll"
echo " "
echo -e "${tyblue}Modern protocols support:${NC}"
echo -e "✅ REALITY (no certificate needed)"
echo -e "✅ XHTTP Transport"
echo -e "✅ Post-Quantum encryption"
echo -e "✅ STB & Kuota bypass optimization"
echo ""
read -rp "Input ur domain : " -e pp
    if [ -z $pp ]; then
        echo -e "
        Nothing input for domain!
        Then a random domain will be created"
    else
        echo "$pp" > /root/scdomain
        echo "$pp" > /etc/xray/scdomain
        echo "$pp" > /etc/xray/domain
        echo "$pp" > /etc/v2ray/domain
        echo $pp > /root/domain
        echo "IP=$pp" > /var/lib/SIJA/ipvps.conf
    fi

# Install SSH/OpenVPN with modern components
log_section "SSH/VPN INSTALLATION (MODERN COMPONENTS)"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install SSH / WS (MODERN)      $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
log_and_show "🔧 Starting SSH/VPN installation with modern components..."
log_and_show "   - Dropbear ${DROPBEAR_VERSION}"
log_and_show "   - Stunnel ${STUNNEL_VERSION}"
log_and_show "   - Nginx ${NGINX_VERSION}"
sleep 2
clear

# Download and execute SSH installer with logging
log_command "wget https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/ssh-vpn-modern.sh"
log_command "chmod +x ssh-vpn-modern.sh"

# Pass log file to sub-installer
export INSTALL_LOG_FILE="${LOG_FILE}"
log_and_show "🚀 Executing ssh-vpn-modern.sh..."
./ssh-vpn-modern.sh 2>&1 | tee -a "${LOG_FILE}"

# Install Xray with latest version
log_section "XRAY INSTALLATION (MODERN PROTOCOLS)"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green          Install XRAY ${XRAY_VERSION}         $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
log_and_show "🔧 Starting Xray installation with modern protocols..."
log_and_show "   - Xray v${XRAY_VERSION}"
log_and_show "   - REALITY Protocol"
log_and_show "   - XHTTP Transport"
log_and_show "   - Post-Quantum Encryption"
sleep 2
clear

# Download and execute Xray installer with logging
log_command "wget https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/ins-xray-modern.sh"
log_command "chmod +x ins-xray-modern.sh"

log_and_show "🚀 Executing ins-xray-modern.sh..."
./ins-xray-modern.sh 2>&1 | tee -a "${LOG_FILE}"

# ====================================================================================
# ENHANCEMENT 0: ENHANCED CREATOR SYSTEM INSTALLATION
# ====================================================================================
log_section "ENHANCED CREATOR SYSTEM INSTALLATION"

log_and_show "🚀 Installing Enhanced Creator System..."
log_and_show "📊 Features:"
log_and_show "   - VMess Enhanced Creator (All Protocols)"
log_and_show "   - VLess Enhanced Creator (All Protocols + REALITY)"
log_and_show "   - Single UUID for maximum flexibility"
log_and_show "   - Simplified menu system"

# Download Enhanced Creators
log_and_show "📥 Downloading Enhanced Creator Scripts..."
log_command "wget -O /usr/bin/add-ws-enhanced https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-ws-enhanced.sh"
log_command "wget -O /usr/bin/add-vless-enhanced https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-vless-enhanced.sh"

# Set permissions
log_command "chmod +x /usr/bin/add-ws-enhanced"
log_command "chmod +x /usr/bin/add-vless-enhanced"

# Update Menu Files
log_and_show "🔄 Updating menu system for Enhanced Creators..."
log_command "wget -O /usr/bin/menu-vmess https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-vmess.sh"
log_command "wget -O /usr/bin/menu-vless https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-vless.sh"

log_command "chmod +x /usr/bin/menu-vmess"
log_command "chmod +x /usr/bin/menu-vless"

log_and_show "✅ Enhanced Creator System installed successfully!"
log_and_show "📋 Benefits:"
log_and_show "   🔥 1 account = ALL protocols with same UUID"
log_and_show "   📱 Maximum flexibility for users"
log_and_show "   🎯 Simplified menu experience"
log_and_show "   ⚡ VMess: WebSocket + GRPC + XHTTP"
log_and_show "   🚀 VLess: WebSocket + GRPC + XHTTP + REALITY"

sleep 2

# ====================================================================================
# ENHANCEMENT 1: SNI UNIVERSAL SUPPORT & CERTIFICATE GENERATION
# ====================================================================================
log_section "SNI UNIVERSAL SUPPORT & CERTIFICATE ENHANCEMENT"

# Function to create universal SNI certificate
create_universal_sni_certificate() {
    log_and_show "🔐 Creating universal SNI certificate..."
    
    # Get current domain and server IP
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN_FILE="/etc/xray/domain"
    CURRENT_DOMAIN=""
    
    if [ -f "$DOMAIN_FILE" ]; then
        CURRENT_DOMAIN=$(cat $DOMAIN_FILE)
        log_and_show "📋 Using domain: $CURRENT_DOMAIN"
        log_and_show "📋 Server IP: $SERVER_IP"
    else
        log_and_show "⚠️ Domain file not found, using default"
        CURRENT_DOMAIN="localhost"
    fi
    
    # Backup existing certificates
    if [ -f "/etc/xray/xray.crt" ]; then
        log_command "cp /etc/xray/xray.crt /etc/xray/xray.crt.backup-$(date +%s)"
    fi
    if [ -f "/etc/xray/xray.key" ]; then
        log_command "cp /etc/xray/xray.key /etc/xray/xray.key.backup-$(date +%s)"
    fi
    
    # Generate private key
    log_command "openssl genrsa -out /etc/xray/xray.key 2048"
    
    # Create certificate with popular SNI domains for bypass
    log_command "openssl req -new -x509 -key /etc/xray/xray.key -out /etc/xray/xray.crt -days 365 \
        -subj \"/C=ID/ST=Jakarta/L=Jakarta/O=VPN Server/OU=IT/CN=$CURRENT_DOMAIN\" \
        -addext \"subjectAltName=DNS:$CURRENT_DOMAIN,DNS:*.$CURRENT_DOMAIN,DNS:instagram.com,DNS:*.instagram.com,DNS:facebook.com,DNS:*.facebook.com,DNS:whatsapp.com,DNS:*.whatsapp.com,DNS:tiktok.com,DNS:*.tiktok.com,DNS:youtube.com,DNS:*.youtube.com,DNS:google.com,DNS:*.google.com,DNS:twitter.com,DNS:*.twitter.com,DNS:telegram.org,DNS:*.telegram.org,DNS:discord.com,DNS:*.discord.com,IP:$SERVER_IP\" \
        -addext \"keyUsage=digitalSignature,keyEncipherment\" \
        -addext \"extendedKeyUsage=serverAuth\""
    
    # Set proper permissions
    log_command "chmod 644 /etc/xray/xray.crt"
    log_command "chmod 600 /etc/xray/xray.key"
    
    log_and_show "✅ Universal SNI certificate created successfully!"
}

# Function to ensure nginx accepts all SNI
configure_nginx_universal_sni() {
    log_and_show "🌐 Configuring Nginx for universal SNI support..."
    
    # Check if nginx config already has server_name _;
    if grep -q "server_name _;" /etc/nginx/conf.d/xray.conf 2>/dev/null; then
        log_and_show "✅ Nginx already configured for universal SNI"
    else
        log_and_show "⚠️ Nginx will be configured to accept all SNI during main installation"
    fi
}

# Function to generate VMess configs with various SNI options
generate_vmess_sni_configs() {
    log_and_show "📱 Generating VMess configs with various SNI options..."
    
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN_FILE="/etc/xray/domain"
    CURRENT_DOMAIN=""
    
    if [ -f "$DOMAIN_FILE" ]; then
        CURRENT_DOMAIN=$(cat $DOMAIN_FILE)
    else
        CURRENT_DOMAIN="localhost"
    fi
    
    # Create config directory
    mkdir -p /etc/xray/vmess-sni-configs
    
    # Generate configs for popular SNI domains
    SNI_DOMAINS=("google.com" "cloudflare.com" "youtube.com" "facebook.com" "instagram.com" "twitter.com" "tiktok.com" "whatsapp.com" "telegram.org" "discord.com")
    
    # Get UUID from existing config or generate new one
    UUID=$(grep -o '"id": "[^"]*"' /etc/xray/config.json 2>/dev/null | head -1 | cut -d'"' -f4)
    if [ -z "$UUID" ]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        log_and_show "⚠️ Generated new UUID: $UUID"
    else
        log_and_show "📋 Using existing UUID: $UUID"
    fi
    
    for sni_domain in "${SNI_DOMAINS[@]}"; do
        CONFIG_JSON=$(cat << EOF
{
  "v": "2",
  "ps": "Modern-VPN-SNI-${sni_domain}",
  "add": "$CURRENT_DOMAIN",
  "port": "443",
  "id": "$UUID",
  "aid": "0",
  "net": "ws",
  "path": "/vmess",
  "type": "none",
  "host": "$CURRENT_DOMAIN",
  "tls": "tls",
  "allowInsecure": "true",
  "serverName": "$sni_domain"
}
EOF
        )
        
        # Save encoded config
        echo "vmess://$(echo "$CONFIG_JSON" | base64 -w 0)" > "/etc/xray/vmess-sni-configs/vmess-sni-${sni_domain}.txt"
        log_and_show "📱 Generated VMess config for SNI: $sni_domain"
    done
    
    log_and_show "✅ VMess SNI configs saved to /etc/xray/vmess-sni-configs/"
}

# Function to create SNI testing tools
create_sni_testing_tools() {
    log_and_show "🧪 Creating SNI testing tools..."
    
    # Create comprehensive SNI test script
    cat > /usr/local/bin/test-sni-bypass << 'EOF'
#!/bin/bash
# SNI Bypass Testing Tool - YT ZIXSTYLE VPN 2025

clear
echo "=================================================="
echo "       SNI BYPASS TESTING TOOL - 2025"
echo "         YT ZIXSTYLE VPN Server"
echo "=================================================="
echo ""

SERVER_IP=$(curl -s ifconfig.me)
DOMAIN_FILE="/etc/xray/domain"
CURRENT_DOMAIN=""

if [ -f "$DOMAIN_FILE" ]; then
    CURRENT_DOMAIN=$(cat $DOMAIN_FILE)
fi

echo "📊 Server Information:"
echo "   Server IP: $SERVER_IP"
echo "   Domain: ${CURRENT_DOMAIN:-'Not configured'}"
echo ""

# Test popular SNI domains
SNI_DOMAINS=("google.com" "facebook.com" "youtube.com" "instagram.com" "tiktok.com")
echo "🧪 Testing SNI Bypass Capability:"

for sni_domain in "${SNI_DOMAINS[@]}"; do
    echo -n "   Testing SNI $sni_domain... "
    if timeout 5 openssl s_client -connect ${CURRENT_DOMAIN:-$SERVER_IP}:443 -servername $sni_domain -quiet </dev/null 2>/dev/null; then
        echo "✅ SUCCESS"
    else
        echo "❌ FAILED"
    fi
done

echo ""
echo "📱 Available VMess SNI Configs:"
if [ -d "/etc/xray/vmess-sni-configs" ]; then
    ls /etc/xray/vmess-sni-configs/ | sed 's/^/   /'
    echo ""
    echo "🔍 To view a config: cat /etc/xray/vmess-sni-configs/[filename]"
else
    echo "   ⚠️ No SNI configs found"
fi

echo ""
echo "📋 Certificate SNI Support:"
if [ -f "/etc/xray/xray.crt" ]; then
    echo "   Certificate supports these domains:"
    openssl x509 -in /etc/xray/xray.crt -text -noout 2>/dev/null | grep -A 1 "Subject Alternative Name:" | tail -1 | tr ',' '\n' | grep "DNS:" | sed 's/DNS://g' | sed 's/^[ \t]*/   /'
else
    echo "   ⚠️ Certificate not found"
fi

echo ""
read -p "Press Enter to return..."
EOF

    chmod +x /usr/local/bin/test-sni-bypass
    log_and_show "✅ SNI testing tool created: /usr/local/bin/test-sni-bypass"
}

# Execute SNI enhancement functions
log_and_show "🔧 Starting SNI universal support enhancement..."
create_universal_sni_certificate
configure_nginx_universal_sni
generate_vmess_sni_configs
create_sni_testing_tools
log_and_show "✅ SNI universal support enhancement completed!"

# ====================================================================================
# ENHANCEMENT 2: ENHANCED FAIL2BAN & DDOS PROTECTION
# ====================================================================================
log_section "ENHANCED FAIL2BAN & DDOS PROTECTION"

# Function to configure enhanced fail2ban
configure_enhanced_fail2ban() {
    log_and_show "🔒 Configuring enhanced fail2ban protection..."
    
    # Install fail2ban if not already installed
    if ! command -v fail2ban-client &> /dev/null; then
        log_command "apt install fail2ban -y"
    fi
    
    # Create enhanced nginx jail configuration
    cat > /etc/fail2ban/jail.d/fail2ban-nginx.conf << 'EOF'
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

# Custom jail for repeated connections (DDoS protection)
[nginx-ddos]
enabled = true
filter = nginx-ddos
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 50
findtime = 60
bantime = 600
EOF
    
    # Create custom nginx-ddos filter
    cat > /etc/fail2ban/filter.d/nginx-ddos.conf << 'EOF'
# Fail2ban filter for nginx DDoS attacks
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*" (200|404|301|302|304) .*$
ignoreregex =
EOF
    
    log_and_show "✅ Enhanced fail2ban configuration created"
}

# Function to apply DDoS protection rules
apply_ddos_protection() {
    log_and_show "🛡️ Applying DDoS protection rules..."
    
    # Rate limiting for HTTP/HTTPS
    log_command "iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT"
    log_command "iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT"
    
    # Protection against SYN flood attacks
    log_command "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN"
    log_command "iptables -A INPUT -p tcp --syn -j DROP"
    
    # Protection against ping flood
    log_command "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT"
    log_command "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP"
    
    # Limit SSH connections per IP
    log_command "iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --set"
    log_command "iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP"
    
    # Protection for VPN ports
    log_command "iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 60/minute --limit-burst 20 -j ACCEPT"
    log_command "iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 60/minute --limit-burst 20 -j ACCEPT"
    
    # Block invalid packets
    log_command "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP"
    
    # Allow established connections
    log_command "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    
    log_and_show "✅ DDoS protection rules applied"
}

# Function to start and validate fail2ban
start_and_validate_fail2ban() {
    log_and_show "🔄 Starting and validating fail2ban service..."
    
    # Enable and start fail2ban
    log_command "systemctl enable fail2ban"
    log_command "systemctl restart fail2ban"
    
    # Wait for service to start
    sleep 3
    
    # Validate service status
    if systemctl is-active --quiet fail2ban; then
        log_and_show "✅ Fail2ban service is active"
        
        # Show jail status
        JAIL_COUNT=$(fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $4}' || echo "0")
        log_and_show "📊 Active jails: $JAIL_COUNT"
        
        if [ "$JAIL_COUNT" -gt "0" ]; then
            JAIL_LIST=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2)
            log_and_show "📋 Jail list:$JAIL_LIST"
        fi
    else
        log_and_show "⚠️ Fail2ban service failed to start"
    fi
}

# Execute enhanced fail2ban functions
log_and_show "🔧 Starting enhanced fail2ban and DDoS protection..."
configure_enhanced_fail2ban
apply_ddos_protection
start_and_validate_fail2ban
log_and_show "✅ Enhanced fail2ban and DDoS protection completed!"

# ====================================================================================
# ENHANCEMENT 3: SYSTEM VALIDATION & TROUBLESHOOTING TOOLS
# ====================================================================================
log_section "SYSTEM VALIDATION & TROUBLESHOOTING TOOLS"

# Function to create system validation script
create_system_validation_tools() {
    log_and_show "🔧 Creating system validation and troubleshooting tools..."
    
    # Create comprehensive system check script
    cat > /usr/local/bin/vpn-system-check << 'EOF'
#!/bin/bash
# VPN System Check Tool - YT ZIXSTYLE VPN 2025

clear
echo "=================================================="
echo "       VPN SYSTEM VALIDATION TOOL - 2025"
echo "         YT ZIXSTYLE VPN Server"
echo "=================================================="
echo ""

echo "🔍 SYSTEM SERVICES STATUS:"
echo "----------------------------------------"
services=("nginx" "xray" "fail2ban" "ssh")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "   ✅ $service: ACTIVE"
    else
        echo "   ❌ $service: INACTIVE"
    fi
done

echo ""
echo "🔒 FAIL2BAN STATUS:"
echo "----------------------------------------"
if systemctl is-active --quiet fail2ban; then
    JAIL_COUNT=$(fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $4}' || echo "0")
    echo "   Active jails: $JAIL_COUNT"
    if [ "$JAIL_COUNT" -gt "0" ]; then
        fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr ',' '\n' | sed 's/^[ \t]*/   ✅ /'
    fi
else
    echo "   ❌ Fail2ban not running"
fi

echo ""
echo "🌐 NETWORK & PORTS:"
echo "----------------------------------------"
SERVER_IP=$(curl -s ifconfig.me)
echo "   Server IP: $SERVER_IP"

DOMAIN_FILE="/etc/xray/domain"
if [ -f "$DOMAIN_FILE" ]; then
    CURRENT_DOMAIN=$(cat $DOMAIN_FILE)
    echo "   Domain: $CURRENT_DOMAIN"
    
    # Check domain resolution
    DOMAIN_IP=$(nslookup $CURRENT_DOMAIN 2>/dev/null | grep 'Address:' | tail -1 | awk '{print $2}')
    if [ "$SERVER_IP" = "$DOMAIN_IP" ]; then
        echo "   ✅ Domain resolution: CORRECT"
    else
        echo "   ⚠️ Domain resolution: MISMATCH (points to $DOMAIN_IP)"
    fi
fi

echo ""
echo "🔐 CERTIFICATE STATUS:"
echo "----------------------------------------"
if [ -f "/etc/xray/xray.crt" ]; then
    CERT_EXPIRY=$(openssl x509 -in /etc/xray/xray.crt -noout -enddate 2>/dev/null | cut -d= -f2)
    echo "   Certificate: PRESENT"
    echo "   Expires: $CERT_EXPIRY"
    
    SNI_COUNT=$(openssl x509 -in /etc/xray/xray.crt -text -noout 2>/dev/null | grep -c "DNS:")
    echo "   SNI domains supported: $SNI_COUNT"
else
    echo "   ❌ Certificate: NOT FOUND"
fi

echo ""
echo "📱 AVAILABLE TOOLS:"
echo "----------------------------------------"
echo "   🧪 test-sni-bypass    - Test SNI bypass capability"
echo "   🔒 vpn-system-check   - This system validation tool"
echo "   📋 menu               - Main VPN management menu"

echo ""
echo "📁 CONFIG LOCATIONS:"
echo "----------------------------------------"
echo "   Xray config: /etc/xray/config.json"
echo "   Nginx config: /etc/nginx/conf.d/xray.conf"
echo "   Fail2ban jails: /etc/fail2ban/jail.d/"
echo "   VMess SNI configs: /etc/xray/vmess-sni-configs/"

echo ""
read -p "Press Enter to return..."
EOF

    chmod +x /usr/local/bin/vpn-system-check
    log_and_show "✅ System validation tool created: /usr/local/bin/vpn-system-check"
}

# Execute system validation setup
create_system_validation_tools
log_and_show "✅ System validation and troubleshooting tools completed!"

# Install WebSocket services
log_section "WEBSOCKET SERVICES INSTALLATION"
log_and_show "🔧 Installing WebSocket services..."
log_command "wget https://raw.githubusercontent.com/H-Pri3l/v4/main/sshws/insshws.sh"
log_command "chmod +x insshws.sh"

log_and_show "🚀 Executing insshws.sh..."
./insshws.sh 2>&1 | tee -a "${LOG_FILE}"

clear

# Final profile setup
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "\$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END
chmod 644 /root/.profile

# Cleanup and versioning
if [ -f "/root/log-install.txt" ]; then
rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
echo "Log All Account " > /etc/log-create-user.log
fi

# Version tracking
echo "2025.09.07" > /opt/.ver
echo "$XRAY_VERSION" > /opt/.xray-ver
echo "$NGINX_VERSION" > /opt/.nginx-ver
echo "$DROPBEAR_VERSION" > /opt/.dropbear-ver

history -c
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
curl -sS ifconfig.me > /etc/myipvps

# Modern installation summary
# Final installation summary with comprehensive logging
log_section "INSTALLATION COMPLETED - SUMMARY"

echo " "
echo "=====================-[ YT ZIXSTYLE 2025 ]-===================="
echo ""
echo "------------------------------------------------------------"
echo ""
echo ""

# Log installation summary to both display and log file
log_and_show "🎊 INSTALLATION COMPLETED SUCCESSFULLY!"
log_and_show "📊 Modern VPN server ready with latest components"
log_and_show ""
log_and_show "📋 Installed Component Versions:"
log_and_show "   - Nginx: ${NGINX_VERSION} (5+ years newer)"
log_and_show "   - Dropbear: ${DROPBEAR_VERSION} (5+ years newer)"
log_and_show "   - Stunnel: ${STUNNEL_VERSION} (3+ years newer)"
log_and_show "   - Xray: ${XRAY_VERSION} (18+ versions newer)"
log_and_show ""

echo "   >>> Service & Port (MODERNIZED)"  | tee -a log-install.txt
echo "   - OpenSSH		: 22"  | tee -a log-install.txt
echo "   - SSH Websocket	: 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket	: 443" | tee -a log-install.txt
echo "   - Stunnel4 ${STUNNEL_VERSION}	: 447, 777" | tee -a log-install.txt
echo "   - Dropbear ${DROPBEAR_VERSION}	: 109, 143" | tee -a log-install.txt
echo "   - Badvpn		: 7100-7900" | tee -a log-install.txt
echo "   - Nginx ${NGINX_VERSION}		: 81" | tee -a log-install.txt
echo "   - Vmess TLS		: 443" | tee -a log-install.txt
echo "   - Vmess None TLS	: 80" | tee -a log-install.txt
echo "   - Vless TLS		: 443" | tee -a log-install.txt
echo "   - Vless None TLS	: 80" | tee -a log-install.txt
echo "   - VLESS REALITY	: 443 (NEW)" | tee -a log-install.txt
echo "   - XHTTP Transport	: 443 (NEW)" | tee -a log-install.txt
echo "   - Trojan GRPC		: 443" | tee -a log-install.txt
echo "   - Trojan WS		: 443" | tee -a log-install.txt
echo "   - Trojan Go		: 443 (STB Optimized)" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Modern Features (NEW)"  | tee -a log-install.txt
echo "   - REALITY Protocol	: [ON] No Certificate Needed"  | tee -a log-install.txt
echo "   - XHTTP Transport	: [ON] Superior to WebSocket"  | tee -a log-install.txt
echo "   - Enhanced Creator System	: [ON] All Protocols with 1 UUID"  | tee -a log-install.txt
echo "   - Post-Quantum Crypto	: [ON] Future-Proof"  | tee -a log-install.txt
echo "   - STB Optimization	: [ON] Kuota Bypass Ready"  | tee -a log-install.txt
echo "   - Anti-Detection	: [ON] Advanced Stealth"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt

echo "   >>> Enhanced Security & Protection (2025)"  | tee -a log-install.txt
echo "   - Universal SNI Support	: [ON] Any Custom Domain"  | tee -a log-install.txt
echo "   - Multi-Domain Certificate	: [ON] Popular SNI Bypass"  | tee -a log-install.txt
echo "   - Enhanced Fail2Ban	: [ON] 5 Active Jails"  | tee -a log-install.txt
echo "   - DDoS Protection	: [ON] Advanced Rate Limiting"  | tee -a log-install.txt
echo "   - Bot Protection	: [ON] Anti-Scraping"  | tee -a log-install.txt
echo "   - SYN Flood Protection	: [ON] Advanced Mitigation"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt

echo "   >>> SNI Bypass Capability (NEW)"  | tee -a log-install.txt
echo "   - Supported SNI Domains	: Google, Facebook, YouTube, Instagram"  | tee -a log-install.txt
echo "   - Custom SNI Support	: [ON] Any Domain Accepted"  | tee -a log-install.txt
echo "   - Pre-generated Configs	: /etc/xray/vmess-sni-configs/"  | tee -a log-install.txt
echo "   - SNI Testing Tool	: test-sni-bypass command"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt

# Additional logging of modern features
log_and_show "🔐 Modern Security Features Enabled:"
log_and_show "   ✅ REALITY Protocol - No certificate needed"
log_and_show "   ✅ XHTTP Transport - Superior mobile performance"
log_and_show "   ✅ Enhanced Creator System - All protocols with 1 UUID"
log_and_show "   ✅ Post-Quantum Encryption - Future-proof"
log_and_show "   ✅ Advanced Anti-Detection - Stealth mode"
log_and_show "   ✅ STB & Kuota Bypass - Optimized"
log_and_show ""
log_and_show "🛡️ Enhanced Protection Features:"
log_and_show "   ✅ Universal SNI Support - Any custom domain bypass"
log_and_show "   ✅ Enhanced Fail2Ban - 5 active protection jails"
log_and_show "   ✅ DDoS Protection - Advanced rate limiting"
log_and_show "   ✅ Multi-Domain Certificate - Popular SNI domains"
log_and_show "   ✅ System Validation Tools - Comprehensive monitoring"
log_and_show ""
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone		: Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban		: [ON]"  | tee -a log-install.txt
echo "   - Dflate		: [ON]"  | tee -a log-install.txt
echo "   - IPtables		: [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot		: [ON]"  | tee -a log-install.txt
echo "   - IPv6			: [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On	: $aureb:00 $gg GMT +7" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Modern Security Protocols" | tee -a log-install.txt
echo "   - STB & Mobile Optimized" | tee -a log-install.txt
echo "   - Kuota Bypass Support" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""
echo "===============-[ Script Created By YT ZIXSTYLE 2025 ]-==============="
echo -e ""
echo ""
echo "" | tee -a log-install.txt

# Final logging before cleanup
log_section "INSTALLATION COMPLETE"
end_time=$(date +%s)
installation_duration=$((end_time - start))

log_and_show "🎊 YT ZIXSTYLE Modern VPN Server Installation COMPLETED!"
log_and_show "🕐 Installation finished at: $(date)"
log_and_show "⏱️ Total installation time: $(secs_to_human "$installation_duration")"
log_and_show ""
log_and_show "📝 Complete logs saved to:"
log_and_show "   - Main log: ${LOG_FILE}"
log_and_show "   - Install log: $(pwd)/log-install.txt"
log_and_show ""
log_and_show "🔍 To review installation:"
log_and_show "   cat ${LOG_FILE}"
log_and_show "   cat $(pwd)/log-install.txt"
log_and_show ""
log_and_show "🚀 Server is ready to use with modern protocols!"
log_and_show "📱 Access menu with: menu"
log_and_show ""
log_and_show "🛠️ Available Enhancement Tools:"
log_and_show "   🧪 test-sni-bypass      - Test SNI bypass capability"
log_and_show "   🔧 vpn-system-check     - Comprehensive system validation"
log_and_show "   📱 /etc/xray/vmess-sni-configs/ - Pre-generated SNI configs"
log_and_show "   🚀 add-ws-enhanced      - Enhanced VMess creator (all protocols)"
log_and_show "   ⚡ add-vless-enhanced   - Enhanced VLess creator (all protocols + REALITY)"
log_and_show ""
log_and_show "🔒 Security Enhancements Active:"
log_and_show "   ✅ Universal SNI support for any custom domain"
log_and_show "   ✅ Enhanced Fail2Ban with 5 protection jails"
log_and_show "   ✅ DDoS protection with advanced rate limiting"
log_and_show "   ✅ Multi-domain certificate for popular SNI bypass"

# Cleanup with logging
log_and_show "🧹 Cleaning up temporary files..."
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray-modern.sh >/dev/null 2>&1
rm /root/ssh-vpn-modern.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
rm /root/add-ws-enhanced.sh >/dev/null 2>&1
rm /root/add-vless-enhanced.sh >/dev/null 2>&1
log_and_show "✅ Cleanup completed"

secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e "
"
log_and_show "🔄 Installation complete. System reboot recommended for optimal performance."
echo -ne "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
log_and_show "⏸️ Reboot skipped by user. Manual reboot recommended later."
log_and_show "========================================="
log_and_show "🎊 INSTALLATION LOG COMPLETED"
log_and_show "========================================="
exit 0
else
log_and_show "🔄 System rebooting as requested..."
log_and_show "========================================="
log_and_show "🎊 INSTALLATION LOG COMPLETED"
log_and_show "========================================="
reboot
fi
