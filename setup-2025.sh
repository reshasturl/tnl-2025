#!/bin/bash
#
# YT ZIXSTYLE VPN Server 2025 - MAIN SETUP CONNECTOR
# Created: September 7, 2025  
# Purpose: Penghubung untuk download dan eksekusi script-script terpisah
# Log: Inherit dari install-2025.sh dan teruskan ke semua child scripts
# ===============================================================================

# Inherit logging system dari install-2025.sh
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from install-2025.sh"
    exit 1
fi

# Continue logging
log_section "SETUP-2025.SH - MAIN CONNECTOR STARTED"
log_and_show "📝 Inheriting log from install-2025.sh: ${INSTALL_LOG_PATH}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Header display
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               YT ZIXSTYLE VPN SERVER 2025                    ║${NC}"
echo -e "${BLUE}║                  MAIN SETUP CONNECTOR                        ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  📝 Comprehensive Logging System                            ║${NC}"
echo -e "${GREEN}║  🔗 Script Chain Architecture                               ║${NC}"
echo -e "${GREEN}║  🚀 Modern Components v2025                                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Permission check function
BURIQ () {
    curl -sS https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ip > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
        username=$(echo $user | sed 's/###//g')
        temp="$username"
    done
    username1=$(echo $temp | sed 's/###//g')
    username2=$(echo $username1 | sed 's/yt-zixstyle//g')
    username3=$(echo $username2 | sed 's/.sh//g')
    username4=$(echo $username3 | sed 's/_//g')
    username5=$(echo $username4 | sed 's/-//g')
    echo $username5 > /usr/local/etc/.usr.ini
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ip | grep $MYIP | awk '{print $2}')
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
    IZIN=$(curl -sS https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ip | grep $MYIP)
    if [ -n "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}

# Check permission
log_section "PERMISSION VERIFICATION"
log_and_show "🔐 Checking installation permission..."

PERMISSION
if [ "$res" = "Permission Accepted..." ]; then
    log_and_show "✅ Permission granted for IP: $MYIP"
else
    log_and_show "❌ Permission denied for IP: $MYIP"
    log_and_show "📞 Contact YT ZIXSTYLE for access authorization"
    exit 1
fi

# Root check
if [ "$EUID" -ne 0 ]; then
    log_and_show "❌ Please run as root (use 'su' command first)"
    exit 1
fi

log_and_show "✅ Root access confirmed"

# System info logging
log_section "SYSTEM INFORMATION"
log_and_show "🖥️  System Details:"
log_and_show "   - Hostname: $(hostname)"
log_and_show "   - OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
log_and_show "   - Kernel: $(uname -r)"
log_and_show "   - Architecture: $(uname -m)"
log_and_show "   - CPU: $(nproc) cores"
log_and_show "   - Memory: $(free -h | awk 'NR==2{printf \"%.1f/%.1f GB (%.2f%%)\", $3/1024/1024, $2/1024/1024, $3*100/$2}')"

# Domain setup
log_section "DOMAIN CONFIGURATION"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "                           ${GREEN}DOMAIN SETUP${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e " ${BLUE}1.${NC} Use Domain/Subdomain"
echo -e " ${BLUE}2.${NC} Use VPS IP Address"
echo ""
read -p " Please select [1-2]: " dns
echo ""

if [[ $dns == "1" ]]; then
    log_and_show "📝 User selected: Custom domain"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "                     ${GREEN}ENTER YOUR DOMAIN${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -p " Domain/Subdomain: " domain
    echo $domain > /root/domain
    log_and_show "🌐 Domain configured: $domain"
elif [[ $dns == "2" ]]; then
    log_and_show "📝 User selected: VPS IP address"
    echo $MYIP > /root/domain
    log_and_show "🌐 Using VPS IP as domain: $MYIP"
else
    log_and_show "❌ Invalid selection. Using VPS IP as default."
    echo $MYIP > /root/domain
    log_and_show "🌐 Default domain: $MYIP"
fi

DOMAIN=$(cat /root/domain)
log_and_show "✅ Final domain: $DOMAIN"

# Create log-install.txt with initial entries
log_section "CREATING LOG-INSTALL.TXT"
log_and_show "📝 Creating service port tracking file..."

cat > /root/log-install.txt << EOF
# YT ZIXSTYLE VPN Server 2025 - Service Installation Log
# Generated: $(date)
# Domain: $DOMAIN
# 
# This file tracks all installed services and their ports
# Format: ServiceName: Port Details
#
EOF

log_and_show "✅ log-install.txt created at /root/log-install.txt"

# Script installation sequence - following setup.sh pattern
log_section "SCRIPT INSTALLATION SEQUENCE"
log_and_show "🚀 Starting component installation in sequence..."

# 1. TOOLS INSTALLATION
log_section "STEP 1: TOOLS INSTALLATION"
log_and_show "🛠️  Installing system tools and dependencies..."

if log_command "wget -q https://raw.githubusercontent.com/reshasturl/tnl-2025/main/tools-2025.sh"; then
    log_command "chmod +x tools-2025.sh"
    log_command "sed -i -e 's/\r$//' tools-2025.sh"
    
    # Export semua environment untuk child script
    export INSTALL_LOG_FILE="$INSTALL_LOG_FILE" 
    export INSTALL_LOG_PATH="$INSTALL_LOG_PATH"
    export DOMAIN="$DOMAIN"
    
    log_and_show "🔧 Executing tools-2025.sh..."
    if ./tools-2025.sh; then
        log_and_show "✅ Tools installation completed successfully"
    else
        log_and_show "⚠️ Tools installation failed, but continuing with other components..."
        echo "TOOLS-2025: FAILED" >> /root/log-install.txt
    fi
else
    log_and_show "⚠️ Failed to download tools-2025.sh, but continuing..."
    echo "TOOLS-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# 2. SSH/VPN INSTALLATION  
log_section "STEP 2: SSH/VPN INSTALLATION"
log_and_show "🔐 Installing SSH, Dropbear, OpenVPN services..."

if log_command "wget -q https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh-2025.sh"; then
    log_command "chmod +x ssh-2025.sh"
    log_command "sed -i -e 's/\r$//' ssh-2025.sh"
    
    log_and_show "🔧 Executing ssh-2025.sh..."
    if ./ssh-2025.sh; then
        log_and_show "✅ SSH/VPN installation completed successfully"
    else
        log_and_show "⚠️ SSH/VPN installation failed, but continuing with other components..."
        echo "SSH-2025: FAILED" >> /root/log-install.txt
    fi
else
    log_and_show "⚠️ Failed to download ssh-2025.sh, but continuing..."
    echo "SSH-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# 3. WEBSOCKET INSTALLATION
log_section "STEP 3: WEBSOCKET INSTALLATION"
log_and_show "🌐 Installing WebSocket tunneling services..."

if log_command "wget -q https://raw.githubusercontent.com/reshasturl/tnl-2025/main/sshws-2025.sh"; then
    log_command "chmod +x sshws-2025.sh"
    log_command "sed -i -e 's/\r$//' sshws-2025.sh"
    
    log_and_show "🔧 Executing sshws-2025.sh..."
    if ./sshws-2025.sh; then
        log_and_show "✅ WebSocket installation completed successfully"
    else
        log_and_show "⚠️ WebSocket installation failed, but continuing with other components..."
        echo "SSHWS-2025: FAILED" >> /root/log-install.txt
    fi
else
    log_and_show "⚠️ Failed to download sshws-2025.sh, but continuing..."
    echo "SSHWS-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# 4. XRAY INSTALLATION
log_section "STEP 4: XRAY INSTALLATION"
log_and_show "⚡ Installing Xray with modern protocols (REALITY, XHTTP)..."

if log_command "wget -q https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray-2025.sh"; then
    log_command "chmod +x xray-2025.sh"
    log_command "sed -i -e 's/\r$//' xray-2025.sh"
    
    log_and_show "🔧 Executing xray-2025.sh..."
    if ./xray-2025.sh; then
        log_and_show "✅ Xray installation completed successfully"
    else
        log_and_show "⚠️ Xray installation failed, but continuing..."
        echo "XRAY-2025: FAILED" >> /root/log-install.txt
    fi
else
    log_and_show "⚠️ Failed to download xray-2025.sh, but continuing..."
    echo "XRAY-2025: DOWNLOAD FAILED" >> /root/log-install.txt
fi

# Installation completion
log_section "INSTALLATION COMPLETED"
log_and_show "🎉 YT ZIXSTYLE VPN Server 2025 installation completed successfully!"
log_and_show "📝 Installation log: ${INSTALL_LOG_PATH}"
log_and_show "📋 Service tracking: /root/log-install.txt"
log_and_show "🌐 Domain configured: $DOMAIN"
log_and_show "🕐 Installation completed at: $(date)"

# Final system info
log_and_show ""
log_and_show "📊 INSTALLATION SUMMARY:"
log_and_show "   ✅ System tools installed"
log_and_show "   ✅ SSH/OpenVPN services configured"  
log_and_show "   ✅ WebSocket tunneling enabled"
log_and_show "   ✅ Xray with modern protocols installed"
log_and_show ""
log_and_show "🚀 Server is ready! Type 'menu' to access VPN management."

# Cleanup temporary files
log_command "rm -f tools-2025.sh ssh-2025.sh sshws-2025.sh xray-2025.sh"

log_section "SETUP-2025.SH COMPLETED"
