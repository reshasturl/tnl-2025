#!/bin/bash
#
# YT ZIXSTYLE VPN Server 2025 - INSTALLER ENTRY POINT
# Created: September 7, 2025
# Purpose: Entry point dengan comprehensive logging system
# ===============================================================================

clear
echo -e "\033[96m"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║               YT ZIXSTYLE VPN SERVER 2025                    ║"
echo "  ║                  MODERN INSTALLER v3.0                      ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "\033[0m"

# Setup comprehensive logging system
export INSTALL_START_TIME=$(date +%Y%m%d-%H%M%S)
export INSTALL_LOG_FILE="yt-zixstyle-install-${INSTALL_START_TIME}.log"
export INSTALL_LOG_PATH="$(pwd)/${INSTALL_LOG_FILE}"

# Enhanced logging functions - akan digunakan oleh semua script
log_and_show() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') | $1" | tee -a "${INSTALL_LOG_PATH}"
}

log_command() {
    log_and_show "🔧 EXECUTING: $1"
    eval "$1" 2>&1 | while IFS= read -r line; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') | OUTPUT: $line" | tee -a "${INSTALL_LOG_PATH}"
    done
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        log_and_show "✅ SUCCESS: Command completed successfully"
    else
        log_and_show "❌ ERROR: Command failed with exit code $exit_code"
    fi
    return $exit_code
}

log_section() {
    log_and_show ""
    log_and_show "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_and_show "🎯 $1"
    log_and_show "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Export functions for child scripts
export -f log_and_show
export -f log_command  
export -f log_section

# Start comprehensive installation logging
log_section "YT ZIXSTYLE VPN SERVER 2025 - INSTALLATION STARTED"
log_and_show "📝 Installation log file: ${INSTALL_LOG_PATH}"
log_and_show "🕐 Installation started at: $(date)"
log_and_show "👤 User: $(whoami)"
log_and_show "🖥️  Hostname: $(hostname)"
log_and_show "🌐 IP Address: $(curl -s ipv4.icanhazip.com)"
log_and_show "💿 OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"

# System preparation
log_section "SYSTEM PREPARATION"
log_and_show "🔧 Preparing system for installation..."

log_command "sysctl -w net.ipv6.conf.all.disable_ipv6=1"
log_command "sysctl -w net.ipv6.conf.default.disable_ipv6=1"
log_command "apt update"
log_command "apt install -y bzip2 gzip coreutils screen curl unzip build-essential wget"

# Download main setup script
log_section "DOWNLOADING MAIN SETUP SCRIPT"
log_and_show "📥 Downloading setup-2025.sh..."

if log_command "wget -q https://raw.githubusercontent.com/reshasturl/tnl-2025/main/setup-2025.sh"; then
    log_command "chmod +x setup-2025.sh"
    log_command "sed -i -e 's/\r$//' setup-2025.sh"
    
    log_section "STARTING MAIN INSTALLATION"
    log_and_show "🚀 Executing main installer in screen session..."
    
    # Execute setup with logging continuation
    screen -dmS yt-zixstyle-install bash -c "
        export INSTALL_LOG_FILE='${INSTALL_LOG_FILE}'
        export INSTALL_LOG_PATH='${INSTALL_LOG_PATH}'
        export INSTALL_START_TIME='${INSTALL_START_TIME}'
        export -f log_and_show
        export -f log_command
        export -f log_section
        ./setup-2025.sh
        echo 'Installation completed. Check log: ${INSTALL_LOG_PATH}' | tee -a '${INSTALL_LOG_PATH}'
    "
    
    log_and_show "📺 Installation started in screen session 'yt-zixstyle-install'"
    log_and_show "📝 Monitor installation: tail -f ${INSTALL_LOG_PATH}"
    log_and_show "📺 Attach to session: screen -r yt-zixstyle-install"
    
else
    log_and_show "❌ Failed to download setup-2025.sh"
    exit 1
fi

log_and_show ""
log_and_show "🎉 Installation initiated successfully!"
log_and_show "📝 Complete log will be saved to: ${INSTALL_LOG_PATH}"
echo ""
