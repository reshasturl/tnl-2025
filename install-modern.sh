#!/bin/bash
# YT ZIXSTYLE VPN INSTALLER 2025 - ONE-LINE COMMAND
# Modern version with latest components

# Setup logging
INSTALL_LOG="yt-zixstyle-install-$(date +%Y%m%d-%H%M%S).log"
CURRENT_DIR=$(pwd)
LOG_FILE="${CURRENT_DIR}/${INSTALL_LOG}"

# Function to log and display
log_and_show() {
    echo "$1" | tee -a "${LOG_FILE}"
}

# Function to log command output
log_command() {
    echo "🔧 Executing: $1" | tee -a "${LOG_FILE}"
    eval "$1" 2>&1 | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        echo "✅ Success: $1" | tee -a "${LOG_FILE}"
    else
        echo "❌ Failed: $1 (Exit code: $exit_code)" | tee -a "${LOG_FILE}"
    fi
    return $exit_code
}

# Start logging
log_and_show "========================================"
log_and_show "🚀 YT ZIXSTYLE VPN INSTALLER 2025 - MODERNIZED VERSION"
log_and_show "📊 Features: Xray v25.9.5, REALITY Protocol, XHTTP Transport"
log_and_show "🔒 Security: Latest Dropbear 2025.88, Stunnel 5.75, Nginx 1.29.1"
log_and_show "📝 Installation log: ${LOG_FILE}"
log_and_show "🕐 Started at: $(date)"
log_and_show "========================================"
log_and_show ""

# System preparation
log_and_show "🔧 Preparing system..."
log_command "sysctl -w net.ipv6.conf.all.disable_ipv6=1"
log_command "sysctl -w net.ipv6.conf.default.disable_ipv6=1"

log_and_show "📦 Updating package lists..."
log_command "apt update"

log_and_show "📦 Installing dependencies..."
log_command "apt install -y bzip2 gzip coreutils screen curl unzip build-essential"

log_and_show "⬇️ Downloading setup-modern.sh..."
log_command "wget https://raw.githubusercontent.com/H-Pri3l/v4/main/setup-modern.sh"

log_and_show "🔧 Setting permissions..."
log_command "chmod +x setup-modern.sh"

log_and_show "🔧 Fixing line endings..."
log_command "sed -i -e 's/\r$//' setup-modern.sh"

log_and_show "🚀 Starting main installation in screen session..."
log_and_show "📝 Main installation will continue logging to: ${LOG_FILE}"
log_and_show "🔍 To monitor: tail -f ${LOG_FILE}"

# Pass log file path to setup-modern.sh
export INSTALL_LOG_FILE="${LOG_FILE}"
screen -S setup -L -Logfile "${LOG_FILE}.screen" ./setup-modern.sh
