#!/bin/bash
#installer Websocker tunneling 
# YT ZIXSTYLE 2025 - Enhanced WebSocket Installation

# Setup logging if available
if [ -n "$INSTALL_LOG_FILE" ]; then
    LOG_FILE="$INSTALL_LOG_FILE"
    log_and_show() {
        echo "$1" | tee -a "${LOG_FILE}"
    }
else
    log_and_show() {
        echo "$1"
    }
fi

cd

log_and_show "🔧 Installing WebSocket services..."

# Verify Python2 availability before downloading WebSocket scripts
if ! command -v python >/dev/null 2>&1; then
    log_and_show "⚠️ Python not found - installing Python2 environment..."
    apt install python2 python2-minimal python2.7 -y
    ln -sf /usr/bin/python2 /usr/bin/python
    log_and_show "✅ Python2 environment installed"
fi

#Install Script Websocket-SSH Python
#wget -O /usr/local/bin/ws-openssh https://raw.githubusercontent.com/H-Pri3l/v4/main/sshws/openssh-socket.py
wget -O /usr/local/bin/ws-dropbear https://raw.githubusercontent.com/H-Pri3l/v4/main/sshws/dropbear-ws.py
wget -O /usr/local/bin/ws-stunnel https://raw.githubusercontent.com/H-Pri3l/v4/main/sshws/ws-stunnel
#wget -O /usr/local/bin/ws-ovpn https://raw.githubusercontent.com/${GitUser}/test1/${namafolder}/main/ws-ovpn && chmod +x /usr/local/bin/ws-ovpn

#izin permision
#chmod +x /usr/local/bin/ws-openssh
chmod +x /usr/local/bin/ws-dropbear
chmod +x /usr/local/bin/ws-stunnel
#chmod +x /usr/local/bin/ws-ovpn


#System OpenSSH Websocket-SSH Python
#wget -O /etc/systemd/system/ws-openssh.service https://raw.githubusercontent.com/H-Pri3l/sallxd/sl/main/sshws/service-wsopenssh && chmod +x /etc/systemd/system/ws-openssh.service

#System Dropbear Websocket-SSH Python
wget -O /etc/systemd/system/ws-dropbear.service https://raw.githubusercontent.com/H-Pri3l/v4/main/sshws/service-wsdropbear

#System SSL/TLS Websocket-SSH Python
wget -O /etc/systemd/system/ws-stunnel.service https://raw.githubusercontent.com/H-Pri3l/v4/main/sshws/ws-stunnel.service

# Fix: Set proper service file permissions (prevent "marked executable" warnings)
log_and_show "🔧 Setting proper systemd service file permissions..."
chmod 644 /etc/systemd/system/ws-dropbear.service
chmod 644 /etc/systemd/system/ws-stunnel.service
log_and_show "✅ WebSocket service file permissions set to 644"

##System Websocket-OpenVPN Python
#wget -O /etc/systemd/system/ws-ovpn.service https://raw.githubusercontent.com/${GitUser}/test1/${namafolder}/main/ws-ovpn.service && chmod +x /etc/systemd/system/ws-ovpn.service

#restart service
systemctl daemon-reload
log_and_show "🔧 Starting WebSocket services..."

#Enable & Start & Restart ws-dropbear service
systemctl enable ws-dropbear.service
systemctl start ws-dropbear.service

#Enable & Start & Restart ws-stunnel service
systemctl enable ws-stunnel.service
systemctl start ws-stunnel.service

# Verify services are running
if systemctl is-active --quiet ws-dropbear.service; then
    log_and_show "✅ ws-dropbear service: ACTIVE"
else
    log_and_show "⚠️ ws-dropbear service: FAILED to start"
fi

if systemctl is-active --quiet ws-stunnel.service; then
    log_and_show "✅ ws-stunnel service: ACTIVE"
else
    log_and_show "⚠️ ws-stunnel service: FAILED to start"
fi

log_and_show "✅ WebSocket installation completed"
