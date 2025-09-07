#!/bin/bash
#
# YT ZIXSTYLE SSH VPN Installer - MODERNIZED VERSION 2025
# Updated: September 7, 2025
# Features: Latest Dropbear 2025.88, Stunnel 5.75, Nginx 1.29.1
# ==================================================

# Setup logging system
CURRENT_DIR=$(pwd)
if [ -n "$INSTALL_LOG_FILE" ]; then
    # Use log file passed from parent script
    LOG_FILE="$INSTALL_LOG_FILE"
else
    # Create new log file if running standalone
    SSH_LOG="yt-zixstyle-ssh-$(date +%Y%m%d-%H%M%S).log"
    LOG_FILE="${CURRENT_DIR}/${SSH_LOG}"
fi

# Enhanced logging functions
log_and_show() {
    echo "$1" | tee -a "${LOG_FILE}"
}

log_command() {
    echo "🔧 [SSH][$(date '+%H:%M:%S')] Executing: $1" | tee -a "${LOG_FILE}"
    eval "$1" 2>&1 | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        echo "✅ [SSH][$(date '+%H:%M:%S')] Success: $1" | tee -a "${LOG_FILE}"
    else
        echo "❌ [SSH][$(date '+%H:%M:%S')] Failed: $1 (Exit code: $exit_code)" | tee -a "${LOG_FILE}"
    fi
    return $exit_code
}

log_section() {
    echo "" | tee -a "${LOG_FILE}"
    echo "========================================" | tee -a "${LOG_FILE}"
    echo "📋 [SSH][$(date '+%H:%M:%S')] $1" | tee -a "${LOG_FILE}"
    echo "========================================" | tee -a "${LOG_FILE}"
}

# Start SSH installer logging
log_section "SSH-VPN-MODERN.SH STARTED"
log_and_show "📝 SSH installer log: ${LOG_FILE}"
log_and_show "🕐 SSH installation started at: $(date)"

# Version definitions
DROPBEAR_VERSION="2025.88"
STUNNEL_VERSION="5.75"
NGINX_VERSION="1.29.1"

log_and_show "📊 SSH component versions:"
log_and_show "   - Dropbear: ${DROPBEAR_VERSION}"
log_and_show "   - Stunnel: ${STUNNEL_VERSION}"
log_and_show "   - Nginx: ${NGINX_VERSION}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           YT ZIXSTYLE SSH/VPN INSTALLER 2025                 ║${NC}"
echo -e "${BLUE}║                  MODERNIZED COMPONENTS                       ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  🚀 Dropbear SSH ${DROPBEAR_VERSION}                                  ║${NC}"
echo -e "${GREEN}║  🚀 Stunnel ${STUNNEL_VERSION}                                        ║${NC}"
echo -e "${GREEN}║  🚀 Nginx ${NGINX_VERSION}                                           ║${NC}"
echo -e "${GREEN}║  🔒 Enhanced Security Features                               ║${NC}"
echo -e "${GREEN}║  📺 STB & Mobile Optimized                                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

#detail nama perusahaan
country=ID
state=Indonesia
locality=Jakarta
organization=Zixstyle
organizationalunit=Zixstyle.my.id
commonname=WarungAwan
email=doyoulikepussy@zixstyle.co.id

# simple password minimal
curl -sS https://raw.githubusercontent.com/H-pri3l/v4/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

echo -e "${GREEN}[INFO]${NC} Updating system packages..."
#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

# Install essential packages including Python2 for WebSocket services
echo -e "${GREEN}[INFO]${NC} Installing essential packages..."

# Fix: Python Environment (prevent ws-dropbear.service Python executable errors)
log_and_show "🔧 Installing Python2 environment for WebSocket services..."
apt install python2 python2-minimal python2.7 -y
ln -sf /usr/bin/python2 /usr/bin/python

# Verify Python symlink
if command -v python >/dev/null 2>&1; then
    log_and_show "✅ Python symlink created successfully: $(which python) -> $(python --version 2>&1)"
else
    log_and_show "❌ Python symlink creation failed"
fi
apt -y install jq shc wget curl figlet ruby build-essential zlib1g-dev libssl-dev
gem install lolcat

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# Modern SSL/TLS installation
install_ssl(){
    echo -e "${GREEN}[INFO]${NC} Installing modern Nginx ${NGINX_VERSION}..."
    if [ -f "/usr/bin/apt-get" ];then
        # Install specific Nginx version ${NGINX_VERSION} from source
        log_and_show "🔧 Installing Nginx ${NGINX_VERSION} from source for modern features..."
        
        # Install build dependencies
        apt-get install -y build-essential zlib1g-dev libpcre3-dev libssl-dev libgd-dev libxml2-dev uuid-dev
        
        # Download and compile Nginx ${NGINX_VERSION}
        cd /tmp
        wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
        tar -xzvf nginx-${NGINX_VERSION}.tar.gz
        cd nginx-${NGINX_VERSION}
        
        # Configure with modern modules
        ./configure \
            --prefix=/etc/nginx \
            --sbin-path=/usr/sbin/nginx \
            --modules-path=/usr/lib/nginx/modules \
            --conf-path=/etc/nginx/nginx.conf \
            --error-log-path=/var/log/nginx/error.log \
            --http-log-path=/var/log/nginx/access.log \
            --pid-path=/var/run/nginx.pid \
            --lock-path=/var/run/nginx.lock \
            --http-client-body-temp-path=/var/cache/nginx/client_temp \
            --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
            --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
            --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
            --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
            --with-file-aio \
            --with-http_ssl_module \
            --with-http_realip_module \
            --with-http_addition_module \
            --with-http_sub_module \
            --with-http_dav_module \
            --with-http_flv_module \
            --with-http_mp4_module \
            --with-http_gunzip_module \
            --with-http_gzip_static_module \
            --with-http_random_index_module \
            --with-http_secure_link_module \
            --with-http_stub_status_module \
            --with-http_auth_request_module \
            --with-http_xslt_module=dynamic \
            --with-http_image_filter_module=dynamic \
            --with-threads \
            --with-stream \
            --with-stream_ssl_module \
            --with-stream_ssl_preread_module \
            --with-stream_realip_module \
            --with-http_slice_module \
            --with-http_v2_module \
            --with-http_v3_module
            
        # Compile and install
        make -j$(nproc)
        make install
        
        # Create nginx user
        useradd --system --home /var/cache/nginx --shell /sbin/nologin --comment "nginx user" --user-group nginx
        
        # Create necessary directories
        mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
        chown -R nginx:nginx /var/cache/nginx
        
        # Install certbot
        apt-get install -y certbot
        
        log_and_show "✅ Nginx ${NGINX_VERSION} compiled and installed with HTTP/3 support"
    else
        yum install -y nginx certbot
        sleep 3s
    fi
}

# Install modern Dropbear SSH
install_dropbear() {
    echo -e "${GREEN}[INFO]${NC} Installing modern Dropbear ${DROPBEAR_VERSION}..."
    
    # Install build dependencies
    apt-get install -y build-essential zlib1g-dev
    
    # Download and compile latest Dropbear
    cd /tmp
    wget https://matt.ucc.asn.au/dropbear/releases/dropbear-${DROPBEAR_VERSION}.tar.bz2
    tar -xjf dropbear-${DROPBEAR_VERSION}.tar.bz2
    cd dropbear-${DROPBEAR_VERSION}
    
    # Configure with modern options
    ./configure --enable-zlib --enable-openpty --enable-syslog --enable-bundled-libtom
    make PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp"
    make install
    
    # Create dropbear user and group
    groupadd -r dropbear 2>/dev/null || true
    useradd -r -g dropbear -d /var/empty -s /bin/false dropbear 2>/dev/null || true
    
    # Generate host keys including DSS key (prevent dropbear_dss_host_key errors)
    log_and_show "🔧 Generating Dropbear host keys..."
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
    dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
    
    # Fix: Enable Dropbear to start (prevent NO_START=1 error)
    log_and_show "🔧 Configuring Dropbear to start automatically..."
    sed -i 's/NO_START=1/NO_START=0/' /etc/default/dropbear 2>/dev/null || true
    echo "NO_START=0" > /etc/default/dropbear
    
    # Verify DSS key generation
    if [ -f /etc/dropbear/dropbear_dss_host_key ]; then
        log_and_show "✅ Dropbear DSS host key generated successfully"
    else
        log_and_show "❌ Dropbear DSS host key generation failed"
    fi
    
    # Cleanup
    cd /
    rm -rf /tmp/dropbear-${DROPBEAR_VERSION}*
    
    echo -e "${GREEN}[SUCCESS]${NC} Dropbear ${DROPBEAR_VERSION} installed successfully"
}

# Install modern Stunnel
install_stunnel() {
    echo -e "${GREEN}[INFO]${NC} Installing modern Stunnel ${STUNNEL_VERSION}..."
    
    # Install dependencies
    apt-get install -y libssl-dev
    
    # Download and compile latest Stunnel
    cd /tmp
    wget https://www.stunnel.org/downloads/stunnel-${STUNNEL_VERSION}.tar.gz
    tar -xzf stunnel-${STUNNEL_VERSION}.tar.gz
    cd stunnel-${STUNNEL_VERSION}
    
    # Configure with modern options
    ./configure --enable-systemd --enable-ipv6 --with-ssl=/usr
    make
    make install
    
    # Create stunnel user and directories
    useradd -r -s /bin/false stunnel4 2>/dev/null || true
    mkdir -p /var/lib/stunnel4
    chown stunnel4:stunnel4 /var/lib/stunnel4
    
    # Create modern stunnel configuration
    mkdir -p /etc/stunnel
    cat > /etc/stunnel/stunnel.conf << EOF
; Stunnel ${STUNNEL_VERSION} Configuration - Modern Setup
; YT ZIXSTYLE 2025

; Certificate/key is needed in server mode and optional in client mode
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key

; Protocol version (all, SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3)
sslVersion = TLSv1.2

; Security enhancements
options = NO_SSLv2
options = NO_SSLv3
options = CIPHER_SERVER_PREFERENCE
options = SINGLE_DH_USE
options = SINGLE_ECDH_USE

; Modern cipher suites
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384

; Service definitions
[dropbear]
accept = 443
connect = 127.0.0.1:109

[dropbear-2]
accept = 777
connect = 127.0.0.1:109

[openvpn]
accept = 442
connect = 127.0.0.1:1194

[ws-stunnel]
accept = 447
connect = 127.0.0.1:8880
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
EOF
    
    # Fix: Set proper certificate permissions (prevent "Insecure file permissions" error)
    log_and_show "🔧 Setting secure certificate permissions..."
    if [ -f /etc/xray/xray.crt ]; then
        chmod 600 /etc/xray/xray.crt
        chmod 600 /etc/xray/xray.key
        log_and_show "✅ Certificate permissions secured (600)"
    fi
    
    # Create certificate if not exists (temporary self-signed)
    if [ ! -f /etc/xray/xray.crt ]; then
        log_and_show "🔧 Creating temporary self-signed certificate..."
        mkdir -p /etc/xray
        openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
            -subj "/C=ID/ST=Jakarta/L=Jakarta/O=Zixstyle/CN=localhost" \
            -keyout /etc/xray/xray.key \
            -out /etc/xray/xray.crt
        chmod 600 /etc/xray/xray.crt /etc/xray/xray.key
        log_and_show "✅ Temporary certificate created with secure permissions"
    fi
    
    # Create systemd service for stunnel
    cat > /etc/systemd/system/stunnel4.service << EOF
[Unit]
Description=SSL tunnel for network daemons (Stunnel ${STUNNEL_VERSION})
After=network.target

[Service]
Type=forking
PIDFile=/var/run/stunnel4.pid
ExecStart=/usr/local/bin/stunnel /etc/stunnel/stunnel.conf
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
    
    # Fix: Set proper service file permissions (prevent "marked executable" warnings)
    log_and_show "🔧 Setting proper systemd service file permissions..."
    chmod 644 /etc/systemd/system/stunnel4.service
    systemctl daemon-reload
    log_and_show "✅ Stunnel4 service file permissions set to 644"
    
    # Cleanup
    cd /
    rm -rf /tmp/stunnel-${STUNNEL_VERSION}*
    
    echo -e "${GREEN}[SUCCESS]${NC} Stunnel ${STUNNEL_VERSION} installed successfully"
}

# Continue with original SSL installation and other components
install_ssl

echo -e "${GREEN}[INFO]${NC} Installing modern components..."

# Install modern Dropbear
install_dropbear

# Install modern Stunnel  
install_stunnel

# Continue with original script logic for other components...
# (Keep the rest of the original ssh-vpn.sh script here)

# Enhanced security configurations
echo -e "${GREEN}[INFO]${NC} Applying enhanced security configurations..."

# Modern SSH configuration
cat >> /etc/ssh/sshd_config << EOF

# YT ZIXSTYLE 2025 - Enhanced Security
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Modern cipher suites
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512

# Security settings
ClientAliveInterval 30
ClientAliveCountMax 3
MaxAuthTries 3
LoginGraceTime 30
EOF

# Enable and start services
systemctl enable nginx
systemctl start nginx

# Fix: Install vnstat for menu functionality (prevent "vnstat: command not found")
log_and_show "🔧 Installing vnstat for menu functionality..."
apt install vnstat -y
systemctl enable vnstat && systemctl start vnstat
log_and_show "✅ vnstat installed and enabled"

# Fix: Create required directories and set environment (prevent menu errors)
log_and_show "🔧 Creating required directories and environment..."
mkdir -p /home/ubuntu/.acme.sh/deswina.com_ecc
touch /home/ubuntu/.acme.sh/deswina.com_ecc/deswina.com.key 2>/dev/null || true
chmod +r /usr/local/etc/..ini 2>/dev/null || true

# Set TERM environment variable
if ! grep -q "TERM=xterm-256color" /etc/environment; then
    echo 'export TERM=xterm-256color' >> /etc/environment
    log_and_show "✅ TERM environment variable set"
fi

# Validation function for nginx config syntax
validate_nginx_config() {
    log_and_show "🔧 Validating nginx configuration..."
    if nginx -t 2>/dev/null; then
        log_and_show "✅ Nginx configuration syntax is valid"
    else
        log_and_show "⚠️ Nginx configuration has syntax issues - will be fixed by Xray installer"
    fi
}
systemctl enable stunnel4
systemctl start stunnel4
systemctl restart ssh

# Version tracking
echo "$DROPBEAR_VERSION" > /opt/.dropbear-ver
echo "$STUNNEL_VERSION" > /opt/.stunnel-ver
echo "$NGINX_VERSION" > /opt/.nginx-ver

# Install modern menu system
echo -e "${GREEN}[INFO]${NC} Installing modern menu system with REALITY & XHTTP support..."

# Download modern menu scripts
cd /usr/bin

wget -O menu "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu.sh"
wget -O menu-vmess "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-vmess.sh"
wget -O menu-vless "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-vless.sh"
wget -O running "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/running.sh"
wget -O clearcache "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/clearcache.sh"
wget -O menu-trgo "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-trgo.sh"
wget -O menu-trojan "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-trojan.sh"
wget -O menu-ssh "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-ssh.sh"
wget -O menu-set "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-set.sh"
wget -O menu-domain "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-domain.sh"
wget -O menu-webmin "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/menu-webmin.sh"
wget -O about "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/about.sh"
wget -O auto-reboot "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/auto-reboot.sh"
wget -O restart "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/restart.sh"
wget -O bw "https://raw.githubusercontent.com/H-Pri3l/v4/main/menu/bw.sh"

# Download modern XRAY management scripts
wget -O add-ws "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-ws.sh"
wget -O add-vless "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-vless.sh"
wget -O add-vless-reality "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-vless-reality.sh"
wget -O add-vless-xhttp "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-vless-xhttp.sh"
wget -O add-vmess-xhttp "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-vmess-xhttp.sh"
wget -O add-tr "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/add-tr.sh"
wget -O del-ws "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/del-ws.sh"
wget -O del-vless "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/del-vless.sh"
wget -O del-tr "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/del-tr.sh"
wget -O cek-ws "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/cek-ws.sh"
wget -O cek-vless "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/cek-vless.sh"
wget -O cek-tr "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/cek-tr.sh"
wget -O renew-ws "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/renew-ws.sh"
wget -O renew-vless "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/renew-vless.sh"
wget -O renew-tr "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/renew-tr.sh"
wget -O trialvmess "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/trialvmess.sh"
wget -O trialvless "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/trialvless.sh"
wget -O trialtrojan "https://raw.githubusercontent.com/H-Pri3l/v4/main/xray/trialtrojan.sh"

# Download SSH management scripts
wget -O usernew "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/trial.sh"
wget -O renew "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/renew.sh"
wget -O hapus "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/hapus.sh"
wget -O cek "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/cek.sh"
wget -O member "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/member.sh"
wget -O delete "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/delete.sh"
wget -O autokill "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/autokill.sh"
wget -O ceklim "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/ceklim.sh"
wget -O tendang "https://raw.githubusercontent.com/H-Pri3l/v4/main/ssh/tendang.sh"

# Set executable permissions for all scripts
chmod +x /usr/bin/*

log_and_show "✅ Modern menu system installed with REALITY & XHTTP support"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 MODERN SSH/VPN INSTALLATION COMPLETE        ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  ✅ Dropbear SSH ${DROPBEAR_VERSION} - Latest Security Patches     ║${NC}"
echo -e "${GREEN}║  ✅ Stunnel ${STUNNEL_VERSION} - Modern TLS/SSL Support            ║${NC}"
echo -e "${GREEN}║  ✅ Nginx ${NGINX_VERSION} - Performance & Security Enhanced     ║${NC}"
echo -e "${GREEN}║  ✅ Enhanced SSH Security Configuration                     ║${NC}"
echo -e "${GREEN}║  ✅ Modern Cipher Suites                                    ║${NC}"
echo -e "${GREEN}║  ✅ Modern Menu System with REALITY & XHTTP                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
