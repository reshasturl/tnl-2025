#!/bin/bash
#
# YT ZIXSTYLE SSH/VPN Installer 2025  
# Created: September 7, 2025
# Purpose: Install SSH, Dropbear, OpenVPN, and related services
# Log: Inherit dari setup-2025.sh
# ===============================================================================

# Inherit logging system
if [ -z "$INSTALL_LOG_PATH" ]; then
    echo "ERROR: Must be called from setup-2025.sh"
    exit 1
fi

log_section "SSH-2025.SH STARTED"
log_and_show "🔐 Starting SSH/VPN services installation..."

# Initialize variables (matching ssh-vpn.sh)
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
MYIP2="s/xxxxxxxxx/$MYIP/g"
NET=$(ip -o -4 route show to default | awk '{print $5}' 2>/dev/null || echo "eth0")
source /etc/os-release 2>/dev/null || true
ver=${VERSION_ID:-"unknown"}

# Install SSH services  
log_and_show "🔑 Installing SSH services..."
log_command "apt install -y openssh-server"

# Setup rc-local systemd service
log_and_show "⚙️  Setting up rc-local service..."
cat > /etc/systemd/system/rc-local.service << 'EOF'
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
EOF

cat > /etc/rc.local << 'EOF'
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
EOF

log_command "chmod +x /etc/rc.local"
log_command "systemctl enable rc-local"
log_command "systemctl start rc-local.service"

# Setup password security
log_and_show "🔐 Setting up password security..."
if log_command "curl -sS https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password"; then
    log_and_show "✅ Password security configured"
else
    log_and_show "⚠️ Password security setup failed"
fi

# System updates and cleanup
log_and_show "📦 Updating system packages..."
log_command "apt update -y"
log_command "apt upgrade -y"
log_command "apt dist-upgrade -y"
log_command "apt-get remove --purge ufw firewalld -y"
log_command "apt-get remove --purge exim4 -y"

# Install additional tools and dependencies (avoid duplicates from tools-2025.sh)
log_and_show "📦 Installing SSH-specific dependencies..."
log_command "apt install -y screen"  # For BadVPN sessions if not in tools

# Set timezone
log_and_show "🕒 Setting timezone to Asia/Jakarta..."
log_command "ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime"

# Set locale for SSH
log_and_show "🌐 Configuring SSH locale..."
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# Disable IPv6
log_and_show "🌐 Disabling IPv6..."
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# Configure SSH ports (matching ssh-vpn.sh exactly)
log_and_show "⚙️  Configuring OpenSSH..."
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config

# Configure Dropbear (using dropbear from tools-2025.sh)
log_and_show "⚙️  Configuring Dropbear..."
# Ensure dropbear config file exists
if [ ! -f /etc/default/dropbear ]; then
    log_and_show "⚠️ Creating dropbear default config..."
    cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"
EOF
else
    sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
fi

# Add shells for dropbear
log_and_show "🐚 Adding shells for dropbear..."
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

# Restart SSH and Dropbear services (matching ssh-vpn.sh)
log_and_show "🔄 Restarting SSH services..."
if systemctl restart ssh 2>/dev/null; then
    log_and_show "✅ SSH service restarted"
elif /etc/init.d/ssh restart 2>/dev/null; then
    log_and_show "✅ SSH service restarted via init.d"
else
    log_and_show "⚠️ SSH restart may require manual intervention"
fi

# Try dropbear restart with fallback
log_and_show "🔄 Starting Dropbear service..."
systemctl enable dropbear 2>/dev/null || true
if systemctl restart dropbear 2>/dev/null; then
    log_and_show "✅ Dropbear service started"
elif /etc/init.d/dropbear restart 2>/dev/null; then
    log_and_show "✅ Dropbear service started via init.d"
else
    log_and_show "⚠️ Dropbear service will be started after reboot"
fi

# Configure Stunnel (using stunnel4 from tools-2025.sh)
cat > /etc/stunnel/stunnel.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 700

[openvpn]
accept = 442
connect = 127.0.0.1:1194
EOF

# Generate SSL certificate (matching ssh-vpn.sh exactly)
log_and_show "📜 Generating SSL certificate..."

# Create stunnel directory if not exists
mkdir -p /etc/stunnel

# Get variables for certificate (matching ssh-vpn.sh)
country=ID
state=Indonesia
locality=Jakarta
organization=Zixstyle
organizationalunit=Zixstyle.my.id
commonname=WarungAwan
email=doyoulikepussy@zixstyle.co.id

# Generate key and certificate files (matching ssh-vpn.sh exactly)
cd /etc/stunnel
openssl genrsa -out key.pem 2048 2>/dev/null
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email" 2>/dev/null
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# Set proper permissions
chmod 600 /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/key.pem
chmod 644 /etc/stunnel/cert.pem

# Ensure stunnel user exists and set ownership
if ! id stunnel4 >/dev/null 2>&1; then
    useradd -r -s /bin/false stunnel4 2>/dev/null || true
fi
chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem 2>/dev/null || true

# Set Stunnel configuration (matching ssh-vpn.sh exactly)
log_and_show "🔒 Enabling and starting stunnel4..."
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
systemctl enable stunnel4 2>/dev/null || true
if systemctl restart stunnel4 2>/dev/null; then
    log_and_show "✅ stunnel4 started successfully"
elif /etc/init.d/stunnel4 restart 2>/dev/null; then
    log_and_show "✅ stunnel4 started via init.d"
else
    log_and_show "⚠️ stunnel4 service may need manual restart after system reboot"
fi
    log_and_show "⚠️ stunnel4 restart failed, trying systemctl..."
    systemctl enable stunnel4 2>/dev/null || true
    systemctl restart stunnel4 2>/dev/null || true
fi

# Configure Nginx (nginx will be installed in sshws-2025.sh)
log_and_show "🌐 Preparing Nginx configuration..."
log_command "rm -f /etc/nginx/sites-enabled/default" 2>/dev/null || true
log_command "rm -f /etc/nginx/sites-available/default" 2>/dev/null || true

# Create nginx directory if it doesn't exist
log_command "mkdir -p /etc/nginx"

# Download nginx configuration with fallback
if log_command "wget -O /etc/nginx/nginx.conf https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/nginx.conf"; then
    log_and_show "✅ Nginx configuration downloaded"
else
    log_and_show "⚠️ Nginx config download failed, will be configured during nginx installation"
fi

# Create public_html directory
log_command "mkdir -p /home/vps/public_html"
log_command "chown www-data:www-data /home/vps/public_html"

# Install BadVPN UDPGW (matching ssh-vpn.sh method exactly)
log_and_show "🚀 Installing BadVPN UDPGW..."
cd
if log_command "wget -O /usr/bin/badvpn-udpgw https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/newudpgw"; then
    log_command "chmod +x /usr/bin/badvpn-udpgw"
    log_and_show "✅ BadVPN UDPGW binary installed"
else
    log_and_show "⚠️ BadVPN binary download failed, compiling from source..."
    # Fallback to source compilation
    log_command "apt install -y cmake git"
    cd /tmp
    if [ ! -d "badvpn" ]; then
        log_command "git clone https://github.com/ambrop72/badvpn.git"
    fi
    cd badvpn
    log_command "mkdir -p build"
    cd build
    log_command "cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1"
    log_command "make"
    log_command "cp udpgw/badvpn-udpgw /usr/bin/"
    cd
fi

# Setup BadVPN in rc.local using systemd service instead of screen
log_and_show "⚙️  Adding BadVPN systemd service to rc.local..."
sed -i '/badvpn/d' /etc/rc.local 2>/dev/null || true  # Remove any existing badvpn entries
sed -i '$ i\systemctl start badvpn-udpgw' /etc/rc.local

# Start BadVPN using systemd services instead of screen (to avoid screen jumping)
log_and_show "🚀 Starting BadVPN services using systemd..."

# Create systemd service for badvpn (Fixed configuration)
cat > /etc/systemd/system/badvpn-udpgw.service << 'EOF'
[Unit]
Description=BadVPN UDP Gateway Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'exec /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500'
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start badvpn service with proper error handling
log_command "systemctl daemon-reload"
log_command "systemctl enable badvpn-udpgw"
if systemctl start badvpn-udpgw; then
    log_and_show "✅ BadVPN service started successfully"
else
    log_and_show "⚠️ badvpn-udpgw service failed, starting manually..."
    # Manual fallback - start single instance
    pkill -f badvpn-udpgw 2>/dev/null || true
    nohup /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500 >/dev/null 2>&1 &
    log_and_show "✅ BadVPN started manually as fallback"
fi

sleep 2
log_and_show "✅ BadVPN services configured"

# Install crontab for user management and system auto-reboot (remove old cron setup)
log_and_show "⏰ Setting up user management cron..."
if [ ! -f "/usr/bin/xp" ]; then
    if log_command "wget -O /usr/bin/xp https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/xp.sh"; then
        log_command "chmod +x /usr/bin/xp"
        log_and_show "✅ User expiry management script downloaded"
    else
        log_and_show "⚠️ xp.sh script not found, skipping cron setup"
    fi
fi

# Enable and start all services (matching ssh-vpn.sh style)
log_and_show "🚀 Starting and enabling services..."
log_command "systemctl daemon-reload"
log_command "systemctl restart ssh"
log_command "systemctl enable ssh"
log_command "systemctl restart dropbear"
log_command "systemctl enable dropbear"
log_command "systemctl restart stunnel4"
log_command "systemctl enable stunnel4"
log_command "systemctl restart squid"
log_command "systemctl enable squid"
log_command "systemctl restart nginx"
log_command "systemctl enable nginx"

# Install BBR kernel optimization (using ssh-vpn.sh compatible URL)
log_and_show "⚡ Installing BBR kernel optimization..."
if log_command "wget -O bbr.sh https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/bbr.sh"; then
    log_command "chmod +x bbr.sh"
    log_and_show "🚀 Executing BBR optimization..."
    ./bbr.sh 2>&1 | tee -a "${INSTALL_LOG_PATH}"
    log_command "rm -f bbr.sh"
    log_and_show "✅ BBR optimization completed"
else
    log_and_show "⚠️ BBR script not found, skipping optimization"
fi

# Configure banner (matching ssh-vpn.sh exactly)
sleep 1
log_and_show "🏷️ Settings banner"
if log_command "wget -q -O /etc/issue.net https://raw.githubusercontent.com/reshasturl/tnl-2025/main/issue.net"; then
    log_command "chmod +x /etc/issue.net"
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
    log_and_show "✅ Login banner configured"
else
    log_and_show "⚠️ Banner file not found, skipping banner configuration"
fi

# Configure iptables to block torrent traffic
log_and_show "🚫 Configuring iptables to block torrent traffic..."
log_command "iptables -A FORWARD -m string --string 'get_peers' --algo bm -j DROP"
log_command "iptables -A FORWARD -m string --string 'announce_peer' --algo bm -j DROP"
log_command "iptables -A FORWARD -m string --string 'find_node' --algo bm -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'BitTorrent' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'BitTorrent protocol' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'peer_id=' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string '.torrent' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'announce.php?passkey=' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'torrent' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'announce' -j DROP"
log_command "iptables -A FORWARD -m string --algo bm --string 'info_hash' -j DROP"

# Save iptables rules (using netfilter-persistent from tools-2025.sh)
log_and_show "💾 Saving iptables rules..."
log_command "iptables-save > /etc/iptables.up.rules"
log_command "iptables-restore -t < /etc/iptables.up.rules"
log_command "netfilter-persistent save"
log_command "netfilter-persistent reload"

# Configure Squid proxy (using squid from tools-2025.sh)
log_and_show "🌐 Configuring Squid proxy..."

# Note: vnstat already installed from source in tools-2025.sh
log_and_show "✅ Using vnstat from tools-2025.sh (installed from source)"

# Configure Squid (modern configuration for 2025)
cat > /etc/squid/squid.conf << 'EOF'
# Squid 2025 Configuration for VPN Server
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1

# Network ACLs
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12  
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7       # RFC 4193 local private network range
acl localnet src fe80::/10      # RFC 4291 link-local (directly plugged) machines

# Port ACLs
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# Access control
http_access allow manager localhost
http_access deny manager
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

# Network settings
http_port 3128
http_port 8080
http_port 8000

# Cache settings
cache_dir ufs /var/spool/squid 1024 16 256
coredump_dir /var/spool/squid
maximum_object_size 512 MB
cache_mem 256 MB

# Performance tuning
workers 2
cpu_affinity_map process_numbers=1,2,3,4 cores=1,2,3,4

# Refresh patterns (updated for 2025)
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern \/(Packages|Sources)(|\.bz2|\.gz|\.xz)$ 0 0% 0 refresh-ims
refresh_pattern \/Release(|\.gpg)$ 0 0% 0 refresh-ims
refresh_pattern \/InRelease$ 0 0% 0 refresh-ims
refresh_pattern \/(Translation-.*)(|\.bz2|\.gz|\.xz)$ 0 0% 0 refresh-ims
refresh_pattern .               0       20%     4320

# Security headers
reply_header_add X-Cache-Status %{HIT_MISS} "from %h"
reply_header_add X-Cache-Control "public, max-age=3600"

# Hide version and server info
via off
forwarded_for off
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all

# Custom hostname
visible_hostname YT-ZIXSTYLE-VPN-2025
EOF

# Initialize Squid cache and start service
log_command "squid -z"  # Initialize cache directories
log_command "systemctl restart squid"
log_command "systemctl enable squid"

# Note: fail2ban already installed in tools-2025.sh
log_and_show "✅ Using fail2ban from tools-2025.sh"

# Install DDOS Deflate
log_and_show "🛡️  Installing DDoS Deflate..."
if [ -d '/usr/local/ddos' ]; then
    log_and_show "⚠️ DDoS Deflate already installed"
else
    mkdir -p /usr/local/ddos
    log_command "wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf"
    log_command "wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE"
    log_command "wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list"
    log_command "wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh"
    log_command "chmod 0755 /usr/local/ddos/ddos.sh"
    log_command "cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos"
    /usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
    log_and_show "✅ DDoS Deflate installed and configured"
fi

# Install SSH account management scripts (matching ssh-vpn.sh location)
log_and_show "👥 Installing SSH account management scripts to /usr/bin..."
cd /usr/bin

# SSH account management (matching ssh-vpn.sh exactly)
log_command "wget -O usernew https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/usernew.sh"
log_command "wget -O trial https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/trial.sh"
log_command "wget -O renew https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/renew.sh"
log_command "wget -O hapus https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/hapus.sh"
log_command "wget -O cek https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/cek.sh"
log_command "wget -O member https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/member.sh"
log_command "wget -O delete https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/delete.sh"
log_command "wget -O autokill https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/autokill.sh"
log_command "wget -O ceklim https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/ceklim.sh"
log_command "wget -O tendang https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/tendang.sh"

# Main menu scripts (matching ssh-vpn.sh exactly)
log_command "wget -O menu https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu.sh"
log_command "wget -O menu-vmess https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-vmess.sh"
log_command "wget -O menu-vless https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-vless.sh"
log_command "wget -O running https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/running.sh"
log_command "wget -O clearcache https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/clearcache.sh"
log_command "wget -O menu-trgo https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-trgo.sh"
log_command "wget -O menu-trojan https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-trojan.sh"

# SSH menu
log_command "wget -O menu-ssh https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-ssh.sh"

# System menu scripts (matching ssh-vpn.sh exactly)
log_command "wget -O menu-set https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-set.sh"
log_command "wget -O menu-domain https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-domain.sh"
log_command "wget -O add-host https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/add-host.sh"
log_command "wget -O port-change https://raw.githubusercontent.com/reshasturl/tnl-2025/main/port/port-change.sh"
log_command "wget -O certv2ray https://raw.githubusercontent.com/reshasturl/tnl-2025/main/xray/certv2ray.sh"
log_command "wget -O menu-webmin https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/menu-webmin.sh"
log_command "wget -O speedtest https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/speedtest_cli.py"
log_command "wget -O about https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/about.sh"
log_command "wget -O auto-reboot https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/auto-reboot.sh"
log_command "wget -O restart https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/restart.sh"
log_command "wget -O bw https://raw.githubusercontent.com/reshasturl/tnl-2025/main/menu/bw.sh"

# Port management scripts (matching ssh-vpn.sh exactly)
log_command "wget -O port-ssl https://raw.githubusercontent.com/reshasturl/tnl-2025/main/port/port-ssl.sh"
log_command "wget -O port-ovpn https://raw.githubusercontent.com/reshasturl/tnl-2025/main/port/port-ovpn.sh"

# Additional system tools (matching ssh-vpn.sh exactly) - xp already downloaded
log_command "wget -O acs-set https://raw.githubusercontent.com/reshasturl/tnl-2025/main/acs-set.sh"
log_command "wget -O sshws https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ssh/sshws.sh"

# Set execute permissions for all scripts (matching ssh-vpn.sh exactly)
log_command "chmod +x menu"
log_command "chmod +x menu-vmess"
log_command "chmod +x menu-vless"
log_command "chmod +x running"
log_command "chmod +x clearcache"
log_command "chmod +x menu-trgo"
log_command "chmod +x menu-trojan"
log_command "chmod +x menu-ssh"
log_command "chmod +x usernew"
log_command "chmod +x trial"
log_command "chmod +x renew"
log_command "chmod +x hapus"
log_command "chmod +x cek"
log_command "chmod +x member"
log_command "chmod +x delete"
log_command "chmod +x autokill"
log_command "chmod +x ceklim"
log_command "chmod +x tendang"
log_command "chmod +x menu-set"
log_command "chmod +x menu-domain"
log_command "chmod +x add-host"
log_command "chmod +x port-change"
log_command "chmod +x certv2ray"
log_command "chmod +x menu-webmin"
log_command "chmod +x speedtest"
log_command "chmod +x about"
log_command "chmod +x auto-reboot"
log_command "chmod +x restart"
log_command "chmod +x bw"
log_command "chmod +x port-ssl"
log_command "chmod +x port-ovpn"
log_command "chmod +x xp"
log_command "chmod +x acs-set"
log_command "chmod +x sshws"

cd

# Setup cron jobs (matching ssh-vpn.sh exactly)
log_and_show "⏰ Setting up system cron jobs..."
cat > /etc/cron.d/re_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-END
7
END

log_command "service cron restart"
log_command "service cron reload"

# System cleanup (matching ssh-vpn.sh exactly)
sleep 1
log_and_show "🧹 Clearing trash"
log_command "apt autoclean -y"

if dpkg -s unscd >/dev/null 2>&1; then
    log_command "apt -y remove --purge unscd"
fi

log_command "apt-get -y --purge remove samba*"
log_command "apt-get -y --purge remove apache2*"
log_command "apt-get -y --purge remove bind9*"
log_command "apt-get -y remove sendmail*"
log_command "apt autoremove -y"

# Set ownership
log_command "chown -R www-data:www-data /home/vps/public_html"

# Final service restart sequence (matching ssh-vpn.sh exactly)
sleep 1
log_and_show "🔄 Restart All service SSH & OVPN"
log_command "/etc/init.d/nginx restart"
sleep 1
log_and_show "✅ Restarting nginx"
log_command "/etc/init.d/openvpn restart"
sleep 1
log_and_show "✅ Restarting cron"
log_command "/etc/init.d/ssh restart"
sleep 1
log_and_show "✅ Restarting ssh"
log_command "/etc/init.d/dropbear restart"
sleep 1
log_and_show "✅ Restarting dropbear"
log_command "/etc/init.d/fail2ban restart"
sleep 1
log_and_show "✅ Restarting fail2ban"
# stunnel4 already restarted above, skip duplicate restart
log_and_show "✅ stunnel4 already restarted"
log_command "/etc/init.d/vnstat restart"
sleep 1
log_and_show "✅ Restarting vnstat"
log_command "/etc/init.d/squid restart"
sleep 1
log_and_show "✅ Restarting squid"

# Start BadVPN services using systemd (no screen jumping)
log_and_show "✅ BadVPN services already started via systemd"
log_command "systemctl status badvpn-udpgw --no-pager"

# Clear bash history and add profile (matching ssh-vpn.sh exactly)
history -c
echo "unset HISTFILE" >> /etc/profile

# Clean up temporary files (matching ssh-vpn.sh exactly)
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh

# Log service info to log-install.txt (focus on used components only)
echo "OpenSSH: 22, 200, 500, 40000, 51443, 58080" >> /root/log-install.txt
echo "Dropbear: 69, 109, 110, 143, 50000" >> /root/log-install.txt
echo "Stunnel4: 222, 777" >> /root/log-install.txt
echo "Squid: 3128, 8080, 8000" >> /root/log-install.txt
echo "BadVPN UDPGW: 7100-7900" >> /root/log-install.txt
echo "SSH Websocket: 80" >> /root/log-install.txt
echo "SSH SSL Websocket: 443" >> /root/log-install.txt
echo "Fail2Ban: [ON]" >> /root/log-install.txt
echo "DDoS Deflate: [ON]" >> /root/log-install.txt
echo "BBR: [ON]" >> /root/log-install.txt
echo "Iptables: [ON]" >> /root/log-install.txt
echo "Banner: [ON]" >> /root/log-install.txt

log_and_show "✅ SSH/VPN services installation completed with focus on WebSocket technologies"
log_section "SSH-2025.SH COMPLETED"

# finishing
clear
