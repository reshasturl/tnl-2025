# Workflow Menu VPN Server - YT ZIXSTYLE 2025

## 🏠 MENU UTAMA (menu.sh)

### Header Information Display
- **Operating System**: Informasi OS yang berjalan
- **Total RAM**: Kapasitas memory server
- **System Uptime**: Waktu server telah berjalan
- **ISP Name**: Informasi provider internet
- **Domain**: Domain yang terkonfigurasi
- **IP VPS**: Alamat IP server

### Main Menu Structure
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                 • SCRIPT MENU •                 
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[•1] SSH & OpenVPN Menu     [•5] SYSTEM Menu
[•2] Vmess Menu             [•6] Status Service  
[•3] Vless Menu             [•7] Clear RAM Cache
[•4] Trojan Go Menu         [•8] Trojan GFW Menu
```

---

## 📋 SUB-MENU WORKFLOWS

### 1. 🔐 SSH & OVPN MENU (menu-ssh.sh)

**Fungsi**: Manajemen akun SSH dan OpenVPN

#### Menu Options:
```
[•1] Create SSH & OpenVPN Account      → usernew
[•2] Trial Account SSH & OpenVPN       → trial  
[•3] Renew SSH & OpenVPN Account       → renew
[•4] Delete SSH & OpenVPN Account      → hapus
[•5] Check User Login SSH & OpenVPN    → cek
[•6] List Member SSH & OpenVPN         → member
[•7] Delete User Expired SSH & OpenVPN → delete
[•8] Set up Autokill SSH               → autokill
[•9] Cek Users Who Do Multi Login SSH  → ceklim
[•0] BACK TO MENU                      → menu
```

**Workflow SSH Management**:
1. **Create Account** → Input username/password/expired date
2. **Trial Account** → Generate temporary account (biasanya 1 hari)
3. **Renew Account** → Extend expiry date existing user
4. **Delete Account** → Remove user dari system
5. **Check Login** → Monitor siapa saja yang sedang login
6. **List Member** → Tampilkan semua user terdaftar
7. **Auto Delete** → Hapus user yang sudah expired
8. **Autokill Setup** → Set limit multi-login per user
9. **Multi Login Check** → Monitor user yang login multiple

---

### 2. 🚀 XRAY / VMESS MENU (menu-vmess.sh)

**Fungsi**: Manajemen protokol VMess (Virtual Mess)

#### Menu Options:
```
[•1] Create VMess Account (All Protocols)  → add-ws-enhanced
[•2] Trial Account VMess                   → trialvmess
[•3] Extending Account VMess Active Life   → renew-ws
[•4] Delete Account VMess                  → del-ws
[•5] Check User Login VMess                → cek-ws
[•0] BACK TO MENU                          → menu
```

**Enhanced VMess Features (1 Creation = All Protocols)**:
- **Auto-Generate**: WebSocket + GRPC + XHTTP dengan 1 UUID
- **Multiple Configs**: TLS (443) + non-TLS (80) + GRPC (443) + XHTTP (443)
- **Maximum Flexibility**: User pilih protokol sesuai kebutuhan
- **Trial System**: Generate temporary VMess account
- **Auto-Renewal**: Extend user expiry
- **User Management**: Create, delete, monitor VMess users

---

### 3. ⚡ XRAY / VLESS MENU (menu-vless.sh)

**Fungsi**: Manajemen protokol VLess (Very Light ESS)

#### Menu Options:
```
[•1] Create VLess Account (All Protocols)  → add-vless-enhanced
[•2] Trial Account VLESS                   → trialvless
[•3] Extending Account VLESS Active Life   → renew-vless
[•4] Delete Account VLESS                  → del-vless
[•5] Check User Login VLESS                → cek-vless
[•0] BACK TO MENU                          → menu
```

**Enhanced VLess Features (1 Creation = All Protocols)**:
- **Auto-Generate**: WebSocket + GRPC + XHTTP + REALITY dengan 1 UUID
- **Multiple Configs**: TLS (443) + non-TLS (80) + GRPC (443) + XHTTP (443) + REALITY (8443)
- **Maximum Flexibility**: User pilih protokol sesuai kebutuhan
- **REALITY Bonus**: Stealth protocol tanpa certificate (auto-included)
- **Complete Management**: Full user lifecycle management

---

### 4. 🛡️ TROJAN Go MENU (menu-trgo.sh)

**Fungsi**: Manajemen Trojan-Go (STB Optimized)

#### Menu Options:
```
[•1] Create Account Trojan Go              → addtrgo
[•2] Trial Account Trojan Go               → trialtrojango
[•3] Extending Account Trojan Go           → renewtrgo
[•4] Delete Account Trojan Go              → deltrgo
[•5] Check User Login Trojan Go            → cektrgo
[•0] BACK TO MENU                          → menu
```

**Trojan-Go Features**:
- **STB Optimized**: Khusus untuk Set-Top Box
- **Kuota Bypass**: Optimized untuk bypass kuota
- **High Performance**: Better performance vs Trojan GFW

---

### 5. ⚔️ TROJAN GFW MENU (menu-trojan.sh)

**Fungsi**: Manajemen Trojan GFW (Traditional)

#### Menu Options:
```
[•1] Create Account Trojan                 → add-tr
[•2] Trial Account Trojan                  → trialtrojan
[•3] Extending Account Trojan Active Life  → renew-tr
[•4] Delete Account Trojan                 → del-tr
[•5] Check User Login Trojan               → cek-tr
[•0] BACK TO MENU                          → menu
```

**Trojan GFW Features**:
- **Traditional Protocol**: Standard Trojan implementation
- **GRPC Support**: HTTP/2 based transport
- **WebSocket Support**: WebSocket transport option

---

### 6. ⚙️ SYSTEM MENU (menu-set.sh)

**Fungsi**: Konfigurasi dan maintenance system

#### Menu Options:
```
[•1] Panel Domain                          → menu-domain
[•2] Change Port All Account               → port-change
[•3] Webmin Menu                           → menu-webmin
[•4] Speedtest VPS                         → speedtest
[•5] About Script                          → about
[•6] Set Auto Reboot                       → auto-reboot
[•7] Restart All Service                   → restart
[•8] Change Banner                         → nano /etc/issue.net
[•9] Cek Bandwith                          → bw
[•0] BACK TO MENU                          → menu
```

**System Management Features**:
- **Domain Management**: Configure/change domain
- **Port Management**: Change service ports
- **Webmin**: Web-based administration
- **Performance Test**: Server speed testing  
- **Auto Maintenance**: Scheduled reboot/restart
- **Monitoring**: Bandwidth usage monitoring

---

### 7. 📊 STATUS SERVICE (running.sh)

**Fungsi**: Monitor status semua service

#### Service Monitoring:
```
🔍 SYSTEM SERVICES STATUS:
✅ nginx: ACTIVE/INACTIVE
✅ xray: ACTIVE/INACTIVE  
✅ fail2ban: ACTIVE/INACTIVE
✅ ssh: ACTIVE/INACTIVE
✅ dropbear: ACTIVE/INACTIVE
✅ stunnel: ACTIVE/INACTIVE
✅ trojan-go: ACTIVE/INACTIVE

📊 SYSTEM INFORMATION:
- CPU Usage
- RAM Usage
- Disk Usage
- Network Traffic
- Active Connections
```

---

### 8. 🧹 CLEAR RAM CACHE (clearcache.sh)

**Fungsi**: Membersihkan cache memory server

#### Cache Cleaning Process:
```bash
# Clear page cache
echo 1 > /proc/sys/vm/drop_caches

# Clear dentries and inodes  
echo 2 > /proc/sys/vm/drop_caches

# Clear all caches
echo 3 > /proc/sys/vm/drop_caches
```

## 📊 **ENHANCED ACCOUNT CREATION WORKFLOW**

### **🎯 SIMPLIFIED USER EXPERIENCE**

#### **Before (Complex Menu)**:
```
VMess Menu:
[1] Create WebSocket → Only WebSocket config
[2] Create XHTTP → Only XHTTP config  
[3] Create GRPC → Only GRPC config

VLess Menu:  
[1] Create WebSocket → Only WebSocket config
[2] Create REALITY → Only REALITY config
[3] Create XHTTP → Only XHTTP config
```
**Problem**: User harus buat 3-6 akun terpisah untuk fleksibilitas

#### **After (Enhanced Creator)**:
```
VMess Menu:
[1] Create VMess Account → ALL protocols (WS+GRPC+XHTTP)

VLess Menu:
[1] Create VLess Account → ALL protocols (WS+GRPC+XHTTP+REALITY)
```
**Benefit**: 1 akun = maximum flexibility dengan same UUID

### **🚀 ENHANCED OUTPUT FORMAT**

#### **VMess Enhanced Output**:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Enhanced VMess Account        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks        : username
Domain         : domain.com
UUID           : 12345678-1234-1234-1234-123456789012
Networks       : ws/grpc/xhttp
Ports          : 443 (TLS) / 80 (none-TLS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Link TLS       : vmess://...     (WebSocket)
Link none TLS  : vmess://...     (WebSocket)  
Link GRPC      : vmess://...     (GRPC)
Link XHTTP     : vmess://...     (XHTTP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ MULTI-TRANSPORT: All VMess protocols!
🔥 SAME UUID: Choose protocol by need!
📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile)
```

#### **VLess Enhanced Output**:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Enhanced VLess Account        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks        : username
Domain         : domain.com  
UUID           : 12345678-1234-1234-1234-123456789012
Networks       : ws/grpc/xhttp/reality
Ports          : 443 (TLS) / 80 (none-TLS) / 8443 (REALITY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Link TLS       : vless://...     (WebSocket)
Link none TLS  : vless://...     (WebSocket)
Link GRPC      : vless://...     (GRPC) 
Link XHTTP     : vless://...     (XHTTP)
🚀 BONUS REALITY  : vless://...  (REALITY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ MULTI-TRANSPORT: All VLess protocols + REALITY!
🔥 SAME UUID: Choose protocol by need!
📱 FLEXIBLE: WS(compatibility) + GRPC(performance) + XHTTP(mobile) + REALITY(stealth)
```

### **📋 PROTOCOL SELECTION GUIDE**

#### **When to Use Each Protocol**:
```bash
🌐 WebSocket (WS)
├── Use Case: General compatibility
├── Ports: 80, 443, 8080
├── Best For: Wide device support
└── Performance: Good

🚀 GRPC  
├── Use Case: High performance
├── Ports: 443 
├── Best For: Fast connections
└── Performance: Excellent

⚡ XHTTP
├── Use Case: Mobile/STB optimization  
├── Ports: 443
├── Best For: Mobile devices, STB
└── Performance: Superior for mobile

🛡️ REALITY (VLess Only)
├── Use Case: Maximum stealth
├── Ports: 8443 (fixed)
├── Best For: Strict censorship bypass
└── Performance: Good + undetectable
```

---

## 🔄 WORKFLOW UMUM PENGGUNAAN

### Workflow Admin Server:
```
1. LOGIN → Menu Utama
2. CHECK STATUS → running (monitor services)
3. USER MANAGEMENT → menu-ssh/vmess/vless/trojan
4. SYSTEM MAINTENANCE → menu-set
5. PERFORMANCE → clearcache + speedtest
```

### Workflow User Management:
```
1. CREATE ACCOUNT → Pilih protokol (SSH/VMess/VLess/Trojan)
2. GENERATE CONFIG → Auto-generate user config
3. MONITOR USAGE → Check login status
4. MAINTENANCE → Renew/Delete expired users
5. TROUBLESHOOT → Check service status
```

### Workflow Troubleshooting:
```
1. CHECK STATUS → running (service status)
2. CHECK LOGS → /var/log/ monitoring
3. RESTART SERVICES → menu-set → restart
4. CLEAR CACHE → clearcache
5. TEST PERFORMANCE → speedtest
```

---

## 🎯 PROTOKOL YANG DIDUKUNG

### Modern Protocols (2025):
- ✅ **VLESS REALITY**: Stealth, no certificate needed
- ✅ **VMESS/VLESS XHTTP**: Superior mobile performance  
- ✅ **Trojan-Go**: STB optimized
- ✅ **SSH WebSocket**: Enhanced SSH tunneling

### Traditional Protocols:
- ✅ **SSH/OpenVPN**: Standard tunneling
- ✅ **VMess WebSocket**: V2Ray protocol
- ✅ **VLess WebSocket**: Lightweight version
- ✅ **Trojan GFW**: Traditional Trojan

### Transport Methods:
- 🌐 **WebSocket**: Wide compatibility
- ⚡ **XHTTP**: Enhanced performance
- 🔒 **REALITY**: Anti-detection stealth
- 📱 **GRPC**: HTTP/2 based

---

## 🛠️ TOOLS & UTILITIES

### Built-in Tools:
```bash
menu                    # Main menu interface
test-sni-bypass        # Test SNI bypass capability  
vpn-system-check       # Comprehensive system validation
speedtest              # Server performance test
```

### Log Monitoring:
```bash
/var/log/xray/         # Xray service logs
/var/log/nginx/        # Web server logs  
/var/log/auth.log      # SSH authentication logs
/var/log/fail2ban.log  # Security events
```

### Configuration Files:
```bash
/etc/xray/config.json              # Xray main config
/etc/xray/vmess-sni-configs/       # SNI bypass configs
/etc/nginx/conf.d/xray.conf        # Reverse proxy config
/etc/fail2ban/jail.d/              # Security rules
```

Ini adalah workflow lengkap untuk manajemen VPN server YT ZIXSTYLE 2025 dengan semua fitur modern dan protokol terbaru! 🚀
