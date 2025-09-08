#!/bin/bash
#
# Fix IP Permission Script - YT ZIXSTYLE 2025
# Purpose: Memperbaiki semua script yang salah format IP check
# ===============================================================================

echo "🔧 FIXING IP PERMISSION ISSUES..."
echo "================================="

# List of files that need to be fixed
FILES=(
    "setup.sh"
    "menu/menu.sh"
    "ssh/usernew.sh"
    "ssh/renew.sh"
    "xray/add-tr.sh"
    "xray/add-vless.sh"
    "xray/add-ws.sh"
    "xray/addtrgo.sh"
    "xray/certv2ray.sh"
    "xray/renew-tr.sh"
    "xray/renew-vless.sh"
    "xray/renew-ws.sh"
    "xray/renewtrgo.sh"
)

CURRENT_DIR=$(pwd)

for file in "${FILES[@]}"; do
    FULL_PATH="${CURRENT_DIR}/${file}"
    if [ -f "$FULL_PATH" ]; then
        echo "🔧 Fixing: $file"
        # Replace complex awk parsing with simple grep
        sed -i "s/IZIN=\$(curl -sS https:\/\/raw\.githubusercontent\.com\/reshasturl\/tnl-2025\/main\/ip | awk '{print \$[0-9]*}' | grep \$MYIP)/IZIN=\$(curl -sS https:\/\/raw.githubusercontent.com\/reshasturl\/tnl-2025\/main\/ip | grep \$MYIP)/g" "$FULL_PATH"
        # Also fix the condition to check if IZIN is not empty
        sed -i 's/if \[ "\$MYIP" = "\$IZIN" \]; then/if [ -n "\$IZIN" ]; then/g' "$FULL_PATH"
        echo "✅ Fixed: $file"
    else
        echo "⚠️  File not found: $file"
    fi
done

echo ""
echo "✅ IP Permission fix completed!"
echo "🧪 Testing IP permission check..."

# Test the permission function
MYIP=$(curl -sS ipv4.icanhazip.com)
IZIN=$(curl -sS https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ip | grep $MYIP)

if [ -n "$IZIN" ]; then
    echo "✅ IP Permission Test: PASSED"
    echo "🎯 Your IP ($MYIP) is authorized!"
    echo "📋 Authorization line: $IZIN"
else
    echo "❌ IP Permission Test: FAILED"
    echo "🚫 Your IP ($MYIP) is not authorized"
fi

echo ""
echo "📋 Current authorized IPs:"
curl -sS https://raw.githubusercontent.com/reshasturl/tnl-2025/main/ip | grep -v "^#" | grep -v "^$"
