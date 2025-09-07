Simple One-Line Command:
wget https://raw.githubusercontent.com/H-Pri3l/v4/main/install-modern.sh && chmod +x install-modern.sh && ./install-modern.sh

Manual Installation:
sysctl -w net.ipv6.conf.all.disable_ipv6=1 &&
sysctl -w net.ipv6.conf.default.disable_ipv6=1 &&
apt update &&
apt install -y bzip2 gzip coreutils screen curl unzip build-essential &&
wget https://raw.githubusercontent.com/H-Pri3l/v4/main/setup-modern.sh &&
chmod +x setup-modern.sh &&
sed -i -e 's/\r$//' setup-modern.sh &&
screen -S setup ./setup-modern.sh

Perlu akses root langsung sebelum menjankan script (dengan "su")