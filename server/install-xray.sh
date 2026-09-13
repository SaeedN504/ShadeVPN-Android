#!/bin/sh
# ShadeVPN Xray REALITY server installer.
#
# Run this ON the VPS (Debian/Ubuntu):
#   sh ./install-xray.sh
#
# What it does:
#   1. Installs Xray-core from the official install script (xray-core releases,
#      not a fork).
#   2. Generates ALL secrets locally on the server: UUID, x25519 keypair,
#      short id. None of this material ever needs to be in the repo or on
#      your laptop.
#   3. Writes /usr/local/etc/xray/config.json configured for VLESS + REALITY
#      over TCP on port 443, camouflaging SNI to a real site.
#   4. Opens the firewall port if ufw is active.
#   5. Prints the exact `vless://` link to paste into the ShadeVPN app.
#
# Idempotent: re-running regenerates config + secrets and restarts xray.
set -eu

CONF_DIR=/usr/local/etc/xray
CONF_FILE=$CONF_DIR/config.json
DEST_SNI=www.microsoft.com:443

echo "==> [1/5] Installing Xray-core"
if command -v xray >/dev/null 2>&1; then
    echo "    xray already installed: $(xray version | head -n1)"
else
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

echo "==> [2/5] Generating secrets locally (never leaves this server)"
UUID=$(/usr/local/bin/xray uuid)
KEYS=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(printf '%s\n' "$KEYS" | sed -n 's/^Private key: //p')
PUBLIC_KEY=$(printf '%s\n' "$KEYS" | sed -n 's/^Public key: //p')
SHORT_ID=$(openssl rand -hex 4)
SERVER_IP=$(curl -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

echo "==> [3/5] Writing $CONF_FILE"
mkdir -p "$CONF_DIR"

cat > "$CONF_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DEST_SNI",
          "xver": 0,
          "serverNames": ["$(printf '%s' "$DEST_SNI" | cut -d: -f1)"],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": ["$SHORT_ID"]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF

chmod 600 "$CONF_FILE"

echo "==> [4/5] Validating config and starting service"
/usr/local/bin/xray run -test -c "$CONF_FILE" >/dev/null
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
systemctl --no-pager --lines=0 status xray | head -n 3 || true

echo "==> [5/5] Firewall"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 443/tcp >/dev/null
    echo "    ufw: allowed 443/tcp"
else
    echo "    ufw not active; make sure port 443/tcp is open in your cloud firewall (OVH panel)."
fi

echo
echo "=============================================================="
echo " Xray REALITY is running. Paste this into ShadeVPN:"
echo "=============================================================="
echo
echo "vless://$UUID@$SERVER_IP:443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=$(printf '%s' "$DEST_SNI" | cut -d: -f1)&pbk=$PUBLIC_KEY&sid=$SHORT_ID&fp=chrome#ShadeVPN"
echo
echo "=============================================================="
echo " Store the link somewhere safe — it contains your UUID."
echo " Public key + short id are fine to keep in the link; the"
echo " private key never left this server."
echo "=============================================================="
