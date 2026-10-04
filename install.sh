#!/usr/bin/env bash
#
# install.sh - installs probe-hunter for system-wide use
#
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$REPO_DIR/probe-hunter.py"
LINK_PATH="/usr/local/bin/probe-hunter"

echo "[*] Installing Python dependencies..."
pip3 install --break-system-packages -r "$REPO_DIR/requirements.txt"

echo "[*] Making probe-hunter.py executable..."
chmod +x "$SCRIPT_PATH"

echo "[*] Symlinking to $LINK_PATH..."
sudo ln -sf "$SCRIPT_PATH" "$LINK_PATH"

echo "[+] Done. Run it with: sudo probe-hunter"
