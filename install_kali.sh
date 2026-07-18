#!/usr/bin/env bash
# install_kali.sh — one-shot automated setup for Kali Linux
#
# Handles: apt dependencies, Go install (if missing), PATH setup,
# ProjectDiscovery tool install, nuclei template update.
#
# Usage:
#   chmod +x install_kali.sh
#   ./install_kali.sh
#
set -euo pipefail

echo "=== Kali automated setup for bug bounty recon pipeline ==="

# ---------- 1. apt dependencies ----------
echo "[1/5] Installing apt dependencies (libpcap-dev, git, curl, chromium)..."
sudo apt update -qq
sudo apt install -y -qq libpcap-dev git curl chromium

# ---------- 2. Go ----------
if ! command -v go &>/dev/null; then
  echo "[2/5] Go not found — installing via apt..."
  sudo apt install -y -qq golang-go
else
  echo "[2/5] Go already installed ($(go version))"
fi

# ---------- 3. PATH setup ----------
GOPATH_BIN="$(go env GOPATH)/bin"
SHELL_RC="$HOME/.bashrc"
[[ "$SHELL" == *zsh* ]] && SHELL_RC="$HOME/.zshrc"

if ! grep -q "$GOPATH_BIN" "$SHELL_RC" 2>/dev/null; then
  echo "[3/5] Adding $GOPATH_BIN to PATH in $SHELL_RC (prepended, so it takes"
  echo "      priority over any same-named system tools, e.g. python's httpx)"
  echo "export PATH=$GOPATH_BIN:\$PATH" >> "$SHELL_RC"
else
  echo "[3/5] PATH already configured in $SHELL_RC"
fi
export PATH="$GOPATH_BIN:$PATH"

# ---------- 4. Install ProjectDiscovery tools ----------
echo "[4/5] Installing subfinder, httpx, naabu, nuclei..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "Installing katana (JS/endpoint crawler)..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "Installing gowitness (screenshot tool)..."
go install -v github.com/sensepost/gowitness@latest

echo "Installing gau (historical URL fetcher)..."
go install -v github.com/lc/gau/v2/cmd/gau@latest

# naabu on Kali needs cap_net_raw to do SYN scans without sudo — set it once:
if command -v "$GOPATH_BIN/naabu" &>/dev/null; then
  echo "      Granting naabu raw socket capability (for non-root SYN scans)..."
  sudo setcap cap_net_raw,cap_net_admin=eip "$GOPATH_BIN/naabu" || \
    echo "      (setcap failed — naabu will just need sudo or fall back to connect scan)"
fi

# ---------- 5. Update nuclei templates ----------
echo "[5/5] Updating nuclei templates..."
"$GOPATH_BIN/nuclei" -update-templates -silent || true

echo
echo "=== Setup complete ==="
echo "Run 'source $SHELL_RC' or open a new terminal to pick up PATH changes."
echo "Then: ./recon.sh -d yourtarget.com"