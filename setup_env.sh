#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$HOME/tools"
GO_VERSION="1.22.3"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Updating apt packages"
sudo apt-get update -y && sudo apt-get upgrade -y

echo "==> Installing apt dependencies"
sudo apt-get install -y \
    python3.11 python3.11-venv python3-pip \
    git curl wget jq tmux \
    nmap masscan sqlmap \
    build-essential libssl-dev

echo "==> Installing Go ${GO_VERSION}"
if ! go version 2>/dev/null | grep -q "${GO_VERSION}"; then
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc"; then
    echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"' >> "$HOME/.bashrc"
fi

echo "==> Installing Go-based security tools"
GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/assetfinder@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%%@*}")
    if ! command -v "$name" &>/dev/null; then
        echo "  Installing $name..."
        go install "$tool"
    else
        echo "  $name already installed, skipping"
    fi
done

echo "==> Cloning SecLists (shallow)"
mkdir -p "$TOOLS_DIR"
if [ ! -d "$TOOLS_DIR/SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TOOLS_DIR/SecLists"
else
    echo "  SecLists already present, skipping"
fi

echo "==> Setting up Python virtual environment"
if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3.11 -m venv "$PROJECT_DIR/venv"
fi

source "$PROJECT_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$PROJECT_DIR/requirements.txt"

echo "==> Installing Playwright browsers"
python -m playwright install-deps chromium
python -m playwright install chromium

echo "==> Copying .env.example → .env (if not present)"
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    echo "  Created .env — add your GITHUB_TOKEN if desired"
fi

echo ""
echo "Setup complete. Run: source venv/bin/activate"
