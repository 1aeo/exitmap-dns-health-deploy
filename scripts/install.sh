#!/bin/bash
# Install exitmap DNS health validation dependencies and setup
#
# Usage:
#   ./scripts/install.sh
#
# This script:
#   1. Creates a Python virtual environment
#   2. Installs exitmap and dependencies
#   3. Creates required directories
#   4. Copies config template if not exists
#   5. Verifies Tor is available

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
EXITMAP_DIR="$(dirname "$DEPLOY_DIR")"

echo "=== exitmap DNS Health Validation Setup ==="
echo "Directory: $EXITMAP_DIR"
echo

# Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is required but not found"
    echo "Install with: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python version: $PYTHON_VERSION"

# Create virtual environment
echo
echo "Creating virtual environment..."
cd "$EXITMAP_DIR"

if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    echo "Created venv/"
else
    echo "venv/ already exists"
fi

# Activate and install
source venv/bin/activate
echo "Activated virtual environment"

echo
echo "Installing dependencies..."
pip install --upgrade pip wheel
pip install -e .

# Install optional dependencies for cloud uploads
echo
echo "Installing optional dependencies..."
pip install awscli 2>/dev/null || echo "awscli not installed (optional, for cloud uploads)"

# Create directories
echo
echo "Creating directories..."
mkdir -p results logs
chmod 755 results logs
echo "Created results/ and logs/"

# Copy config template
if [[ ! -f "$DEPLOY_DIR/config.env" ]] && [[ -f "$DEPLOY_DIR/config.env.example" ]]; then
    cp "$DEPLOY_DIR/config.env.example" "$DEPLOY_DIR/config.env"
    echo "Created deploy/config.env from template"
    echo "  Edit deploy/config.env to customize settings"
else
    echo "config.env already exists or template not found"
fi

# Make scripts executable
echo
echo "Making scripts executable..."
chmod +x "$DEPLOY_DIR/scripts/"*.sh 2>/dev/null || true

# Check for Tor
echo
echo "Checking Tor availability..."
if command -v tor &>/dev/null; then
    TOR_VERSION=$(tor --version | head -1)
    echo "Tor found: $TOR_VERSION"
else
    echo "Warning: Tor not found in PATH"
    echo "Install with: sudo apt install tor"
    echo "exitmap will start its own Tor process, but tor must be installed"
fi

# Verify DNS
echo
echo "Verifying wildcard DNS..."
if command -v dig &>/dev/null; then
    RESOLVED=$(dig +short test.tor.exit.validator.1aeo.com 2>/dev/null || echo "")
    if [[ "$RESOLVED" == "64.65.4.1" ]]; then
        echo "Wildcard DNS working: test.tor.exit.validator.1aeo.com -> $RESOLVED"
    else
        echo "Warning: Wildcard DNS check failed"
        echo "  Expected: 64.65.4.1"
        echo "  Got: $RESOLVED"
        echo "  The scan will still work, but you may want to investigate"
    fi
else
    echo "dig not found - skipping DNS verification"
    echo "Install with: sudo apt install dnsutils"
fi

# Summary
echo
echo "=== Setup Complete ==="
echo
echo "Next steps:"
echo "  1. Edit config.env to customize settings (optional)"
echo "  2. Run a test scan:"
echo "     source venv/bin/activate"
echo "     ./deploy/scripts/run_dns_validation.sh"
echo
echo "  3. Set up scheduled runs (optional):"
echo "     sudo cp deploy/configs/cron.d/exitmap-dns /etc/cron.d/"
echo "     sudo nano /etc/cron.d/exitmap-dns"
echo
echo "  4. View results:"
echo "     cat results/latest.json | python3 -m json.tool"
