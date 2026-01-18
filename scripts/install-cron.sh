#!/bin/bash
# Install crontab entry from config.env settings
#
# Usage: ./scripts/install-cron.sh [--dry-run]
#
# Reads DEPLOY_PATH and CRON_SCHEDULE from config.env and installs
# the appropriate crontab entry for DNS validation.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_PATH="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$DEPLOY_PATH/config.env"

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
fi

# Load config
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: config.env not found at $CONFIG_FILE"
    exit 1
fi

# Source config to get variables (expand $HOME)
set -a
source "$CONFIG_FILE"
set +a

# Expand DEPLOY_PATH (in case it uses $HOME)
DEPLOY_PATH=$(eval echo "$DEPLOY_PATH")

# Default schedule if not set
CRON_SCHEDULE="${CRON_SCHEDULE:-15 */2 * * *}"
# Remove quotes if present
CRON_SCHEDULE="${CRON_SCHEDULE//\"/}"

# Build cron entry
CRON_ENTRY="$CRON_SCHEDULE $DEPLOY_PATH/scripts/run-dns-validation.sh -c 4 >> $DEPLOY_PATH/logs/cron.log 2>&1"
CRON_MARKER="# exitmap-dnshealth"

echo "Deploy path: $DEPLOY_PATH"
echo "Schedule: $CRON_SCHEDULE"
echo ""
echo "Cron entry to install:"
echo "$CRON_MARKER - DNS validation every 2 hours with 4 cross-validation instances"
echo "$CRON_ENTRY"
echo ""

if $DRY_RUN; then
    echo "[Dry run] Would install the above cron entry"
    exit 0
fi

# Get current crontab (or empty if none)
CURRENT_CRON=$(crontab -l 2>/dev/null || true)

# Check if our entry already exists
if echo "$CURRENT_CRON" | grep -q "exitmap-dnshealth"; then
    echo "Updating existing exitmap-dnshealth cron entry..."
    # Remove old entry (both comment and command lines)
    NEW_CRON=$(echo "$CURRENT_CRON" | grep -v "exitmap-dnshealth" | grep -v "run-dns-validation.sh")
else
    echo "Adding new exitmap-dnshealth cron entry..."
    NEW_CRON="$CURRENT_CRON"
fi

# Add new entry
NEW_CRON="$NEW_CRON
$CRON_MARKER - DNS validation every 2 hours with 4 cross-validation instances
$CRON_ENTRY"

# Remove leading/trailing blank lines and install
echo "$NEW_CRON" | sed '/^$/N;/^\n$/d' | crontab -

echo "Done! Current crontab:"
crontab -l
