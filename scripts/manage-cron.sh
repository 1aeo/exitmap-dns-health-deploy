#!/bin/bash
# Manage crontab for DNS Health Validation
#
# Usage:
#   ./scripts/manage_cron.sh [install|remove|status]
#
# Configuration:
#   Set CRON_SCHEDULE in config.env (default: "0 */6 * * *" = every 6 hours)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
EXITMAP_DIR="$(dirname "$DEPLOY_DIR")"

# Load configuration
if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
fi

LOG_DIR="${LOG_DIR:-$EXITMAP_DIR/logs}"
CRON_SCHEDULE="${CRON_SCHEDULE:-0 */6 * * *}"
CRON_MARKER="# exitmap-dnshealth"

# Use run_with_retry.sh for robustness
CRON_CMD="$SCRIPT_DIR/run_with_retry.sh scheduled_\$(date +\\%Y\\%m\\%d_\\%H\\%M)"

show_status() {
    echo "Current crontab entries for exitmap:"
    crontab -l 2>/dev/null | grep -A1 "$CRON_MARKER" || echo "  (none installed)"
    echo ""
    echo "Configured schedule: $CRON_SCHEDULE"
    echo "Log directory: $LOG_DIR"
}

install_cron() {
    echo "Installing crontab..."
    
    # Remove existing entry if present
    (crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | grep -v "run_with_retry.sh" | grep -v "run_dns_validation.sh") | crontab - 2>/dev/null || true
    
    # Add new entry
    (crontab -l 2>/dev/null; echo "$CRON_MARKER"; echo "$CRON_SCHEDULE $CRON_CMD >> $LOG_DIR/cron.log 2>&1") | crontab -
    
    echo "Installed. New crontab:"
    crontab -l | grep -A1 "$CRON_MARKER"
    echo ""
    echo "Logs will be written to: $LOG_DIR/cron.log"
}

remove_cron() {
    echo "Removing crontab entry..."
    (crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | grep -v "run_with_retry.sh" | grep -v "run_dns_validation.sh") | crontab - 2>/dev/null || true
    echo "Removed."
}

case "${1:-status}" in
    install)
        install_cron
        ;;
    remove)
        remove_cron
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 [install|remove|status]"
        exit 1
        ;;
esac
