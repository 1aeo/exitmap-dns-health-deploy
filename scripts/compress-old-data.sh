#!/bin/bash
# exitmap DNS Health - Monthly Data Compression
# Compresses validation files 180+ days old into monthly archives
# 
# Archives are named: exitmap-YYYYMM.tar.gz (e.g., exitmap-202501.tar.gz)
# 
# Usage:
#   ./scripts/compress-old-data.sh              # Compress 180+ day old files
#   ./scripts/compress-old-data.sh --dry-run    # Show what would be compressed

set -euo pipefail

# Security: Use safe umask for created files
umask 077

# Source shared functions and initialize paths
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
init_paths
load_config || true

PUBLIC_DIR="${OUTPUT_DIR:-$DEPLOY_DIR/public}"
LOG_DIR="${LOG_DIR:-$DEPLOY_DIR/logs}"

# Parse arguments
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

echo "========================================="
echo "Data Compression - $(date)"
[[ "$DRY_RUN" == "true" ]] && echo "*** DRY RUN - No changes will be made ***"
echo "========================================="

# Check available disk space (need at least 5GB free for safety)
AVAILABLE=$(df -BG "$DEPLOY_DIR" | tail -1 | awk '{print $4}' | tr -d 'G')
if [[ "$AVAILABLE" -lt 5 ]]; then
    log_error "Less than 5GB free disk space. Aborting."
    exit 1
fi

# Create archives directories
mkdir -p "$PUBLIC_DIR/archives" "$LOG_DIR/archives"
chmod 755 "$PUBLIC_DIR/archives" "$LOG_DIR/archives"

# === COMPRESS VALIDATION FILES (180+ days old) ===
echo "Checking for validation files 180+ days old..."

# Get list of months with old files
# dns_health_YYYYMMDD_HHMMSS.json -> extract YYYYMM
MONTHS_TO_COMPRESS=$(find "$PUBLIC_DIR" -maxdepth 1 -name "dns_health_*.json" -mtime +180 -type f 2>/dev/null | \
    sed 's/.*dns_health_\([0-9]\{6\}\).*/\1/' | sort -u)

if [[ -n "$MONTHS_TO_COMPRESS" ]]; then
    for MONTH in $MONTHS_TO_COMPRESS; do
        # Security: Validate MONTH format (should be 6 digits YYYYMM)
        if ! echo "$MONTH" | grep -qE '^[0-9]{6}$'; then
            echo "  ⚠ Skipping invalid month format: $MONTH"
            continue
        fi
        
        ARCHIVE_NAME="exitmap-$MONTH.tar.gz"
        ARCHIVE_PATH="$PUBLIC_DIR/archives/$ARCHIVE_NAME"
        
        echo "Processing month: $MONTH"
        
        # Find all files for this month using null-delimited output for safety
        mapfile -d '' FILES_ARRAY < <(find "$PUBLIC_DIR" -maxdepth 1 -name "dns_health_${MONTH}*.json" -mtime +180 -type f -print0 2>/dev/null)
        
        if [[ ${#FILES_ARRAY[@]} -gt 0 ]]; then
            FILE_COUNT=${#FILES_ARRAY[@]}
            echo "  Found $FILE_COUNT files for $MONTH"
            
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "  [DRY RUN] Would compress $FILE_COUNT files → $ARCHIVE_NAME"
                continue
            fi
            
            # Security: Build basename list safely without command injection
            BASENAMES=()
            for f in "${FILES_ARRAY[@]}"; do
                BASENAMES+=("$(basename "$f")")
            done
            
            # Create archive with all files for this month
            tar czf "$ARCHIVE_PATH" -C "$PUBLIC_DIR" "${BASENAMES[@]}" 2>/dev/null
            
            # Verify archive was created and contains files
            if [[ -f "$ARCHIVE_PATH" ]] && tar tzf "$ARCHIVE_PATH" >/dev/null 2>&1; then
                # Archive verified, safe to delete originals
                for f in "${FILES_ARRAY[@]}"; do
                    rm -f "$f"
                done
                chmod 644 "$ARCHIVE_PATH"
                log_success "Compressed $FILE_COUNT files → $ARCHIVE_NAME"
            else
                log_error "Archive verification failed, keeping originals"
                rm -f "$ARCHIVE_PATH"
            fi
        fi
    done
else
    echo "No files older than 180 days found"
fi

# === COMPRESS CRON LOG (if > 50 MB) ===
echo "Checking log sizes..."

CRON_LOG="$LOG_DIR/cron.log"
if [[ -f "$CRON_LOG" ]]; then
    LOG_SIZE=$(stat -c%s "$CRON_LOG" 2>/dev/null || echo 0)
    # Security: Validate LOG_SIZE is a number
    if ! [[ "$LOG_SIZE" =~ ^[0-9]+$ ]]; then
        LOG_SIZE=0
    fi
    LOG_SIZE_MB=$((LOG_SIZE / 1048576))
    
    if [[ "$LOG_SIZE_MB" -gt 50 ]]; then
        # Security: Use safe date format and validate
        DATE_PART=$(date +%Y-%m)
        if [[ "$DATE_PART" =~ ^[0-9]{4}-[0-9]{2}$ ]]; then
            ARCHIVE_NAME="cron-${DATE_PART}.log.gz"
        else
            echo "  ⚠ Invalid date format, skipping log compression"
            ARCHIVE_NAME=""
        fi
        
        if [[ -n "$ARCHIVE_NAME" ]]; then
            echo "cron.log is ${LOG_SIZE_MB}MB, compressing..."
            
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "  [DRY RUN] Would compress cron.log → $ARCHIVE_NAME"
            else
                # Compress entire log
                gzip -9 -c "$CRON_LOG" > "$LOG_DIR/archives/$ARCHIVE_NAME"
                
                # Verify compression
                if [[ -f "$LOG_DIR/archives/$ARCHIVE_NAME" ]] && gunzip -t "$LOG_DIR/archives/$ARCHIVE_NAME" 2>/dev/null; then
                    # Keep only last 500 lines in current log (use temp file safely)
                    TEMP_FILE=$(mktemp "$LOG_DIR/cron.log.XXXXXX")
                    tail -500 "$CRON_LOG" > "$TEMP_FILE"
                    mv "$TEMP_FILE" "$CRON_LOG"
                    chmod 644 "$LOG_DIR/archives/$ARCHIVE_NAME"
                    log_success "Compressed to $ARCHIVE_NAME"
                else
                    log_error "Compression verification failed"
                    rm -f "$LOG_DIR/archives/$ARCHIVE_NAME"
                fi
            fi
        fi
    else
        echo "cron.log is ${LOG_SIZE_MB}MB (under 50MB threshold)"
    fi
else
    echo "No cron.log found"
fi

# === UPDATE FILES MANIFEST ===
echo "Updating file manifest..."

if [[ "$DRY_RUN" == "true" ]]; then
    echo "  [DRY RUN] Would update files.json"
else
    cd "$PUBLIC_DIR" || exit 1
    
    # List current uncompressed files (sorted newest first)
    ls -1 dns_health_*.json 2>/dev/null | sort -r | jq -R -s 'split("\n") | map(select(length > 0))' > files.json.tmp || echo '[]' > files.json.tmp
    
    # Add archives to manifest if they exist
    if [[ -d archives ]] && ls archives/*.tar.gz >/dev/null 2>&1; then
        # Create combined manifest with files and archives
        ARCHIVES=$(ls -1 archives/*.tar.gz 2>/dev/null | jq -R -s 'split("\n") | map(select(length > 0))')
        jq -n --argjson files "$(cat files.json.tmp)" --argjson archives "$ARCHIVES" \
            '{files: $files, archives: $archives}' > files.json.new 2>/dev/null && mv files.json.new files.json
        rm -f files.json.tmp
    else
        mv files.json.tmp files.json
    fi
    
    chmod 644 files.json 2>/dev/null || true
    log_success "Updated files.json"
fi

echo ""
echo "Compression completed at $(date)"
