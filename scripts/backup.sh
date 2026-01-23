#!/bin/bash
# Automated backup script for OSINT Agent data
# Run daily via cron: 0 2 * * * /path/to/backup.sh
#
# ENCRYPTION SETUP:
#   1. Generate a key pair: gpg --full-generate-key
#   2. Export GPG_RECIPIENT in your environment or set below
#   3. For automated decryption, ensure the private key is available
#
# DECRYPTION:
#   gpg -d backup.tar.gz.gpg | tar xzf -

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DATE="$(date +%Y-%m-%d)"
BACKUP_DIR="$PROJECT_DIR/backups/$BACKUP_DATE"
TEMP_DIR="$PROJECT_DIR/backups/.tmp-$BACKUP_DATE"

# Encryption config - set GPG_RECIPIENT to enable encryption
# Example: export GPG_RECIPIENT="analyst@organization.com"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"
ENCRYPT_BACKUPS="${ENCRYPT_BACKUPS:-true}"

echo "Starting backup at $(date)"
echo "Project: $PROJECT_DIR"
echo "Backup: $BACKUP_DIR"

# Check encryption availability
USE_ENCRYPTION=false
if [ "$ENCRYPT_BACKUPS" = "true" ] && [ -n "$GPG_RECIPIENT" ]; then
    if command -v gpg &> /dev/null; then
        if gpg --list-keys "$GPG_RECIPIENT" &> /dev/null; then
            USE_ENCRYPTION=true
            echo "Encryption: ENABLED (recipient: $GPG_RECIPIENT)"
        else
            echo "WARNING: GPG key for '$GPG_RECIPIENT' not found - backups will be unencrypted"
        fi
    else
        echo "WARNING: gpg not installed - backups will be unencrypted"
    fi
elif [ "$ENCRYPT_BACKUPS" = "true" ]; then
    echo "WARNING: GPG_RECIPIENT not set - backups will be unencrypted"
    echo "  Set GPG_RECIPIENT=your@email.com to enable encryption"
else
    echo "Encryption: DISABLED (ENCRYPT_BACKUPS=$ENCRYPT_BACKUPS)"
fi

# Create directories
mkdir -p "$BACKUP_DIR"
if [ "$USE_ENCRYPTION" = true ]; then
    mkdir -p "$TEMP_DIR"
    trap 'rm -rf "$TEMP_DIR"' EXIT
fi

# Determine where to write files (temp dir if encrypting, backup dir if not)
WORK_DIR="$BACKUP_DIR"
if [ "$USE_ENCRYPTION" = true ]; then
    WORK_DIR="$TEMP_DIR"
fi

# Backup SQLite database (safe during writes)
if [ -f "$PROJECT_DIR/data/iocs.db" ]; then
    sqlite3 "$PROJECT_DIR/data/iocs.db" ".backup '$WORK_DIR/iocs.db'"
    echo "✓ IOC database backed up"
else
    echo "- No IOC database found (skipped)"
fi

# Backup context files
if [ -d "$PROJECT_DIR/data/context" ]; then
    cp -r "$PROJECT_DIR/data/context" "$WORK_DIR/"
    echo "✓ Context files backed up"
fi

# Backup config (excluding secrets)
if [ -d "$PROJECT_DIR/config" ]; then
    mkdir -p "$WORK_DIR/config"
    cp "$PROJECT_DIR/config/"*.json "$WORK_DIR/config/" 2>/dev/null || true
    echo "✓ Config files backed up"
fi

# Encrypt if enabled
if [ "$USE_ENCRYPTION" = true ]; then
    echo "Encrypting backup..."
    ARCHIVE_NAME="backup-$BACKUP_DATE.tar.gz.gpg"
    tar -czf - -C "$TEMP_DIR" . | gpg --encrypt --recipient "$GPG_RECIPIENT" --trust-model always -o "$BACKUP_DIR/$ARCHIVE_NAME"
    echo "✓ Backup encrypted: $ARCHIVE_NAME"

    # Clean up temp directory (trap will also handle this)
    rm -rf "$TEMP_DIR"
fi

# Compress logs older than 7 days
find "$PROJECT_DIR/data/logs" -name "*.jsonl" -mtime +7 -exec gzip {} \; 2>/dev/null || true
echo "✓ Old logs compressed"

# Remove backups older than 30 days
find "$PROJECT_DIR/backups" -maxdepth 1 -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null || true
echo "✓ Old backups cleaned"

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
echo ""
echo "Backup completed: $BACKUP_DIR ($BACKUP_SIZE)"
if [ "$USE_ENCRYPTION" = true ]; then
    echo "Encrypted with GPG (recipient: $GPG_RECIPIENT)"
    echo "Decrypt with: gpg -d $BACKUP_DIR/$ARCHIVE_NAME | tar xzf -"
else
    echo "WARNING: Backup is NOT encrypted - contains sensitive IOC data"
fi
echo "Finished at $(date)"
