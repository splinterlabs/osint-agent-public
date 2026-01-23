#!/usr/bin/env bash
set -euo pipefail

# Sync private repo to public repo
# Usage: ./scripts/sync-to-public.sh [--dry-run]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PUBLIC_REPO_URL="${PUBLIC_REPO_URL:-}"
PUBLIC_BRANCH="${PUBLIC_BRANCH:-main}"
DRY_RUN=false

# Files/directories to exclude from public repo
EXCLUDE_PATTERNS=(
    ".private/"
    ".private/**"
    "*.private.*"
    "scripts/sync-to-public.sh"
    ".sync-config"
    "INTERNAL_*.md"
    "OSINT_AGENT_PROPOSAL.md"
    "data/campaigns/*.json"
    "data/context/*.json"
    "uv.lock"
    "mcp-server/uv.lock"
)

# Parse arguments
for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            ;;
        --repo=*)
            PUBLIC_REPO_URL="${arg#*=}"
            ;;
    esac
done

echo -e "${GREEN}=== Sync to Public Repository ===${NC}"
echo ""

# Check for config file
if [[ -f "$PROJECT_ROOT/.sync-config" ]]; then
    source "$PROJECT_ROOT/.sync-config"
fi

if [[ -z "$PUBLIC_REPO_URL" ]]; then
    echo -e "${RED}Error: PUBLIC_REPO_URL not set${NC}"
    echo "Set it via:"
    echo "  1. Environment variable: export PUBLIC_REPO_URL=https://github.com/user/repo.git"
    echo "  2. Config file: echo 'PUBLIC_REPO_URL=...' > .sync-config"
    echo "  3. Command line: ./sync-to-public.sh --repo=https://github.com/user/repo.git"
    exit 1
fi

echo "Source: $PROJECT_ROOT"
echo "Target: $PUBLIC_REPO_URL"
echo "Branch: $PUBLIC_BRANCH"
echo "Dry run: $DRY_RUN"
echo ""

# Create temporary directory for staging
STAGING_DIR=$(mktemp -d)
trap "rm -rf $STAGING_DIR" EXIT

echo -e "${YELLOW}Creating staging copy...${NC}"

# Build rsync exclude arguments
EXCLUDE_ARGS=()
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    EXCLUDE_ARGS+=(--exclude="$pattern")
done

# Also exclude git directory and common ignores
EXCLUDE_ARGS+=(
    --exclude=".git"
    --exclude="__pycache__"
    --exclude="*.pyc"
    --exclude=".pytest_cache"
    --exclude=".mypy_cache"
    --exclude=".ruff_cache"
    --exclude="*.egg-info"
    --exclude=".venv"
    --exclude="venv"
    --exclude=".env"
    --exclude=".env.local"
    --exclude="data/iocs.db"
    --exclude="data/rate_limits.db"
    --exclude="data/cache/"
    --exclude="data/logs/*.jsonl"
    --exclude=".claude/data/cache/"
    --exclude=".claude/data/logs/*.jsonl"
    --exclude="backups/"
    --exclude="mcp-server/.venv"
)

# Copy files to staging
rsync -av "${EXCLUDE_ARGS[@]}" "$PROJECT_ROOT/" "$STAGING_DIR/"

echo ""
echo -e "${YELLOW}Files to sync:${NC}"
find "$STAGING_DIR" -type f | sed "s|$STAGING_DIR/||" | head -50
FILE_COUNT=$(find "$STAGING_DIR" -type f | wc -l | tr -d ' ')
echo "... ($FILE_COUNT files total)"
echo ""

# Show what's being excluded
echo -e "${YELLOW}Excluded patterns:${NC}"
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    echo "  - $pattern"
done
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}Dry run - no changes made${NC}"
    echo ""
    echo "To sync for real, run without --dry-run"
    exit 0
fi

# Initialize git in staging directory
cd "$STAGING_DIR"
git init -q
git remote add public "$PUBLIC_REPO_URL"

# Try to fetch existing public repo
echo -e "${YELLOW}Fetching public repo...${NC}"
if git fetch public "$PUBLIC_BRANCH" 2>/dev/null; then
    git checkout -b sync-branch "public/$PUBLIC_BRANCH"

    # Remove all tracked files and re-add from staging
    git rm -rf . --quiet 2>/dev/null || true

    # Copy staged files back
    rsync -av "${EXCLUDE_ARGS[@]}" "$PROJECT_ROOT/" "$STAGING_DIR/" --delete

    git add -A
else
    echo "Public branch doesn't exist yet, creating..."
    git checkout -b "$PUBLIC_BRANCH"
    git add -A
fi

# Check if there are changes
if git diff --cached --quiet; then
    echo -e "${GREEN}No changes to sync${NC}"
    exit 0
fi

# Show diff summary
echo ""
echo -e "${YELLOW}Changes to push:${NC}"
git diff --cached --stat | tail -20
echo ""

# Confirm push
read -p "Push these changes to public repo? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

# Get commit message
LATEST_COMMIT=$(cd "$PROJECT_ROOT" && git log -1 --pretty=format:"%s")
COMMIT_MSG="Sync: $LATEST_COMMIT"

echo ""
echo -e "${YELLOW}Committing and pushing...${NC}"
git commit -m "$COMMIT_MSG"
git push public "HEAD:$PUBLIC_BRANCH"

echo ""
echo -e "${GREEN}Successfully synced to public repo!${NC}"
