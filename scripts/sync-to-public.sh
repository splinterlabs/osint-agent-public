#!/usr/bin/env bash
set -euo pipefail

# Sync private repo to public repo
# Usage: ./scripts/sync-to-public.sh [--dry-run]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PUBLIC_REPO_URL="${PUBLIC_REPO_URL:-}"
PUBLIC_BRANCH="${PUBLIC_BRANCH:-main}"
SYNC_BRANCH="sync/latest"
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
echo "Target branch: $PUBLIC_BRANCH"
echo "Sync branch: $SYNC_BRANCH"
echo "Dry run: $DRY_RUN"
echo ""

# Run pre-publish validation
echo -e "${BLUE}Running pre-publish validation...${NC}"
if [[ -f "$PROJECT_ROOT/scripts/validate-public-sync.sh" ]]; then
    if ! "$PROJECT_ROOT/scripts/validate-public-sync.sh"; then
        echo -e "${RED}Validation failed! Cannot sync to public repository.${NC}"
        echo -e "${RED}Fix the violations above before syncing.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Validation passed${NC}"
    echo ""
else
    echo -e "${YELLOW}⚠️  Warning: validate-public-sync.sh not found, skipping validation${NC}"
    echo ""
fi

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

# Configure git for this operation
git config user.email "sync@localhost"
git config user.name "Sync Script"

# Try to fetch existing public repo
echo -e "${YELLOW}Fetching public repo...${NC}"
if git fetch public "$PUBLIC_BRANCH" 2>/dev/null; then
    echo "Public branch exists, will update..."

    # Create initial commit with staged files
    git add -A
    git commit -m "Staged files" --allow-empty -q

    # Now reset to match public branch history
    git fetch public "$PUBLIC_BRANCH"
    git reset --soft "public/$PUBLIC_BRANCH"

    # Re-add all files (this stages only the differences)
    git add -A
else
    echo "Public branch doesn't exist yet, creating..."
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
read -p "Push these changes and create PR? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

# Get commit message from private repo
LATEST_COMMIT=$(cd "$PROJECT_ROOT" && git log -1 --pretty=format:"%s")
COMMIT_MSG="Sync: $LATEST_COMMIT"

echo ""
echo -e "${YELLOW}Committing and pushing to sync branch...${NC}"
git commit -m "$COMMIT_MSG"
git push -f public "HEAD:$SYNC_BRANCH"

echo ""
echo -e "${YELLOW}Creating pull request...${NC}"

# Extract owner/repo from URL for gh CLI
# Handles both https://github.com/owner/repo.git and git@github.com:owner/repo.git
REPO_SLUG=$(echo "$PUBLIC_REPO_URL" | sed -E 's|.*github\.com[:/]||; s|\.git$||')

# Check if PR already exists
EXISTING_PR=$(gh pr list --repo "$REPO_SLUG" --head "$SYNC_BRANCH" --base "$PUBLIC_BRANCH" --json number --jq '.[0].number' 2>/dev/null || echo "")

if [[ -n "$EXISTING_PR" ]]; then
    echo -e "${GREEN}Updated existing PR #${EXISTING_PR}${NC}"
    echo "View at: https://github.com/$REPO_SLUG/pull/$EXISTING_PR"
else
    # Create new PR
    PR_URL=$(gh pr create \
        --repo "$REPO_SLUG" \
        --head "$SYNC_BRANCH" \
        --base "$PUBLIC_BRANCH" \
        --title "$COMMIT_MSG" \
        --body "Automated sync from private repository.

**Latest commit:** $LATEST_COMMIT

---
*This PR was created by the sync script.*")

    echo -e "${GREEN}Created PR: $PR_URL${NC}"
fi

echo ""
echo -e "${GREEN}Successfully synced to public repo!${NC}"
