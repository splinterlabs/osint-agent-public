#!/usr/bin/env bash
# Pre-publish validation script
# Prevents data leaks before syncing to public repository
# Exit code 0 = safe to publish, non-zero = violations found

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VIOLATIONS=0
WARNINGS=0

echo -e "${BLUE}=== Pre-Publish Data Leak Validation ===${NC}"
echo ""

# Define patterns that should NEVER appear in public repo
FORBIDDEN_PATTERNS=(
    # Personal identifiers
    "splinter@ntry"
    "github@ntry"
    "Sander Spierenburg"
    "/Users/user"

    # Internal domains
    "\.ntry\.(net|home|local)"
    "infinity\.ntry"
    "mcp-maigret\.infinity"

    # Internal infrastructure (specific to user's setup)
    # Note: Generic product names are OK in docs, but specific hostnames are not
    "unifi\.ntry"
    "portainer\.ntry"
    "traefik\.ntry"

    # Secret/credential patterns (just in case)
    "SECRET_INTERNAL_KEY.*=.*['\"](?!this-should|example|placeholder)"
    "API_KEY.*=.*['\"][^'\"]{20,}"
)

# Files that should be in .gitignore but might be tracked
SHOULD_BE_IGNORED=(
    "config/watchlist.json"
    ".mcp.json"
    ".private/"
    "*.private.*"
    "INTERNAL_*.md"
    "data/campaigns/*.json"
    "data/context/*.json"
    ".sync-config"
    "Makefile"  # User-specific, use Makefile.example
)

# Patterns that are OK in certain contexts (exclude from checks)
ALLOWLIST_PATTERNS=(
    # The validation script itself contains patterns to search for
    "scripts/validate-public-sync\.sh:.*"

    # Documentation examples are OK
    "docs/.*:.*example\.com"
    "docs/.*:.*192\.168\.1\.1"  # Example IP in docs
    "README\.md:.*github\.com/splinterlabs"  # Project URL
    "SECURITY\.md:.*Private IP ranges.*192\.168"  # Security docs

    # Test files are OK
    "test_.*\.py:.*"
    ".*_test\.py:.*"

    # Example/template files are OK
    ".*\.example\..*:.*"
    "config/templates/.*:.*"

    # Scratchpad/temp files
    ".*/scratchpad/.*:.*"
)

function check_forbidden_patterns() {
    echo -e "${BLUE}[1/5] Checking for forbidden patterns in tracked files...${NC}"

    local found=0

    for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
        # Search all tracked files
        local matches=$(git ls-files -z | xargs -0 grep -inE "$pattern" 2>/dev/null | grep -vE "$(IFS='|'; echo "${ALLOWLIST_PATTERNS[*]}")" || true)

        if [[ -n "$matches" ]]; then
            echo -e "${RED}❌ Found forbidden pattern: $pattern${NC}"
            echo "$matches" | head -5
            if [[ $(echo "$matches" | wc -l) -gt 5 ]]; then
                echo "   ... and $(($(echo "$matches" | wc -l) - 5)) more matches"
            fi
            echo ""
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo -e "${GREEN}✓ No forbidden patterns found${NC}"
    else
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
    echo ""
}

function check_ignored_files() {
    echo -e "${BLUE}[2/5] Checking for files that should be .gitignored...${NC}"

    local found=0

    for pattern in "${SHOULD_BE_IGNORED[@]}"; do
        # Check if pattern matches any tracked files
        local tracked=$(git ls-files "$pattern" 2>/dev/null || true)

        if [[ -n "$tracked" ]]; then
            echo -e "${RED}❌ Tracked file should be in .gitignore: $pattern${NC}"
            echo "$tracked"
            echo ""
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo -e "${GREEN}✓ No improperly tracked files${NC}"
    else
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
    echo ""
}

function check_private_ips() {
    echo -e "${BLUE}[3/5] Checking for private IP addresses (excluding examples)...${NC}"

    # Find private IPs but exclude:
    # - Test IP ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
    # - Version numbers (10.0, 10.15, etc in version strings)
    # - CVSS scores (10.0)
    # - Documentation examples

    local matches=$(git ls-files -z | \
        xargs -0 grep -nE '\b(192\.168\.|10\.[0-9]{1,3}\.[0-9]{1,3}\.|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.)' 2>/dev/null | \
        grep -vE 'test_|example|docs/|README|SECURITY|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|Windows NT 10\.|macOS.*10\.|cvss.*10\.0|version.*10\.' || true)

    if [[ -n "$matches" ]]; then
        echo -e "${YELLOW}⚠️  Found potential private IP addresses:${NC}"
        echo "$matches" | head -5
        if [[ $(echo "$matches" | wc -l) -gt 5 ]]; then
            echo "   ... and $(($(echo "$matches" | wc -l) - 5)) more matches"
        fi
        echo -e "${YELLOW}   Review these manually - may be false positives${NC}"
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "${GREEN}✓ No private IPs found (excluding examples)${NC}"
    fi
    echo ""
}

function check_example_files_exist() {
    echo -e "${BLUE}[4/5] Checking for required .example files...${NC}"

    local missing=0

    # Check that example files exist for user-specific configs
    if [[ ! -f ".mcp.json.example" ]]; then
        echo -e "${RED}❌ Missing .mcp.json.example${NC}"
        missing=1
    fi

    if [[ ! -f "config/watchlist.example.json" ]]; then
        echo -e "${RED}❌ Missing config/watchlist.example.json${NC}"
        missing=1
    fi

    if [[ ! -f "Makefile.example" ]]; then
        echo -e "${YELLOW}⚠️  Missing Makefile.example (optional)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    if [[ $missing -eq 0 ]]; then
        echo -e "${GREEN}✓ All required example files present${NC}"
    else
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
    echo ""
}

function check_gitignore_patterns() {
    echo -e "${BLUE}[5/5] Verifying .gitignore includes sensitive patterns...${NC}"

    local missing=0

    # Required .gitignore patterns
    REQUIRED_IGNORES=(
        "config/watchlist.json"
        ".mcp.json"
        ".private/"
        ".sync-config"
        "Makefile"
    )

    for pattern in "${REQUIRED_IGNORES[@]}"; do
        if ! grep -qF "$pattern" .gitignore 2>/dev/null; then
            echo -e "${RED}❌ .gitignore missing pattern: $pattern${NC}"
            missing=1
        fi
    done

    if [[ $missing -eq 0 ]]; then
        echo -e "${GREEN}✓ All required .gitignore patterns present${NC}"
    else
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
    echo ""
}

# Run all checks
check_forbidden_patterns
check_ignored_files
check_private_ips
check_example_files_exist
check_gitignore_patterns

# Summary
echo -e "${BLUE}=== Validation Summary ===${NC}"
echo ""

if [[ $VIOLATIONS -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}✅ PASS - No violations found. Safe to publish.${NC}"
    exit 0
elif [[ $VIOLATIONS -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  WARNINGS - $WARNINGS warnings found. Review manually.${NC}"
    echo -e "${YELLOW}   Proceeding with caution...${NC}"
    exit 0
else
    echo -e "${RED}❌ FAIL - $VIOLATIONS violations found${NC}"
    if [[ $WARNINGS -gt 0 ]]; then
        echo -e "${YELLOW}   Plus $WARNINGS warnings${NC}"
    fi
    echo ""
    echo -e "${RED}Cannot sync to public repository until violations are fixed.${NC}"
    echo ""
    echo "Suggested fixes:"
    echo "  1. Add sensitive files to .gitignore"
    echo "  2. Run: git rm --cached <file>  (to untrack but keep local)"
    echo "  3. Create .example versions of config files"
    echo "  4. Remove personal identifiers from tracked files"
    echo ""
    exit 1
fi
