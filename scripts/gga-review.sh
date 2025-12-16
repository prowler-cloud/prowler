#!/bin/bash
# Gentleman Guardian Angel (gga) - AI Code Review Hook
# This script is called by pre-commit after all formatters/linters have run
#
# Only reviews files in directories that have an AGENTS.md file.
# This allows teams to opt-in to AI code review by adding AGENTS.md to their component.

set -e

# Colors
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

# Check if AI code review is enabled
if [ "${CODE_REVIEW_ENABLED:-false}" != "true" ]; then
    echo -e "${YELLOW}⏭️  AI code review disabled (CODE_REVIEW_ENABLED!=true)${NC}"
    exit 0
fi

# Check if AGENTS-CODE-REVIEW.md exists
if [ ! -f "AGENTS-CODE-REVIEW.md" ]; then
    echo -e "${YELLOW}⏭️  AI code review skipped (AGENTS-CODE-REVIEW.md not found)${NC}"
    exit 0
fi

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(ts|tsx|js|jsx|py)$' || true)

if [ -z "$STAGED_FILES" ]; then
    echo -e "${YELLOW}⏭️  No matching files staged for AI review${NC}"
    exit 0
fi

# Filter out files from directories without AGENTS.md (opt-in model)
FILES_TO_REVIEW=""
SKIPPED_DIRS=""

for file in $STAGED_FILES; do
    # Get the top-level directory of the file
    TOP_DIR=$(echo "$file" | cut -d'/' -f1)

    # Check if this directory has an AGENTS.md file
    if [ -f "${TOP_DIR}/AGENTS.md" ]; then
        FILES_TO_REVIEW="$FILES_TO_REVIEW $file"
    else
        # Track skipped directories (only unique)
        if [[ ! "$SKIPPED_DIRS" =~ $TOP_DIR ]]; then
            SKIPPED_DIRS="$SKIPPED_DIRS $TOP_DIR"
        fi
    fi
done

# Report skipped directories
if [ -n "$SKIPPED_DIRS" ]; then
    echo -e "${YELLOW}ℹ️  Skipping directories without AGENTS.md:${SKIPPED_DIRS}${NC}"
fi

# Check if there are files to review after filtering
if [ -z "$(echo "$FILES_TO_REVIEW" | tr -d ' ')" ]; then
    echo -e "${GREEN}✅ No files to review (all staged files are in directories without AGENTS.md)${NC}"
    exit 0
fi

# Install gga if not present
if ! command -v gga &> /dev/null; then
    echo -e "${BLUE}📦 Installing Gentleman Guardian Angel (gga)...${NC}"
    if command -v brew &> /dev/null; then
        brew tap gentleman-programming/tap 2>/dev/null || true
        brew install gga
    else
        # Fallback: install from source for Linux/CI environments
        GGA_TMP_DIR=$(mktemp -d)
        git clone --depth 1 https://github.com/Gentleman-Programming/gentleman-guardian-angel.git "$GGA_TMP_DIR"
        chmod +x "$GGA_TMP_DIR/install.sh"
        "$GGA_TMP_DIR/install.sh"
        rm -rf "$GGA_TMP_DIR"
    fi
fi

# Verify gga is available
if ! command -v gga &> /dev/null; then
    echo "❌ Failed to install gga"
    echo "Please install manually: https://github.com/Gentleman-Programming/gentleman-guardian-angel"
    exit 1
fi

# Run gga code review
exec gga run
