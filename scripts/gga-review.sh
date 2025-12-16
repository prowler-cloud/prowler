#!/bin/bash
# Gentleman Guardian Angel (gga) - AI Code Review Hook
# This script is called by pre-commit after all formatters/linters have run

set -e

# Colors
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if AI code review is enabled
if [ "${CODE_REVIEW_ENABLED:-false}" != "true" ]; then
    echo -e "${YELLOW}⏭️  AI code review disabled (CODE_REVIEW_ENABLED!=true)${NC}"
    exit 0
fi

# Install gga if not present
if ! command -v gga &> /dev/null; then
    echo -e "${BLUE}📦 Installing Gentleman Guardian Angel (gga)...${NC}"
    if command -v brew &> /dev/null; then
        brew install gentleman-programming/tap/gga
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
