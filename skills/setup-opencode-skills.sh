#!/bin/bash
# Setup OpenCode skills for Prowler development
# This script copies the custom OpenCode tools to your global config

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCODE_TOOLS_DIR="$SCRIPT_DIR/opencode"
TARGET_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode/tool"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔧 Prowler OpenCode Skills Setup"
echo "================================="
echo ""

# Check if source directory exists
if [ ! -d "$OPENCODE_TOOLS_DIR" ]; then
    echo -e "${RED}Error: OpenCode tools directory not found at $OPENCODE_TOOLS_DIR${NC}"
    exit 1
fi

# Create target directory if it doesn't exist
if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${YELLOW}Creating OpenCode tools directory: $TARGET_DIR${NC}"
    mkdir -p "$TARGET_DIR"
fi

# Count tools
TOOL_COUNT=$(find "$OPENCODE_TOOLS_DIR" -maxdepth 1 -name "*.ts" 2>/dev/null | wc -l | tr -d ' ')

if [ "$TOOL_COUNT" -eq 0 ]; then
    echo -e "${RED}No .ts files found in $OPENCODE_TOOLS_DIR${NC}"
    exit 1
fi

echo "Found $TOOL_COUNT skills to install:"
echo ""

# Copy each tool
for tool_file in "$OPENCODE_TOOLS_DIR"/*.ts; do
    tool_name=$(basename "$tool_file")

    if [ -f "$TARGET_DIR/$tool_name" ]; then
        echo -e "  ${YELLOW}↻${NC} Updating: $tool_name"
    else
        echo -e "  ${GREEN}+${NC} Installing: $tool_name"
    fi

    cp "$tool_file" "$TARGET_DIR/$tool_name"
done

echo ""
echo -e "${GREEN}✅ Successfully installed $TOOL_COUNT OpenCode skills!${NC}"
echo ""
echo "Skills installed to: $TARGET_DIR"
echo ""
echo "Available skills:"
echo "  Generic:  typescript, react-19, nextjs-15, playwright, pytest,"
echo "            django-drf, zod-4, zustand-5, tailwind-4, ai-sdk-5"
echo ""
echo "  Prowler:  prowler, prowler-api, prowler-ui, prowler-mcp,"
echo "            prowler-sdk-check, prowler-test-ui, prowler-test-api,"
echo "            prowler-test-sdk, prowler-compliance, prowler-docs,"
echo "            prowler-provider, prowler-pr"
echo ""
echo "Restart OpenCode to use the new skills."
