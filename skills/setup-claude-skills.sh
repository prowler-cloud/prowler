#!/bin/bash
# Setup Claude Code skills for Prowler development
# This script creates a symlink from skills/claude to .claude/skills

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CLAUDE_SKILLS_SOURCE="$SCRIPT_DIR/claude"
CLAUDE_SKILLS_TARGET="$REPO_ROOT/.claude/skills"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🤖 Prowler Claude Code Skills Setup"
echo "===================================="
echo ""

# Check if source directory exists
if [ ! -d "$CLAUDE_SKILLS_SOURCE" ]; then
    echo -e "${RED}Error: Claude skills directory not found at $CLAUDE_SKILLS_SOURCE${NC}"
    exit 1
fi

# Count skills
SKILL_COUNT=$(find "$CLAUDE_SKILLS_SOURCE" -maxdepth 1 -type d | wc -l | tr -d ' ')
SKILL_COUNT=$((SKILL_COUNT - 1))  # Subtract 1 for the directory itself

if [ "$SKILL_COUNT" -eq 0 ]; then
    echo -e "${RED}No skills found in $CLAUDE_SKILLS_SOURCE${NC}"
    exit 1
fi

# Create .claude directory if it doesn't exist
if [ ! -d "$REPO_ROOT/.claude" ]; then
    echo -e "${YELLOW}Creating .claude directory${NC}"
    mkdir -p "$REPO_ROOT/.claude"
fi

# Handle existing skills directory/symlink
if [ -L "$CLAUDE_SKILLS_TARGET" ]; then
    echo -e "${YELLOW}Removing existing symlink${NC}"
    rm "$CLAUDE_SKILLS_TARGET"
elif [ -d "$CLAUDE_SKILLS_TARGET" ]; then
    echo -e "${YELLOW}Backing up existing skills directory to .claude/skills.backup${NC}"
    mv "$CLAUDE_SKILLS_TARGET" "$REPO_ROOT/.claude/skills.backup.$(date +%s)"
fi

# Create symlink
ln -s "$CLAUDE_SKILLS_SOURCE" "$CLAUDE_SKILLS_TARGET"

echo -e "${GREEN}✅ Successfully linked $SKILL_COUNT Claude Code skills!${NC}"
echo ""
echo "Symlink created:"
echo "  $CLAUDE_SKILLS_TARGET -> $CLAUDE_SKILLS_SOURCE"
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
echo "Skills are now available in Claude Code via the /skill command."
