#!/bin/bash
# Setup AI Skills for Prowler development
# Configures AI coding assistants that follow agentskills.io standard:
#   - Claude Code: .claude/skills/ symlink + CLAUDE.md copies
#   - Gemini CLI: .gemini/skills/ symlink + GEMINI.md copies
#   - Codex (OpenAI): .codex/skills/ symlink + AGENTS.md (native)
#   - GitHub Copilot: .github/copilot-instructions.md copy
#
# AGENTS.md is the source of truth. This script copies it to:
#   - CLAUDE.md (for Claude Code)
#   - GEMINI.md (for Gemini CLI)
#   - .github/copilot-instructions.md (for GitHub Copilot, root only)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SKILLS_SOURCE="$SCRIPT_DIR"

# Target locations
CLAUDE_SKILLS_TARGET="$REPO_ROOT/.claude/skills"
CODEX_SKILLS_TARGET="$REPO_ROOT/.codex/skills"
GEMINI_SKILLS_TARGET="$REPO_ROOT/.gemini/skills"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🤖 Prowler AI Skills Setup"
echo "=========================="
echo ""

# Count skills (directories with SKILL.md)
SKILL_COUNT=$(find "$SKILLS_SOURCE" -maxdepth 2 -name "SKILL.md" | wc -l | tr -d ' ')

if [ "$SKILL_COUNT" -eq 0 ]; then
    echo -e "${RED}No skills found in $SKILLS_SOURCE${NC}"
    exit 1
fi

echo -e "${BLUE}Found $SKILL_COUNT skills to configure${NC}"
echo ""

# =============================================================================
# CLAUDE CODE SETUP (.claude/skills symlink - auto-discovery)
# =============================================================================
echo -e "${YELLOW}[1/4] Setting up Claude Code...${NC}"

if [ ! -d "$REPO_ROOT/.claude" ]; then
    mkdir -p "$REPO_ROOT/.claude"
fi

if [ -L "$CLAUDE_SKILLS_TARGET" ]; then
    rm "$CLAUDE_SKILLS_TARGET"
elif [ -d "$CLAUDE_SKILLS_TARGET" ]; then
    mv "$CLAUDE_SKILLS_TARGET" "$REPO_ROOT/.claude/skills.backup.$(date +%s)"
fi

ln -s "$SKILLS_SOURCE" "$CLAUDE_SKILLS_TARGET"
echo -e "${GREEN}  ✓ .claude/skills -> skills/${NC}"

# =============================================================================
# CODEX (OPENAI) SETUP (.codex/skills symlink)
# =============================================================================
echo -e "${YELLOW}[2/4] Setting up Codex (OpenAI)...${NC}"

if [ ! -d "$REPO_ROOT/.codex" ]; then
    mkdir -p "$REPO_ROOT/.codex"
fi

if [ -L "$CODEX_SKILLS_TARGET" ]; then
    rm "$CODEX_SKILLS_TARGET"
elif [ -d "$CODEX_SKILLS_TARGET" ]; then
    mv "$CODEX_SKILLS_TARGET" "$REPO_ROOT/.codex/skills.backup.$(date +%s)"
fi

ln -s "$SKILLS_SOURCE" "$CODEX_SKILLS_TARGET"
echo -e "${GREEN}  ✓ .codex/skills -> skills/${NC}"

# =============================================================================
# GEMINI CLI SETUP (.gemini/skills symlink - auto-discovery)
# =============================================================================
echo -e "${YELLOW}[3/4] Setting up Gemini CLI...${NC}"

if [ ! -d "$REPO_ROOT/.gemini" ]; then
    mkdir -p "$REPO_ROOT/.gemini"
fi

if [ -L "$GEMINI_SKILLS_TARGET" ]; then
    rm "$GEMINI_SKILLS_TARGET"
elif [ -d "$GEMINI_SKILLS_TARGET" ]; then
    mv "$GEMINI_SKILLS_TARGET" "$REPO_ROOT/.gemini/skills.backup.$(date +%s)"
fi

ln -s "$SKILLS_SOURCE" "$GEMINI_SKILLS_TARGET"
echo -e "${GREEN}  ✓ .gemini/skills -> skills/${NC}"

# =============================================================================
# COPY AGENTS.md TO AI-SPECIFIC FORMATS
# =============================================================================
echo -e "${YELLOW}[4/4] Copying AGENTS.md to AI-specific formats...${NC}"

# Find all AGENTS.md files in the repository
AGENTS_FILES=$(find "$REPO_ROOT" -name "AGENTS.md" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
AGENTS_COUNT=0

for AGENTS_FILE in $AGENTS_FILES; do
    AGENTS_DIR=$(dirname "$AGENTS_FILE")

    # Copy to CLAUDE.md (same directory)
    cp "$AGENTS_FILE" "$AGENTS_DIR/CLAUDE.md"

    # Copy to GEMINI.md (same directory)
    cp "$AGENTS_FILE" "$AGENTS_DIR/GEMINI.md"

    # Get relative path for display
    REL_PATH="${AGENTS_DIR#"$REPO_ROOT"/}"
    if [ "$AGENTS_DIR" = "$REPO_ROOT" ]; then
        REL_PATH="(root)"
    fi

    echo -e "${GREEN}  ✓ $REL_PATH/AGENTS.md -> CLAUDE.md, GEMINI.md${NC}"
    AGENTS_COUNT=$((AGENTS_COUNT + 1))
done

# Copy root AGENTS.md to .github/copilot-instructions.md (GitHub Copilot)
if [ -f "$REPO_ROOT/AGENTS.md" ]; then
    mkdir -p "$REPO_ROOT/.github"
    cp "$REPO_ROOT/AGENTS.md" "$REPO_ROOT/.github/copilot-instructions.md"
    echo -e "${GREEN}  ✓ AGENTS.md -> .github/copilot-instructions.md (Copilot)${NC}"
fi

echo -e "${BLUE}  Copied $AGENTS_COUNT AGENTS.md file(s)${NC}"

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${GREEN}✅ Successfully configured $SKILL_COUNT AI skills!${NC}"
echo ""
echo "Configuration created:"
echo "  • Claude Code:    .claude/skills/ + CLAUDE.md copies"
echo "  • Codex (OpenAI): .codex/skills/ + AGENTS.md (native)"
echo "  • Gemini CLI:     .gemini/skills/ + GEMINI.md copies"
echo "  • GitHub Copilot: .github/copilot-instructions.md"
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
echo -e "${BLUE}Note: Restart your AI coding assistant to load the skills.${NC}"
echo -e "${BLUE}      AGENTS.md is the source of truth - edit it, then re-run this script.${NC}"
