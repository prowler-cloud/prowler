#!/bin/bash
# Setup AI Skills for Prowler development
# Configures AI coding assistants that follow agentskills.io standard:
#   - Claude Code: .claude/skills/ symlink (auto-discovery)
#   - Gemini CLI: .gemini/skills/ symlink (auto-discovery)
#   - Codex (OpenAI): .codex/skills/ symlink + AGENTS.md
#   - GitHub Copilot: reads AGENTS.md from repo root (no symlink needed)

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
echo -e "${YELLOW}[1/3] Setting up Claude Code...${NC}"

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
echo -e "${YELLOW}[2/3] Setting up Codex (OpenAI)...${NC}"

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
echo -e "${YELLOW}[3/3] Setting up Gemini CLI...${NC}"

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
# SUMMARY
# =============================================================================
echo ""
echo -e "${GREEN}✅ Successfully configured $SKILL_COUNT AI skills!${NC}"
echo ""
echo "Configuration created:"
echo "  • Claude Code:    .claude/skills/ (symlink, auto-discovery)"
echo "  • Codex (OpenAI): .codex/skills/ (symlink, reads AGENTS.md)"
echo "  • Gemini CLI:     .gemini/skills/ (symlink, auto-discovery)"
echo "  • GitHub Copilot: reads AGENTS.md from repo root (no setup needed)"
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
echo -e "${BLUE}      Claude/Gemini auto-discover skills from SKILL.md descriptions.${NC}"
echo -e "${BLUE}      Codex/Copilot use AGENTS.md instructions to reference skills.${NC}"
