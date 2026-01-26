#!/bin/bash

# Setup Git Hooks for Prowler
# This script installs git hooks using prek (fast pre-commit alternative)

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔧 Setting up Prowler Git Hooks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo -e "${RED}❌ Not in a git repository${NC}"
  exit 1
fi

# Check if pyproject.toml exists
if [ ! -f "pyproject.toml" ]; then
  echo -e "${RED}❌ pyproject.toml not found${NC}"
  echo -e "${YELLOW}   Please run this script from the repository root${NC}"
  exit 1
fi

# Check if prek is installed, if not try to install it
if ! command -v prek &>/dev/null; then
  echo -e "${YELLOW}📦 prek not found, attempting to install...${NC}"
  if command -v pipx &>/dev/null; then
    pipx install prek
  elif command -v uv &>/dev/null; then
    uv tool install prek
  elif command -v brew &>/dev/null; then
    brew install prek
  else
    echo -e "${RED}❌ Could not install prek automatically${NC}"
    echo -e "${YELLOW}   Install prek manually: https://github.com/j178/prek${NC}"
    echo -e "${YELLOW}   Options: pipx install prek | brew install prek | uv tool install prek${NC}"
    exit 1
  fi
fi

echo -e "${GREEN}✓${NC} prek is installed: $(prek --version)"

echo ""
# Clear any existing core.hooksPath to avoid conflicts
if git config --get core.hooksPath >/dev/null 2>&1; then
  echo -e "${YELLOW}🧹 Clearing existing core.hooksPath configuration...${NC}"
  git config --unset-all core.hooksPath
fi

# Uninstall old pre-commit hooks if they exist
if [ -f ".git/hooks/pre-commit" ] && grep -q "pre-commit" ".git/hooks/pre-commit" 2>/dev/null; then
  echo -e "${YELLOW}🧹 Removing old pre-commit hooks...${NC}"
  pre-commit uninstall 2>/dev/null || true
fi

echo -e "${YELLOW}🔗 Installing prek hooks...${NC}"
prek install

echo ""
echo -e "${GREEN}✅ Git hooks successfully configured!${NC}"
echo ""
echo -e "${YELLOW}📋 prek system (fast pre-commit alternative):${NC}"
echo -e "   • prek manages all git hooks (~7x faster than pre-commit)"
echo -e "   • API files: Python checks (black, flake8, bandit, etc.)"
echo -e "   • UI files: UI checks (TypeScript, ESLint, Claude Code validation)"
echo -e "   • Run manually: prek run --all-files"
echo ""
echo -e "${GREEN}🎉 Setup complete!${NC}"
echo ""
