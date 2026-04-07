#!/bin/bash

# Setup Git Hooks for Prowler
# This script installs prek hooks using the project's Poetry environment
# or a system-wide prek installation

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

# Clear any existing core.hooksPath to avoid conflicts
if git config --get core.hooksPath >/dev/null 2>&1; then
  echo -e "${YELLOW}🧹 Clearing existing core.hooksPath configuration...${NC}"
  git config --unset-all core.hooksPath
fi

echo ""

# Try to find prek: system-wide first, then Poetry
if command -v prek &>/dev/null; then
  echo -e "${GREEN}✓${NC} prek found in PATH"
  echo -e "${YELLOW}🔗 Installing prek hooks...${NC}"
  prek install --overwrite
elif command -v poetry &>/dev/null && [ -f "pyproject.toml" ]; then
  if poetry run prek --version &>/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} prek found via Poetry"
  else
    echo -e "${YELLOW}📦 Installing project dependencies (including prek)...${NC}"
    poetry install --with dev
  fi
  echo -e "${YELLOW}🔗 Installing prek hooks...${NC}"
  poetry run prek install --overwrite
else
  echo -e "${RED}❌ prek is not installed${NC}"
  echo -e "${YELLOW}   Install prek using one of these methods:${NC}"
  echo -e "   • brew install prek"
  echo -e "   • pnpm add -g @j178/prek"
  echo -e "   • pip install prek"
  echo -e "   • See https://prek.j178.dev/installation/ for more options"
  exit 1
fi

echo ""
echo -e "${GREEN}✅ Git hooks successfully configured!${NC}"
echo ""
echo -e "${YELLOW}📋 Prek hook system:${NC}"
echo -e "   • Prek manages all git hooks"
echo -e "   • API files: Python checks (black, flake8, bandit, etc.)"
echo -e "   • UI files: UI checks (TypeScript, ESLint, Claude Code validation)"
echo ""
echo -e "${GREEN}🎉 Setup complete!${NC}"
echo ""
