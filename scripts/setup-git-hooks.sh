#!/bin/bash

# Setup Git Hooks for Prowler
# This script installs pre-commit hooks using the project's Poetry environment

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

# Check if Poetry is installed
if ! command -v poetry &>/dev/null; then
  echo -e "${RED}❌ Poetry is not installed${NC}"
  echo -e "${YELLOW}   Install Poetry: https://python-poetry.org/docs/#installation${NC}"
  exit 1
fi

# Check if pyproject.toml exists
if [ ! -f "pyproject.toml" ]; then
  echo -e "${RED}❌ pyproject.toml not found${NC}"
  echo -e "${YELLOW}   Please run this script from the repository root${NC}"
  exit 1
fi

# Check if dependencies are already installed
if ! poetry run python -c "import pre_commit" 2>/dev/null; then
  echo -e "${YELLOW}📦 Installing project dependencies (including pre-commit)...${NC}"
  poetry install --with dev
else
  echo -e "${GREEN}✓${NC} Dependencies already installed"
fi

echo ""
# Clear any existing core.hooksPath to avoid pre-commit conflicts
if git config --get core.hooksPath >/dev/null 2>&1; then
  echo -e "${YELLOW}🧹 Clearing existing core.hooksPath configuration...${NC}"
  git config --unset-all core.hooksPath
fi

echo -e "${YELLOW}🔗 Installing pre-commit hooks...${NC}"
poetry run pre-commit install

echo ""
echo -e "${GREEN}✅ Git hooks successfully configured!${NC}"
echo ""
echo -e "${YELLOW}📋 Pre-commit system:${NC}"
echo -e "   • Python pre-commit manages all git hooks"
echo -e "   • API files: Python checks (black, flake8, bandit, etc.)"
echo -e "   • UI files: UI checks (TypeScript, ESLint, Claude Code validation)"
echo ""
echo -e "${GREEN}🎉 Setup complete!${NC}"
echo ""
