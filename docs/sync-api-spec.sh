#!/bin/bash

# Sync API OpenAPI Specification to Documentation
# This script copies the OpenAPI spec from the API source to the docs folder

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
API_SPEC_SOURCE="$PROJECT_ROOT/api/src/backend/api/specs/v1.yaml"
API_SPEC_DEST="$SCRIPT_DIR/api-reference/openapi.yaml"

echo "🔄 Syncing API specification to documentation..."

# Check if source file exists
if [ ! -f "$API_SPEC_SOURCE" ]; then
    echo -e "${RED}❌ Error: Source API spec not found at $API_SPEC_SOURCE${NC}"
    exit 1
fi

# Check if destination directory exists
if [ ! -d "$(dirname "$API_SPEC_DEST")" ]; then
    echo -e "${YELLOW}⚠️  Creating destination directory...${NC}"
    mkdir -p "$(dirname "$API_SPEC_DEST")"
fi

# Check if files are different
if [ -f "$API_SPEC_DEST" ]; then
    if cmp -s "$API_SPEC_SOURCE" "$API_SPEC_DEST"; then
        echo -e "${GREEN}✅ API spec is already up to date!${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️  API spec has changes, updating...${NC}"
    fi
fi

# Copy the file
if cp "$API_SPEC_SOURCE" "$API_SPEC_DEST"; then
    echo -e "${GREEN}✅ API specification synced successfully!${NC}"
    echo "   Source: $API_SPEC_SOURCE"
    echo "   Destination: $API_SPEC_DEST"

    # Extract version from the spec
    VERSION=$(grep -m 1 "version:" "$API_SPEC_DEST" | sed 's/.*version: //')
    echo -e "${GREEN}   Version: $VERSION${NC}"
else
    echo -e "${RED}❌ Error: Failed to sync API specification${NC}"
    exit 1
fi

echo ""
echo "💡 Next steps:"
echo "   1. Review the changes: git diff docs/api-reference/openapi.yaml"
echo "   2. Test locally: cd docs && mintlify dev"
echo "   3. Commit the changes if everything looks good"
