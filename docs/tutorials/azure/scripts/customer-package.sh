#!/bin/bash

# Customer Package Preparation Script
# This script creates a clean package for customers with only the necessary files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$SCRIPT_DIR/prowler-azure-setup"

echo "Creating customer package..."

# Create package directory
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy essential scripts
cp "$SCRIPT_DIR/all-in-one-single-sub.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/all-in-one-multi-sub.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/single-subscription-setup.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/multi-subscription-setup.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/setup-prowler.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/cleanup-prowler.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/troubleshoot-azure-auth.sh" "$PACKAGE_DIR/"

# Copy customer documentation
cp "$SCRIPT_DIR/CUSTOMER-README.md" "$PACKAGE_DIR/README.md"

# Create customer-specific instruction files
cat > "$PACKAGE_DIR/QUICK-START.md" << 'EOF'
# Quick Start Guide

## For Single Subscription Setup:
```bash
bash all-in-one-single-sub.sh
```

## For Multiple Subscriptions Setup:
```bash
bash all-in-one-multi-sub.sh
```

## Need Help?
```bash
bash troubleshoot-azure-auth.sh
```

## Important Files:
- `README.md` - Complete instructions
- `prowler-config.env` - Generated credentials (DO NOT SHARE)
- `cleanup-prowler.sh` - Remove all created resources

**⚠️ Security Warning:** Never share your Client Secret or prowler-config.env file!
EOF

# Create credentials collection template
cat > "$PACKAGE_DIR/CREDENTIALS-TEMPLATE.md" << 'EOF'
# Prowler Azure Credentials

Please provide the following information after running the setup script:

## ✅ Safe to Share:
- **Client ID (Application ID):** `_____________________`
- **Tenant ID:** `_____________________`
- **Subscription IDs configured:** `_____________________`

## ⚠️ DO NOT INCLUDE:
- Client Secret (keep this secure on your side)
- prowler-config.env file contents
- Any screenshots of credential output

## Setup Confirmation:
- [ ] Script completed successfully
- [ ] No error messages during setup
- [ ] prowler-config.env file was created
- [ ] All target subscriptions were configured

## Next Steps:
Your system administrator will use these credentials to configure Prowler scanning for your Azure environment.
EOF

# Make scripts executable
chmod +x "$PACKAGE_DIR"/*.sh

# Create package info
cat > "$PACKAGE_DIR/PACKAGE-INFO.txt" << EOF
Prowler Azure Setup Package
Generated: $(date)
Version: 1.0

Contents:
- all-in-one-single-sub.sh    : Complete setup for single subscription
- all-in-one-multi-sub.sh     : Complete setup for multiple subscriptions  
- single-subscription-setup.sh: Core single subscription setup
- multi-subscription-setup.sh : Core multi-subscription setup
- setup-prowler.sh            : General setup functions
- cleanup-prowler.sh          : Remove all created resources
- troubleshoot-azure-auth.sh  : Diagnostic and troubleshooting
- README.md                   : Complete instructions
- QUICK-START.md              : Quick reference
- CREDENTIALS-TEMPLATE.md     : Template for providing credentials back

Start with: README.md
EOF

echo "✅ Customer package created at: $PACKAGE_DIR"
echo ""
echo "Package contents:"
ls -la "$PACKAGE_DIR"
echo ""
echo "To create a zip file for distribution:"
echo "cd '$SCRIPT_DIR' && zip -r prowler-azure-setup.zip prowler-azure-setup/"