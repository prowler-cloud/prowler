#!/bin/bash

# Creates a clean customer package with only necessary files
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_NAME="prowler-azure-setup"
PACKAGE_DIR="$SCRIPT_DIR/$PACKAGE_NAME"

echo "🚀 Creating customer package..."

# Clean and create package directory
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Copy essential scripts
echo "📋 Copying scripts..."
cp "$SCRIPT_DIR/all-in-one-single-sub.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/all-in-one-multi-sub.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/single-subscription-setup.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/multi-subscription-setup.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/setup-prowler.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/cleanup-prowler.sh" "$PACKAGE_DIR/"
cp "$SCRIPT_DIR/troubleshoot-azure-auth.sh" "$PACKAGE_DIR/"

# Copy documentation
cp "$SCRIPT_DIR/CUSTOMER-SETUP-GUIDE.md" "$PACKAGE_DIR/README.md"

# Create credential collection template
cat > "$PACKAGE_DIR/SHARE-THESE-CREDENTIALS.md" << 'EOF'
# Credentials to Share

After running the setup script, please provide these details:

## ✅ Required Credentials (Share via Secure Channel):
- **Client ID:** `________________________`
- **Client Secret:** `________________________` 🔐 **USE SECURE TRANSMISSION**
- **Tenant ID:** `________________________`  
- **Subscription IDs:** `________________________`

## 🔐 Security Instructions:
- Use encrypted email or secure file transfer
- Do not send credentials in plain text emails
- Do not include in screenshots
- Delete from your system after secure transmission

## Setup Status:
- [ ] Script completed without errors
- [ ] prowler-config.env file was created
- [ ] All target subscriptions configured

**Next Steps:** Your administrator will use these credentials to configure Prowler scanning.
EOF

# Make scripts executable
chmod +x "$PACKAGE_DIR"/*.sh

# Create package summary
cat > "$PACKAGE_DIR/PACKAGE-CONTENTS.txt" << EOF
Prowler Azure Setup Package
Generated: $(date)

🎯 Start Here: README.md

📁 Scripts:
  all-in-one-single-sub.sh     → Single subscription setup
  all-in-one-multi-sub.sh      → Multiple subscriptions setup
  troubleshoot-azure-auth.sh   → Fix common issues
  cleanup-prowler.sh           → Remove created resources

📄 Files:
  README.md                    → Complete setup instructions
  SHARE-THESE-CREDENTIALS.md   → Template for sharing credentials
  
🔧 Support Files:
  single-subscription-setup.sh, multi-subscription-setup.sh, setup-prowler.sh
EOF

echo "✅ Package created: $PACKAGE_DIR"
echo ""
echo "📦 Package contents:"
ls -la "$PACKAGE_DIR"
echo ""
echo "🎁 To create ZIP for distribution:"
echo "   cd '$SCRIPT_DIR' && zip -r $PACKAGE_NAME.zip $PACKAGE_NAME/"
echo ""
echo "📧 Customer instructions:"
echo "   1. Send them the ZIP file"
echo "   2. Ask them to run: bash all-in-one-single-sub.sh (or multi-sub version)"
echo "   3. Request they fill out SHARE-THESE-CREDENTIALS.md with ALL credentials"
echo "   4. Have them send credentials back via secure channel (encrypted email/file transfer)"