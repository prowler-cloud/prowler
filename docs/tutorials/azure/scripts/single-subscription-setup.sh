#!/bin/bash

# Prowler Azure Setup Script for Single Subscription
# Automates the complete setup of Azure authentication for Prowler using the current subscription
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="Prowler Security Scanner"
CUSTOM_ROLE_NAME="ProwlerRole"

# Functions
print_header() {
    echo -e "${BLUE}${BOLD}🔧 $1${NC}"
    echo "======================================"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI not found. Please install Azure CLI first."
        echo "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        print_error "jq not found. Please install jq first."
        echo "Install from: https://stedolan.github.io/jq/download/"
        exit 1
    fi
    
    if ! az account show &> /dev/null; then
        print_error "Please log in to Azure CLI first: az login"
        exit 1
    fi
    
    print_success "Prerequisites met"
}

get_current_subscription() {
    echo ""
    print_header "Subscription Configuration"
    
    # Get current subscription
    CURRENT_SUB=$(az account show --query id -o tsv)
    CURRENT_SUB_NAME=$(az account show --query name -o tsv)
    
    echo -e "Using the current subscription: ${GREEN}${BOLD}$CURRENT_SUB_NAME${NC}"
    echo -e "Subscription ID: ${GREEN}$CURRENT_SUB${NC}"
    echo ""
    
    # Confirm with user
    echo -e "${YELLOW}Do you want to use this subscription for Prowler? (y/n)${NC}"
    read -r CONFIRM
    
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        print_warning "Please select the subscription you want to use: az account set --subscription <id>"
        exit 1
    fi
    
    SUBSCRIPTION_ID=$CURRENT_SUB
    print_success "Will configure Prowler for subscription: $SUBSCRIPTION_ID"
}

create_app_registration() {
    print_header "Creating App Registration"
    
    # Create app registration
    print_warning "Creating app registration with name: $APP_NAME"
    APP_OUTPUT=$(az ad app create \
        --display-name "$APP_NAME" \
        --required-resource-accesses @- << 'EOF'
[
    {
        "resourceAppId": "00000003-0000-0000-c000-000000000000",
        "resourceAccess": [
            {
                "id": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
                "type": "Role"
            },
            {
                "id": "246dd0d5-5bd0-4def-940b-0421030a5b68",
                "type": "Role"
            },
            {
                "id": "38d9df27-64da-44fd-b7c5-a6fbac20248f",
                "type": "Role"
            }
        ]
    }
]
EOF
    )
    
    APP_ID=$(echo $APP_OUTPUT | jq -r '.appId')
    APP_OBJECT_ID=$(echo $APP_OUTPUT | jq -r '.id')
    
    print_success "Created App Registration: $APP_ID"
    
    # Create service principal
    print_warning "Creating service principal..."
    SP_OUTPUT=$(az ad sp create --id $APP_ID)
    SP_OBJECT_ID=$(echo $SP_OUTPUT | jq -r '.id')
    
    print_success "Created Service Principal: $SP_OBJECT_ID"
    
    # Create client secret
    print_warning "Creating client secret..."
    SECRET_OUTPUT=$(az ad app credential reset --id $APP_ID --display-name "Prowler Client Secret")
    CLIENT_SECRET=$(echo $SECRET_OUTPUT | jq -r '.password')
    
    print_success "Created client secret"
    
    # Grant admin consent (requires Global Administrator or Application Administrator)
    echo ""
    print_warning "Attempting to grant admin consent for API permissions..."
    
    if az ad app permission admin-consent --id $APP_ID 2>/dev/null; then
        print_success "Admin consent granted automatically"
    else
        print_warning "Could not grant admin consent automatically"
        print_warning "Please manually grant admin consent in Azure Portal:"
        print_warning "1. Go to Azure AD > App registrations > $APP_NAME"
        print_warning "2. Click 'API permissions' > 'Grant admin consent'"
    fi
}

create_custom_role() {
    print_header "Creating Custom Role"
    
    print_warning "Creating ProwlerRole in subscription: $SUBSCRIPTION_ID"
    
    # Check if role already exists
    if az role definition list --name "$CUSTOM_ROLE_NAME" --subscription "$SUBSCRIPTION_ID" --query "[0].roleName" -o tsv 2>/dev/null | grep -q "$CUSTOM_ROLE_NAME"; then
        print_warning "ProwlerRole already exists in subscription $SUBSCRIPTION_ID"
    else
        # Create custom role
        az role definition create --subscription "$SUBSCRIPTION_ID" --role-definition @- << EOF
{
    "Name": "$CUSTOM_ROLE_NAME",
    "IsCustom": true,
    "Description": "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role",
    "AssignableScopes": ["/subscriptions/$SUBSCRIPTION_ID"],
    "Actions": [
        "Microsoft.Web/sites/host/listkeys/action",
        "Microsoft.Web/sites/config/list/Action"
    ]
}
EOF
        print_success "Created ProwlerRole in subscription: $SUBSCRIPTION_ID"
    fi
}

assign_roles() {
    print_header "Assigning Roles"
    
    print_warning "Assigning roles in subscription: $SUBSCRIPTION_ID"
    
    # Assign Reader role
    print_warning "Assigning Reader role..."
    if az role assignment create \
        --role "Reader" \
        --assignee $SP_OBJECT_ID \
        --subscription "$SUBSCRIPTION_ID" >/dev/null 2>&1; then
        print_success "Assigned Reader role in $SUBSCRIPTION_ID"
    else
        print_warning "Reader role assignment may already exist in $SUBSCRIPTION_ID"
    fi
    
    # Assign ProwlerRole
    print_warning "Assigning ProwlerRole..."
    if az role assignment create \
        --role "$CUSTOM_ROLE_NAME" \
        --assignee $SP_OBJECT_ID \
        --subscription "$SUBSCRIPTION_ID" >/dev/null 2>&1; then
        print_success "Assigned ProwlerRole in $SUBSCRIPTION_ID"
    else
        print_warning "ProwlerRole assignment may already exist in $SUBSCRIPTION_ID"
    fi
}

display_summary() {
    print_header "Setup Complete!"
    
    TENANT_ID=$(az account show --query tenantId -o tsv)
    
    echo ""
    echo -e "${GREEN}${BOLD}🎉 Prowler Azure authentication is now configured!${NC}"
    echo ""
    echo -e "${BLUE}${BOLD}Configuration Details:${NC}"
    echo "----------------------"
    echo -e "Application Name: ${BOLD}$APP_NAME${NC}"
    echo -e "Application ID: ${BOLD}$APP_ID${NC}"
    echo -e "Tenant ID: ${BOLD}$TENANT_ID${NC}"
    echo -e "Subscription: ${BOLD}$SUBSCRIPTION_ID${NC}"
    echo ""
    
    # Create a formatted box for the client secret
    WIDTH=80
    LINE=$(printf "%${WIDTH}s" | tr " " "-")
    echo -e "${YELLOW}$LINE${NC}"
    echo -e "${YELLOW}|${NC} ${BOLD}CLIENT SECRET (SAVE THIS SECURELY - IT WON'T BE SHOWN AGAIN!)${NC}"
    echo -e "${YELLOW}$LINE${NC}"
    echo -e "${YELLOW}|${NC} ${GREEN}${BOLD}$CLIENT_SECRET${NC}"
    echo -e "${YELLOW}$LINE${NC}"
    echo ""
    
    echo -e "${BLUE}${BOLD}Prowler App Instructions:${NC}"
    echo "----------------------"
    echo -e "1. Open Prowler App"
    echo -e "2. Go to Configuration > Cloud Providers > Add Cloud Provider > Microsoft Azure"
    echo -e "3. Enter these credentials:"
    echo -e "   - Client ID: ${BOLD}$APP_ID${NC}"
    echo -e "   - Client Secret: (use the value above)"
    echo -e "   - Tenant ID: ${BOLD}$TENANT_ID${NC}"
    echo -e "4. Click Next and complete the setup"
    echo ""
    
    echo -e "${BLUE}${BOLD}CLI Instructions:${NC}"
    echo "----------------------"
    echo "To use with Prowler CLI, run:"
    echo ""
    echo -e "${GREEN}export AZURE_CLIENT_ID=\"$APP_ID\"${NC}"
    echo -e "${GREEN}export AZURE_CLIENT_SECRET=\"$CLIENT_SECRET\"${NC}"
    echo -e "${GREEN}export AZURE_TENANT_ID=\"$TENANT_ID\"${NC}"
    echo -e "${GREEN}prowler azure --sp-env-auth${NC}"
    echo ""
    
    # Save configuration to file
    CONFIG_FILE="prowler-config.env"
    cat > $CONFIG_FILE << EOF
# Prowler Azure Configuration
# Generated on $(date)
# Single subscription: $SUBSCRIPTION_ID
export AZURE_CLIENT_ID="$APP_ID"
export AZURE_CLIENT_SECRET="$CLIENT_SECRET"
export AZURE_TENANT_ID="$TENANT_ID"
EOF
    
    print_success "Configuration saved to $CONFIG_FILE"
    echo -e "You can source this file with: ${GREEN}source $CONFIG_FILE${NC}"
}

# Main execution
main() {
    echo ""
    echo -e "${BLUE}${BOLD}===================================================${NC}"
    echo -e "${BLUE}${BOLD}   Prowler Azure Setup - Single Subscription       ${NC}"
    echo -e "${BLUE}${BOLD}===================================================${NC}"
    echo ""
    echo -e "This script will configure Prowler for your ${BOLD}current subscription only${NC}."
    echo -e "For multi-subscription setup, use ${BOLD}multi-subscription-setup.sh${NC} instead."
    echo ""
    
    check_prerequisites
    get_current_subscription
    create_app_registration
    create_custom_role
    assign_roles
    display_summary
}

# Run main function
main