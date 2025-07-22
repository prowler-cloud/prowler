#!/bin/bash

# Prowler Azure Setup Script for Multiple Subscriptions
# Automates the complete setup of Azure authentication for Prowler across multiple subscriptions
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

get_graph_permissions() {
    print_header "Getting Microsoft Graph API Information"
    
    # Get Microsoft Graph Service Principal ID
    print_warning "Fetching Microsoft Graph service principal..."
    GRAPH_SP=$(az ad sp list --display-name "Microsoft Graph" --query "[0]" 2>/dev/null)
    
    if [[ -z "$GRAPH_SP" || "$GRAPH_SP" == "null" ]]; then
        print_error "Could not find Microsoft Graph service principal"
        exit 1
    fi
    
    GRAPH_APP_ID=$(echo $GRAPH_SP | jq -r '.appId')
    print_success "Found Microsoft Graph App ID: $GRAPH_APP_ID"
    
    # Get required permission IDs dynamically
    print_warning "Fetching required permission IDs..."
    
    # Get Domain.Read.All permission ID
    DOMAIN_READ_ALL_ID=$(echo $GRAPH_SP | jq -r '.appRoles[] | select(.value=="Domain.Read.All") | .id')
    if [[ -z "$DOMAIN_READ_ALL_ID" || "$DOMAIN_READ_ALL_ID" == "null" ]]; then
        print_error "Could not find Domain.Read.All permission ID"
        exit 1
    fi
    print_success "Domain.Read.All ID: $DOMAIN_READ_ALL_ID"
    
    # Get Policy.Read.All permission ID
    POLICY_READ_ALL_ID=$(echo $GRAPH_SP | jq -r '.appRoles[] | select(.value=="Policy.Read.All") | .id')
    if [[ -z "$POLICY_READ_ALL_ID" || "$POLICY_READ_ALL_ID" == "null" ]]; then
        print_error "Could not find Policy.Read.All permission ID"
        exit 1
    fi
    print_success "Policy.Read.All ID: $POLICY_READ_ALL_ID"
    
    # Get UserAuthenticationMethod.Read.All permission ID
    USER_AUTH_READ_ALL_ID=$(echo $GRAPH_SP | jq -r '.appRoles[] | select(.value=="UserAuthenticationMethod.Read.All") | .id')
    if [[ -z "$USER_AUTH_READ_ALL_ID" || "$USER_AUTH_READ_ALL_ID" == "null" ]]; then
        print_error "Could not find UserAuthenticationMethod.Read.All permission ID"
        exit 1
    fi
    print_success "UserAuthenticationMethod.Read.All ID: $USER_AUTH_READ_ALL_ID"
}

get_subscription_ids() {
    echo ""
    print_header "Subscription Configuration"
    
    echo -e "${BLUE}${BOLD}Available subscriptions:${NC}"
    az account list --query "[].{Name:name, SubscriptionId:id, State:state}" --output table
    
    echo ""
    echo -e "${YELLOW}Enter subscription IDs that Prowler should scan (one per line, empty line to finish):${NC}"
    
    SUBSCRIPTION_IDS=()
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            break
        fi
        
        # Validate subscription ID format (basic UUID validation)
        if [[ $line =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
            SUBSCRIPTION_IDS+=("$line")
            print_success "Added subscription: $line"
        else
            print_warning "Invalid subscription ID format: $line"
        fi
    done
    
    if [[ ${#SUBSCRIPTION_IDS[@]} -eq 0 ]]; then
        print_error "No valid subscription IDs provided"
        exit 1
    fi
    
    echo ""
    print_success "Will configure Prowler for ${#SUBSCRIPTION_IDS[@]} subscriptions"
}

create_app_registration() {
    print_header "Creating App Registration"
    
    # Check if app registration already exists
    print_warning "Checking for existing app registration with name: $APP_NAME"
    EXISTING_APP=$(az ad app list --display-name "$APP_NAME" --query "[0]" 2>/dev/null)
    
    if [[ $EXISTING_APP != "null" && -n "$EXISTING_APP" ]]; then
        APP_ID=$(echo $EXISTING_APP | jq -r '.appId')
        APP_OBJECT_ID=$(echo $EXISTING_APP | jq -r '.id')
        print_warning "Found existing App Registration: $APP_ID"
        
        # Update required permissions to ensure they're correct
        print_warning "Updating API permissions for existing app..."
        PERMISSIONS_JSON=$(cat << EOF
[
    {
        "resourceAppId": "$GRAPH_APP_ID",
        "resourceAccess": [
            {
                "id": "$DOMAIN_READ_ALL_ID",
                "type": "Role"
            },
            {
                "id": "$POLICY_READ_ALL_ID",
                "type": "Role"
            },
            {
                "id": "$USER_AUTH_READ_ALL_ID",
                "type": "Role"
            }
        ]
    }
]
EOF
        )
        
        echo "$PERMISSIONS_JSON" | az ad app update --id "$APP_ID" --required-resource-accesses @- >/dev/null
        print_success "Updated API permissions for existing app"
    else
        # Create new app registration
        print_warning "Creating new app registration with name: $APP_NAME"
        PERMISSIONS_JSON=$(cat << EOF
[
    {
        "resourceAppId": "$GRAPH_APP_ID",
        "resourceAccess": [
            {
                "id": "$DOMAIN_READ_ALL_ID",
                "type": "Role"
            },
            {
                "id": "$POLICY_READ_ALL_ID",
                "type": "Role"
            },
            {
                "id": "$USER_AUTH_READ_ALL_ID",
                "type": "Role"
            }
        ]
    }
]
EOF
        )
        
        APP_OUTPUT=$(echo "$PERMISSIONS_JSON" | az ad app create \
            --display-name "$APP_NAME" \
            --required-resource-accesses @-)
        
        APP_ID=$(echo $APP_OUTPUT | jq -r '.appId')
        APP_OBJECT_ID=$(echo $APP_OUTPUT | jq -r '.id')
        
        print_success "Created App Registration: $APP_ID"
    fi
    
    # Check if service principal already exists
    print_warning "Checking for existing service principal..."
    EXISTING_SP=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0]" 2>/dev/null)
    
    if [[ $EXISTING_SP != "null" && -n "$EXISTING_SP" ]]; then
        SP_OBJECT_ID=$(echo $EXISTING_SP | jq -r '.id')
        print_warning "Found existing Service Principal: $SP_OBJECT_ID"
    else
        # Create service principal
        print_warning "Creating service principal..."
        SP_OUTPUT=$(az ad sp create --id $APP_ID 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            print_warning "Service principal creation failed. It might already exist."
            EXISTING_SP=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0]" 2>/dev/null)
            
            if [[ $EXISTING_SP != "null" && -n "$EXISTING_SP" ]]; then
                SP_OBJECT_ID=$(echo $EXISTING_SP | jq -r '.id')
                print_warning "Found existing Service Principal: $SP_OBJECT_ID"
            else
                print_error "Failed to create or find service principal for app ID: $APP_ID"
                exit 1
            fi
        else
            SP_OBJECT_ID=$(echo $SP_OUTPUT | jq -r '.id')
            print_success "Created Service Principal: $SP_OBJECT_ID"
        fi
    fi
    
    # Create client secret
    print_warning "Creating client secret..."
    SECRET_OUTPUT=$(az ad app credential reset --id $APP_ID --display-name "Prowler Client Secret")
    CLIENT_SECRET=$(echo $SECRET_OUTPUT | jq -r '.password')
    
    print_success "Created/updated client secret"
    
    # Grant admin consent (requires Global Administrator or Application Administrator)
    echo ""
    print_warning "Attempting to grant admin consent for API permissions..."
    
    if az ad app permission admin-consent --id $APP_ID 2>/dev/null; then
        print_success "Admin consent granted automatically"
    else
        echo ""
        print_warning "Could not grant admin consent automatically. This is a common issue."
        print_warning "We need to complete this step manually for the setup to work correctly."
        echo ""
        
        # Create consent URL
        TENANT_ID=$(az account show --query tenantId -o tsv)
        CONSENT_URL="https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$APP_ID/isMSAApp/"
        
        echo -e "${YELLOW}${BOLD}Admin Consent Required:${NC}"
        echo "--------------------------------------"
        echo -e "1. ${BOLD}Open this URL in your browser:${NC}"
        echo -e "   ${BLUE}$CONSENT_URL${NC}"
        echo -e "2. Sign in as an admin if needed"
        echo -e "3. Click 'API permissions' in the left menu"
        echo -e "4. Click the '${BOLD}Grant admin consent for <your directory>${NC}' button"
        echo -e "5. Click 'Yes' when prompted"
        echo -e "6. You should see green checkmarks next to all permissions"
        echo ""
        
        # Try to open the URL automatically
        if command -v open &>/dev/null; then
            echo -e "${YELLOW}Would you like to open the consent page automatically? (y/n)${NC}"
            read -r OPEN_BROWSER
            if [[ "$OPEN_BROWSER" =~ ^[Yy]$ ]]; then
                echo "Opening browser..."
                open "$CONSENT_URL"
            fi
        elif command -v xdg-open &>/dev/null; then
            echo -e "${YELLOW}Would you like to open the consent page automatically? (y/n)${NC}"
            read -r OPEN_BROWSER
            if [[ "$OPEN_BROWSER" =~ ^[Yy]$ ]]; then
                echo "Opening browser..."
                xdg-open "$CONSENT_URL"
            fi
        fi
        
        echo ""
        echo -e "${YELLOW}Press Enter after you've granted admin consent...${NC}"
        read -r
        
        # Verify if consent was granted by checking one of the permissions
        echo "Verifying admin consent..."
        CONSENT_CHECK=$(az ad app show --id $APP_ID --query "appRoles[?value=='Domain.Read.All'].allowedMemberTypes" -o tsv 2>/dev/null)
        
        if [[ -n "$CONSENT_CHECK" ]]; then
            print_success "Admin consent verified successfully!"
        else
            print_warning "Could not verify admin consent. This may affect Prowler's ability to scan certain resources."
            print_warning "You can try granting consent again later using the Azure portal."
        fi
    fi
}

create_custom_roles() {
    print_header "Creating Custom Roles"
    
    for SUB_ID in "${SUBSCRIPTION_IDS[@]}"; do
        print_warning "Checking for ProwlerRole in subscription: $SUB_ID"
        
        # Check if role already exists
        if az role definition list --name "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" --query "[0].roleName" -o tsv 2>/dev/null | grep -q "$CUSTOM_ROLE_NAME"; then
            print_warning "ProwlerRole already exists in subscription $SUB_ID"
            
            # Check if the role needs updating
            print_warning "Verifying role permissions..."
            ROLE_ACTIONS=$(az role definition list --name "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" --query "[0].permissions[0].actions" -o tsv)
            
            if [[ "$ROLE_ACTIONS" != *"Microsoft.Web/sites/host/listkeys/action"* ]] || [[ "$ROLE_ACTIONS" != *"Microsoft.Web/sites/config/list/Action"* ]]; then
                print_warning "Updating ProwlerRole with required permissions..."
                
                # Delete and recreate the role with proper permissions
                ROLE_ID=$(az role definition list --name "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" --query "[0].name" -o tsv)
                az role definition delete --name "$ROLE_ID" --subscription "$SUB_ID" >/dev/null
                
                # Create custom role
                az role definition create --subscription "$SUB_ID" --role-definition @- << EOF >/dev/null
{
    "Name": "$CUSTOM_ROLE_NAME",
    "IsCustom": true,
    "Description": "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role",
    "AssignableScopes": ["/subscriptions/$SUB_ID"],
    "Actions": [
        "Microsoft.Web/sites/host/listkeys/action",
        "Microsoft.Web/sites/config/list/Action"
    ]
}
EOF
                print_success "Updated ProwlerRole with required permissions"
            else
                print_success "ProwlerRole already has the required permissions"
            fi
        else
            # Create custom role
            print_warning "Creating new ProwlerRole..."
            az role definition create --subscription "$SUB_ID" --role-definition @- << EOF >/dev/null
{
    "Name": "$CUSTOM_ROLE_NAME",
    "IsCustom": true,
    "Description": "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role",
    "AssignableScopes": ["/subscriptions/$SUB_ID"],
    "Actions": [
        "Microsoft.Web/sites/host/listkeys/action",
        "Microsoft.Web/sites/config/list/Action"
    ]
}
EOF
            print_success "Created ProwlerRole in subscription: $SUB_ID"
        fi
    done
}

assign_roles() {
    print_header "Assigning Roles"
    
    for SUB_ID in "${SUBSCRIPTION_IDS[@]}"; do
        print_warning "Checking role assignments in subscription: $SUB_ID"
        
        # Check if Reader role is already assigned
        print_warning "Checking Reader role assignment..."
        READER_ASSIGNED=$(az role assignment list --assignee "$SP_OBJECT_ID" --role "Reader" --subscription "$SUB_ID" --query "[0].roleDefinitionName" -o tsv 2>/dev/null)
        
        if [[ "$READER_ASSIGNED" == "Reader" ]]; then
            print_success "Reader role is already assigned in $SUB_ID"
        else
            print_warning "Assigning Reader role..."
            if az role assignment create \
                --role "Reader" \
                --assignee "$SP_OBJECT_ID" \
                --subscription "$SUB_ID" >/dev/null 2>&1; then
                print_success "Assigned Reader role in $SUB_ID"
            else
                print_warning "Failed to assign Reader role. It may already exist."
            fi
        fi
        
        # Check if ProwlerRole is already assigned
        print_warning "Checking ProwlerRole assignment..."
        PROWLER_ASSIGNED=$(az role assignment list --assignee "$SP_OBJECT_ID" --role "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" --query "[0].roleDefinitionName" -o tsv 2>/dev/null)
        
        if [[ "$PROWLER_ASSIGNED" == "$CUSTOM_ROLE_NAME" ]]; then
            print_success "ProwlerRole is already assigned in $SUB_ID"
        else
            print_warning "Assigning ProwlerRole..."
            if az role assignment create \
                --role "$CUSTOM_ROLE_NAME" \
                --assignee "$SP_OBJECT_ID" \
                --subscription "$SUB_ID" >/dev/null 2>&1; then
                print_success "Assigned ProwlerRole in $SUB_ID"
            else
                print_warning "Failed to assign ProwlerRole. It may already exist."
            fi
        fi
    done
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
    echo -e "Subscriptions: ${BOLD}${#SUBSCRIPTION_IDS[@]}${NC}"
    echo ""
    
    # Print all subscription IDs
    echo -e "${BLUE}${BOLD}Configured Subscriptions:${NC}"
    for SUB_ID in "${SUBSCRIPTION_IDS[@]}"; do
        echo -e "- ${GREEN}$SUB_ID${NC}"
    done
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
    echo -e "5. Repeat for each subscription if needed"
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
    echo -e "Prowler will automatically scan all configured subscriptions."
    echo ""
    
    # Save configuration to file
    CONFIG_FILE="prowler-config.env"
    cat > $CONFIG_FILE << EOF
# Prowler Azure Configuration
# Generated on $(date)
# Multi-subscription setup: ${#SUBSCRIPTION_IDS[@]} subscriptions
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
    echo -e "${BLUE}${BOLD}   Prowler Azure Setup - Multiple Subscriptions     ${NC}"
    echo -e "${BLUE}${BOLD}===================================================${NC}"
    echo ""
    echo -e "This script will configure Prowler across ${BOLD}multiple subscriptions${NC}."
    echo -e "For single subscription setup, use ${BOLD}single-subscription-setup.sh${NC} instead."
    echo ""
    
    check_prerequisites
    get_graph_permissions
    get_subscription_ids
    create_app_registration
    create_custom_roles
    assign_roles
    display_summary
}

# Run main function
main