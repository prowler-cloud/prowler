#!/bin/bash

# Prowler Azure Setup Script
# Automates the complete setup of Azure authentication for Prowler
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="Prowler Security Scanner"
CUSTOM_ROLE_NAME="ProwlerRole"

# Functions
print_header() {
    echo -e "${BLUE}🔧 $1${NC}"
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
    
    echo "Available subscriptions:"
    az account list --query "[].{Name:name, SubscriptionId:id, State:state}" --output table
    
    echo ""
    echo "Enter subscription IDs that Prowler should scan (one per line, empty line to finish):"
    
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
    
    # Create app registration
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
    
    # Create service principal
    SP_OUTPUT=$(az ad sp create --id $APP_ID)
    SP_OBJECT_ID=$(echo $SP_OUTPUT | jq -r '.id')
    
    print_success "Created Service Principal: $SP_OBJECT_ID"
    
    # Create client secret
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
    
    for SUB_ID in "${SUBSCRIPTION_IDS[@]}"; do
        print_warning "Creating ProwlerRole in subscription: $SUB_ID"
        
        # Check if role already exists
        if az role definition list --name "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" --query "[0].roleName" -o tsv | grep -q "$CUSTOM_ROLE_NAME"; then
            print_warning "ProwlerRole already exists in subscription $SUB_ID"
        else
            # Create custom role
            az role definition create --subscription "$SUB_ID" --role-definition @- << EOF
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
        print_warning "Assigning roles in subscription: $SUB_ID"
        
        # Assign Reader role
        if az role assignment create \
            --role "Reader" \
            --assignee $SP_OBJECT_ID \
            --subscription "$SUB_ID" >/dev/null 2>&1; then
            print_success "Assigned Reader role in $SUB_ID"
        else
            print_warning "Reader role assignment may already exist in $SUB_ID"
        fi
        
        # Assign ProwlerRole
        if az role assignment create \
            --role "$CUSTOM_ROLE_NAME" \
            --assignee $SP_OBJECT_ID \
            --subscription "$SUB_ID" >/dev/null 2>&1; then
            print_success "Assigned ProwlerRole in $SUB_ID"
        else
            print_warning "ProwlerRole assignment may already exist in $SUB_ID"
        fi
    done
}

display_summary() {
    print_header "Setup Complete!"
    
    TENANT_ID=$(az account show --query tenantId -o tsv)
    
    echo ""
    echo -e "${GREEN}🎉 Prowler Azure authentication is now configured!${NC}"
    echo ""
    echo "Configuration Details:"
    echo "----------------------"
    echo "Application Name: $APP_NAME"
    echo "Application ID: $APP_ID"
    echo "Tenant ID: $TENANT_ID"
    echo "Subscriptions: ${#SUBSCRIPTION_IDS[@]}"
    echo ""
    echo "Environment Variables:"
    echo "---------------------"
    echo "export AZURE_CLIENT_ID=\"$APP_ID\""
    echo "export AZURE_CLIENT_SECRET=\"$CLIENT_SECRET\""
    echo "export AZURE_TENANT_ID=\"$TENANT_ID\""
    echo ""
    echo "Usage:"
    echo "------"
    echo "# Set environment variables (copy-paste the above exports)"
    echo "# Then run Prowler:"
    echo "prowler azure --sp-env-auth"
    echo ""
    print_warning "IMPORTANT: Save the client secret securely - it won't be shown again!"
    echo ""
    
    # Save configuration to file
    CONFIG_FILE="prowler-config.env"
    cat > $CONFIG_FILE << EOF
# Prowler Azure Configuration
# Generated on $(date)
export AZURE_CLIENT_ID="$APP_ID"
export AZURE_CLIENT_SECRET="$CLIENT_SECRET"
export AZURE_TENANT_ID="$TENANT_ID"
EOF
    
    print_success "Configuration saved to $CONFIG_FILE"
    echo "You can source this file with: source $CONFIG_FILE"
}

# Main execution
main() {
    print_header "Prowler Azure Setup"
    echo "This script will automatically configure Azure authentication for Prowler"
    echo ""
    
    check_prerequisites
    get_graph_permissions
    get_subscription_ids
    create_app_registration
    create_custom_role
    assign_roles
    display_summary
}

# Run main function
main