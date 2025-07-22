#!/bin/bash

# Prowler Azure Authentication Troubleshooting Script
# This script helps diagnose and fix common authentication issues with Prowler for Azure

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}${BOLD}🔍 $1${NC}"
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

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Header
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler Azure Authentication Troubleshooter         ${NC}"
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo

# Check prerequisites
print_header "Checking Prerequisites"

if ! command -v az &> /dev/null; then
    print_error "Azure CLI not found. Please install Azure CLI first."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    print_error "jq not found. Please install jq first."
    exit 1
fi

if ! az account show &> /dev/null; then
    print_error "Not logged in to Azure CLI. Please run: az login"
    exit 1
fi

print_success "Prerequisites met"
echo

# Get current Azure context
print_header "Current Azure Context"
CURRENT_TENANT=$(az account show --query tenantId -o tsv)
CURRENT_SUB=$(az account show --query id -o tsv)
CURRENT_SUB_NAME=$(az account show --query name -o tsv)

echo -e "Tenant ID: ${GREEN}$CURRENT_TENANT${NC}"
echo -e "Current Subscription: ${GREEN}$CURRENT_SUB_NAME${NC}"
echo -e "Subscription ID: ${GREEN}$CURRENT_SUB${NC}"
echo

# Check if Prowler credentials are set
print_header "Checking Prowler Credentials"

if [[ -z "$AZURE_CLIENT_ID" ]]; then
    print_warning "AZURE_CLIENT_ID environment variable is not set"
    CREDS_SET=false
else
    print_success "AZURE_CLIENT_ID is set: $AZURE_CLIENT_ID"
    CREDS_SET=true
fi

if [[ -z "$AZURE_CLIENT_SECRET" ]]; then
    print_warning "AZURE_CLIENT_SECRET environment variable is not set"
    CREDS_SET=false
else
    print_success "AZURE_CLIENT_SECRET is set (hidden)"
fi

if [[ -z "$AZURE_TENANT_ID" ]]; then
    print_warning "AZURE_TENANT_ID environment variable is not set"
    CREDS_SET=false
else
    print_success "AZURE_TENANT_ID is set: $AZURE_TENANT_ID"
fi

echo

# If credentials not set, look for config file
if [[ "$CREDS_SET" == "false" ]]; then
    if [[ -f "prowler-config.env" ]]; then
        print_info "Found prowler-config.env file. You can source it with:"
        echo -e "${GREEN}source prowler-config.env${NC}"
        echo
        
        # Extract values from config file for checking
        AZURE_CLIENT_ID=$(grep "AZURE_CLIENT_ID" prowler-config.env | cut -d'"' -f2)
        AZURE_TENANT_ID=$(grep "AZURE_TENANT_ID" prowler-config.env | cut -d'"' -f2)
    else
        print_error "No Prowler credentials found. Please run the setup script first."
        exit 1
    fi
fi

# Check if app registration exists
print_header "Checking App Registration"

if [[ -n "$AZURE_CLIENT_ID" ]]; then
    APP_INFO=$(az ad app show --id "$AZURE_CLIENT_ID" 2>/dev/null)
    
    if [[ -n "$APP_INFO" ]]; then
        APP_NAME=$(echo $APP_INFO | jq -r '.displayName')
        print_success "Found app registration: $APP_NAME"
        
        # Check API permissions
        print_info "Checking API permissions..."
        PERMISSIONS=$(az ad app permission list --id "$AZURE_CLIENT_ID" --query "[?resourceAppId=='00000003-0000-0000-c000-000000000000'].resourceAccess[].id" -o tsv)
        
        REQUIRED_PERMISSIONS=(
            "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
            "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All
            "38d9df27-64da-44fd-b7c5-a6fbac20248f"  # UserAuthenticationMethod.Read.All
        )
        
        for perm in "${REQUIRED_PERMISSIONS[@]}"; do
            if echo "$PERMISSIONS" | grep -q "$perm"; then
                print_success "Required permission found: $perm"
            else
                print_error "Missing required permission: $perm"
            fi
        done
        
        # Check admin consent
        print_info "Checking admin consent status..."
        CONSENT_STATUS=$(az ad app permission list-grants --id "$AZURE_CLIENT_ID" 2>/dev/null)
        
        if [[ -n "$CONSENT_STATUS" && "$CONSENT_STATUS" != "[]" ]]; then
            print_success "Admin consent appears to be granted"
        else
            print_warning "Admin consent may not be granted. This could cause authentication issues."
            echo
            print_info "To grant admin consent:"
            echo "1. Go to Azure Portal > Azure Active Directory > App registrations"
            echo "2. Find your app: $APP_NAME"
            echo "3. Click on 'API permissions'"
            echo "4. Click 'Grant admin consent for $CURRENT_TENANT'"
        fi
    else
        print_error "App registration not found for client ID: $AZURE_CLIENT_ID"
        print_info "The app may have been deleted. Please run the setup script again."
    fi
else
    print_error "No client ID available to check"
fi

echo

# Check service principal
print_header "Checking Service Principal"

if [[ -n "$AZURE_CLIENT_ID" ]]; then
    SP_INFO=$(az ad sp show --id "$AZURE_CLIENT_ID" 2>/dev/null)
    
    if [[ -n "$SP_INFO" ]]; then
        SP_OBJECT_ID=$(echo $SP_INFO | jq -r '.id')
        print_success "Found service principal: $SP_OBJECT_ID"
    else
        print_error "Service principal not found for app ID: $AZURE_CLIENT_ID"
        print_info "Creating service principal..."
        
        if az ad sp create --id "$AZURE_CLIENT_ID" 2>/dev/null; then
            print_success "Service principal created successfully"
        else
            print_error "Failed to create service principal"
        fi
    fi
fi

echo

# Check role assignments
print_header "Checking Role Assignments"

# Ask user which subscription they're trying to scan
echo -e "${YELLOW}Which subscription are you trying to scan with Prowler?${NC}"
echo "1) Current subscription ($CURRENT_SUB_NAME)"
echo "2) A different subscription"
echo "3) Multiple subscriptions"
read -p "Select an option (1-3): " OPTION

case $OPTION in
    1)
        SUBSCRIPTIONS_TO_CHECK=("$CURRENT_SUB")
        ;;
    2)
        read -p "Enter the subscription ID: " USER_SUB
        SUBSCRIPTIONS_TO_CHECK=("$USER_SUB")
        ;;
    3)
        echo "Enter subscription IDs (one per line, empty line to finish):"
        SUBSCRIPTIONS_TO_CHECK=()
        while IFS= read -r line; do
            if [[ -z "$line" ]]; then
                break
            fi
            SUBSCRIPTIONS_TO_CHECK+=("$line")
        done
        ;;
    *)
        print_error "Invalid option"
        exit 1
        ;;
esac

echo

# Check roles for each subscription
for SUB_ID in "${SUBSCRIPTIONS_TO_CHECK[@]}"; do
    print_info "Checking subscription: $SUB_ID"
    
    # Verify subscription exists and is accessible
    SUB_NAME=$(az account show --subscription "$SUB_ID" --query name -o tsv 2>/dev/null)
    
    if [[ -z "$SUB_NAME" ]]; then
        print_error "Cannot access subscription $SUB_ID. You may not have permissions."
        continue
    fi
    
    print_success "Subscription accessible: $SUB_NAME"
    
    if [[ -n "$SP_OBJECT_ID" ]]; then
        # Check Reader role
        READER_CHECK=$(az role assignment list --assignee "$SP_OBJECT_ID" --role "Reader" --subscription "$SUB_ID" --query "[0].roleDefinitionName" -o tsv 2>/dev/null)
        
        if [[ "$READER_CHECK" == "Reader" ]]; then
            print_success "Reader role is assigned"
        else
            print_error "Reader role is NOT assigned"
            print_info "Attempting to assign Reader role..."
            
            if az role assignment create --role "Reader" --assignee "$SP_OBJECT_ID" --subscription "$SUB_ID" 2>/dev/null; then
                print_success "Reader role assigned successfully"
            else
                print_error "Failed to assign Reader role. You may need Owner or User Access Administrator permissions."
            fi
        fi
        
        # Check ProwlerRole
        PROWLER_CHECK=$(az role assignment list --assignee "$SP_OBJECT_ID" --role "ProwlerRole" --subscription "$SUB_ID" --query "[0].roleDefinitionName" -o tsv 2>/dev/null)
        
        if [[ "$PROWLER_CHECK" == "ProwlerRole" ]]; then
            print_success "ProwlerRole is assigned"
        else
            print_warning "ProwlerRole is NOT assigned (optional but recommended)"
            
            # Check if ProwlerRole exists
            ROLE_EXISTS=$(az role definition list --name "ProwlerRole" --subscription "$SUB_ID" --query "[0].roleName" -o tsv 2>/dev/null)
            
            if [[ "$ROLE_EXISTS" != "ProwlerRole" ]]; then
                print_info "ProwlerRole doesn't exist. Creating it..."
                
                # Create ProwlerRole
                az role definition create --subscription "$SUB_ID" --role-definition @- << EOF >/dev/null 2>&1
{
    "Name": "ProwlerRole",
    "IsCustom": true,
    "Description": "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role",
    "AssignableScopes": ["/subscriptions/$SUB_ID"],
    "Actions": [
        "Microsoft.Web/sites/host/listkeys/action",
        "Microsoft.Web/sites/config/list/Action"
    ]
}
EOF
                if [ $? -eq 0 ]; then
                    print_success "ProwlerRole created"
                else
                    print_warning "Failed to create ProwlerRole. Some checks may not work."
                fi
            fi
            
            # Try to assign ProwlerRole
            if [[ "$ROLE_EXISTS" == "ProwlerRole" ]] || [ $? -eq 0 ]; then
                print_info "Attempting to assign ProwlerRole..."
                
                if az role assignment create --role "ProwlerRole" --assignee "$SP_OBJECT_ID" --subscription "$SUB_ID" 2>/dev/null; then
                    print_success "ProwlerRole assigned successfully"
                else
                    print_warning "Failed to assign ProwlerRole. Some checks may not work."
                fi
            fi
        fi
    else
        print_error "No service principal ID available to check role assignments"
    fi
    
    echo
done

# Test authentication
print_header "Testing Authentication"

if [[ "$CREDS_SET" == "true" ]] || [[ -f "prowler-config.env" ]]; then
    print_info "Testing service principal authentication..."
    
    # Try to authenticate with the service principal
    TEST_RESULT=$(az login --service-principal \
        -u "${AZURE_CLIENT_ID}" \
        -p "${AZURE_CLIENT_SECRET}" \
        --tenant "${AZURE_TENANT_ID}" 2>&1)
    
    if [ $? -eq 0 ]; then
        print_success "Service principal authentication successful!"
        
        # List accessible subscriptions
        print_info "Accessible subscriptions:"
        az account list --query "[].{Name:name, ID:id}" --output table
        
        # Logout from service principal
        az logout 2>/dev/null
        
        # Log back in as user
        print_info "Logging back in as user..."
        az login --only-show-errors > /dev/null 2>&1
    else
        print_error "Service principal authentication failed!"
        echo "$TEST_RESULT" | grep -E "(error|Error)" | head -5
        echo
        print_info "Common causes:"
        echo "- Invalid client secret (regenerate with setup script)"
        echo "- Wrong tenant ID"
        echo "- Service principal disabled"
    fi
fi

echo

# Summary and recommendations
print_header "Summary and Recommendations"

echo -e "${BLUE}${BOLD}Next Steps:${NC}"
echo

if [[ "$CREDS_SET" == "false" ]]; then
    echo "1. Source your configuration file:"
    echo -e "   ${GREEN}source prowler-config.env${NC}"
    echo
fi

echo "2. Run Prowler with:"
echo -e "   ${GREEN}prowler azure --sp-env-auth${NC}"
echo

echo "3. If you still get errors:"
echo "   - Wait 2-3 minutes for Azure AD changes to propagate"
echo "   - Ensure admin consent is granted in Azure Portal"
echo "   - Check that your subscription ID matches what was configured"
echo "   - Run this troubleshooting script again"
echo

echo "4. For specific subscription scanning:"
echo -e "   ${GREEN}prowler azure --sp-env-auth --subscription-ids <subscription-id>${NC}"

echo
print_success "Troubleshooting complete!"