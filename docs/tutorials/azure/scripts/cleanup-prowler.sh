#!/bin/bash

# Prowler Azure Cleanup Script
# Removes all resources created by setup-prowler.sh
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
    echo -e "${BLUE}🧹 $1${NC}"
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

confirm_cleanup() {
    print_header "Prowler Cleanup Confirmation"
    echo "This will remove ALL Prowler-related Azure resources:"
    echo "- App Registration: $APP_NAME"
    echo "- Service Principal"
    echo "- Custom Role: $CUSTOM_ROLE_NAME (from all subscriptions)"
    echo "- Role Assignments"
    echo ""
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " -r
    if [[ ! $REPLY == "yes" ]]; then
        echo "Cleanup cancelled."
        exit 0
    fi
}

find_prowler_resources() {
    print_header "Finding Prowler Resources"
    
    # Find app registration
    APP_INFO=$(az ad app list --display-name "$APP_NAME" --query "[0].{appId:appId,objectId:id}" -o json)
    
    if [[ "$APP_INFO" == "null" || -z "$APP_INFO" ]]; then
        print_warning "No Prowler app registration found with name: $APP_NAME"
        APP_ID=""
        SP_OBJECT_ID=""
    else
        APP_ID=$(echo $APP_INFO | jq -r '.appId')
        
        # Find service principal
        SP_INFO=$(az ad sp list --display-name "$APP_NAME" --query "[0].id" -o tsv)
        SP_OBJECT_ID="$SP_INFO"
        
        print_success "Found App Registration: $APP_ID"
        print_success "Found Service Principal: $SP_OBJECT_ID"
    fi
}

get_subscriptions_with_prowler_role() {
    print_header "Finding Subscriptions with ProwlerRole"
    
    SUBSCRIPTIONS_WITH_ROLE=()
    
    # Get all accessible subscriptions
    SUBSCRIPTION_IDS=$(az account list --query "[].id" -o tsv)
    
    for SUB_ID in $SUBSCRIPTION_IDS; do
        if az role definition list --name "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" --query "[0].roleName" -o tsv 2>/dev/null | grep -q "$CUSTOM_ROLE_NAME"; then
            SUBSCRIPTIONS_WITH_ROLE+=("$SUB_ID")
            print_success "Found ProwlerRole in subscription: $SUB_ID"
        fi
    done
    
    if [[ ${#SUBSCRIPTIONS_WITH_ROLE[@]} -eq 0 ]]; then
        print_warning "No subscriptions found with ProwlerRole"
    fi
}

remove_role_assignments() {
    if [[ -z "$SP_OBJECT_ID" ]]; then
        print_warning "No service principal found, skipping role assignment cleanup"
        return
    fi
    
    print_header "Removing Role Assignments"
    
    for SUB_ID in "${SUBSCRIPTIONS_WITH_ROLE[@]}"; do
        print_warning "Removing role assignments in subscription: $SUB_ID"
        
        # Remove Reader role assignment
        READER_ASSIGNMENTS=$(az role assignment list \
            --assignee "$SP_OBJECT_ID" \
            --role "Reader" \
            --subscription "$SUB_ID" \
            --query "[].id" -o tsv 2>/dev/null || true)
        
        for ASSIGNMENT_ID in $READER_ASSIGNMENTS; do
            if az role assignment delete --ids "$ASSIGNMENT_ID" 2>/dev/null; then
                print_success "Removed Reader role assignment"
            fi
        done
        
        # Remove ProwlerRole assignment
        PROWLER_ASSIGNMENTS=$(az role assignment list \
            --assignee "$SP_OBJECT_ID" \
            --role "$CUSTOM_ROLE_NAME" \
            --subscription "$SUB_ID" \
            --query "[].id" -o tsv 2>/dev/null || true)
        
        for ASSIGNMENT_ID in $PROWLER_ASSIGNMENTS; do
            if az role assignment delete --ids "$ASSIGNMENT_ID" 2>/dev/null; then
                print_success "Removed ProwlerRole assignment"
            fi
        done
    done
}

remove_custom_roles() {
    print_header "Removing Custom Roles"
    
    for SUB_ID in "${SUBSCRIPTIONS_WITH_ROLE[@]}"; do
        print_warning "Removing ProwlerRole from subscription: $SUB_ID"
        
        if az role definition delete --name "$CUSTOM_ROLE_NAME" --subscription "$SUB_ID" 2>/dev/null; then
            print_success "Removed ProwlerRole from $SUB_ID"
        else
            print_warning "Could not remove ProwlerRole from $SUB_ID (may not exist or be in use)"
        fi
    done
}

remove_app_registration() {
    if [[ -z "$APP_ID" ]]; then
        print_warning "No app registration found, skipping"
        return
    fi
    
    print_header "Removing App Registration and Service Principal"
    
    # Delete app registration (this also deletes the service principal)
    if az ad app delete --id "$APP_ID" 2>/dev/null; then
        print_success "Removed App Registration and Service Principal"
    else
        print_error "Failed to remove App Registration"
    fi
}

cleanup_config_files() {
    print_header "Cleaning Up Configuration Files"
    
    if [[ -f "prowler-config.env" ]]; then
        rm -f prowler-config.env
        print_success "Removed prowler-config.env"
    fi
}

display_summary() {
    print_header "Cleanup Complete!"
    
    echo ""
    echo -e "${GREEN}🧹 All Prowler Azure resources have been removed${NC}"
    echo ""
    echo "Cleaned up:"
    echo "- App Registration: $APP_NAME"
    echo "- Service Principal"
    echo "- Custom Role: $CUSTOM_ROLE_NAME (from ${#SUBSCRIPTIONS_WITH_ROLE[@]} subscriptions)"
    echo "- All role assignments"
    echo "- Configuration files"
    echo ""
    print_success "Cleanup completed successfully!"
}

# Main execution
main() {
    confirm_cleanup
    find_prowler_resources
    get_subscriptions_with_prowler_role
    remove_role_assignments
    remove_custom_roles
    remove_app_registration
    cleanup_config_files
    display_summary
}

# Run main function
main