#!/bin/bash

# Setup GCP Authentication for Prowler Scanning
# This script installs gcloud CLI if needed and configures authentication

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== GCP Authentication Setup for Prowler ===${NC}"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*)    echo "macos" ;;
        Linux*)     echo "linux" ;;
        *)          echo "unsupported" ;;
    esac
}

# Function to install gcloud CLI
install_gcloud() {
    local os=$(detect_os)
    
    if [ "$os" = "unsupported" ]; then
        echo -e "${RED}Unsupported operating system. Please install gcloud CLI manually.${NC}"
        echo "Visit: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    
    echo -e "${YELLOW}Installing Google Cloud SDK...${NC}"
    
    if [ "$os" = "macos" ]; then
        # Check if homebrew is installed
        if command_exists brew; then
            echo "Installing via Homebrew..."
            brew install --cask google-cloud-sdk
        else
            echo "Installing via direct download..."
            curl https://sdk.cloud.google.com | bash
            exec -l $SHELL
        fi
    elif [ "$os" = "linux" ]; then
        # Install on Linux
        echo "Installing via apt-get or direct download..."
        if command_exists apt-get; then
            echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
            sudo apt-get install apt-transport-https ca-certificates gnupg
            curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
            sudo apt-get update && sudo apt-get install google-cloud-sdk
        else
            curl https://sdk.cloud.google.com | bash
            exec -l $SHELL
        fi
    fi
}

# Step 1: Check if gcloud is installed
if ! command_exists gcloud; then
    echo -e "${YELLOW}gcloud CLI not found. Installing...${NC}"
    install_gcloud
    
    # Re-check after installation
    if ! command_exists gcloud; then
        echo -e "${RED}Failed to install gcloud CLI. Please install manually and run this script again.${NC}"
        echo "Visit: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
else
    echo -e "${GREEN}✓ gcloud CLI is already installed${NC}"
fi

# Step 2: Update gcloud components
echo -e "\n${YELLOW}Updating gcloud components...${NC}"
gcloud components update --quiet || true

# Step 3: Initialize gcloud configuration
echo -e "\n${YELLOW}Initializing gcloud configuration...${NC}"
echo -e "${YELLOW}Please follow the prompts to configure your GCP account.${NC}"
gcloud init

# Step 4: Set up project
echo -e "\n${YELLOW}Setting up GCP project...${NC}"

# Get current project if any
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)

if [ -n "$CURRENT_PROJECT" ]; then
    echo -e "Current project: ${GREEN}$CURRENT_PROJECT${NC}"
    read -p "Do you want to use this project? (Y/n): " USE_CURRENT
    
    if [[ ! $USE_CURRENT =~ ^[Nn]$ ]]; then
        PROJECT_ID="$CURRENT_PROJECT"
        echo -e "${GREEN}✓ Using current project: $PROJECT_ID${NC}"
    else
        # User doesn't want to use current project
        CURRENT_PROJECT=""
    fi
fi

if [ -z "$CURRENT_PROJECT" ] || [[ $USE_CURRENT =~ ^[Nn]$ ]]; then
    echo -e "\n${YELLOW}Project options:${NC}"
    echo "1. Create a new project called 'ProwlerTest'"
    echo "2. Use an existing project"
    read -p "Choose option (1/2): " PROJECT_OPTION
    
    if [ "$PROJECT_OPTION" = "1" ]; then
        echo -e "\n${YELLOW}Creating project 'ProwlerTest'...${NC}"
        if gcloud projects create ProwlerTest 2>/dev/null; then
            echo -e "${GREEN}✓ Project 'ProwlerTest' created successfully${NC}"
            PROJECT_ID="ProwlerTest"
        else
            echo -e "${YELLOW}⚠ Could not create project 'ProwlerTest'.${NC}"
            echo "This could be because:"
            echo "- Project ID already exists"
            echo "- You don't have permission to create projects"
            echo "- Billing account is required"
            
            read -p "Do you want to try using 'ProwlerTest' anyway? (y/N): " USE_ANYWAY
            if [[ $USE_ANYWAY =~ ^[Yy]$ ]]; then
                PROJECT_ID="ProwlerTest"
                echo -e "${YELLOW}Will attempt to use existing 'ProwlerTest' project${NC}"
            else
                echo -e "${YELLOW}Please enter an existing project ID:${NC}"
                read -r PROJECT_ID
            fi
        fi
    else
        echo -e "\n${YELLOW}Please enter your existing GCP Project ID:${NC}"
        read -r PROJECT_ID
    fi
    
    # Validate and set the project
    echo -e "\n${YELLOW}Validating project '$PROJECT_ID'...${NC}"
    if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
        gcloud config set project "$PROJECT_ID"
        echo -e "${GREEN}✓ Project validated and set to: $PROJECT_ID${NC}"
    else
        echo -e "${RED}✗ Project '$PROJECT_ID' does not exist or you don't have access to it.${NC}"
        echo -e "${YELLOW}Please check:${NC}"
        echo "1. The project ID is correct (project IDs are globally unique)"
        echo "2. You have access to the project"
        echo "3. The project exists in your GCP account"
        
        echo -e "\n${YELLOW}Available projects in your account:${NC}"
        gcloud projects list --format="table(projectId,name,projectNumber)" 2>/dev/null || echo "Could not list projects"
        
        echo -e "\n${YELLOW}Please enter a valid project ID from the list above:${NC}"
        read -r PROJECT_ID
        
        if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
            gcloud config set project "$PROJECT_ID"
            echo -e "${GREEN}✓ Project validated and set to: $PROJECT_ID${NC}"
        else
            echo -e "${RED}✗ Project '$PROJECT_ID' is still not valid. Exiting.${NC}"
            echo "Please ensure you have a valid GCP project and re-run this script."
            exit 1
        fi
    fi
fi

# Step 5: Set up Application Default Credentials with proper scopes
echo -e "\n${YELLOW}Setting up Application Default Credentials for Prowler...${NC}"
echo -e "${YELLOW}This will open a browser window for authentication.${NC}"
echo -e "${YELLOW}Make sure to consent to ALL requested scopes for proper functionality.${NC}"

# Try with --no-browser first if the web authentication fails
if ! gcloud auth application-default login; then
    echo -e "\n${YELLOW}Web authentication failed. Trying with --no-browser option...${NC}"
    echo -e "${YELLOW}You will need to copy and paste an authentication code.${NC}"
    if ! gcloud auth application-default login --no-browser; then
        echo -e "\n${RED}Authentication failed. This might be due to scope consent issues.${NC}"
        echo -e "${YELLOW}Please try the following manually:${NC}"
        echo -e "1. Run: ${YELLOW}gcloud auth application-default revoke${NC}"
        echo -e "2. Run: ${YELLOW}gcloud auth application-default login${NC}"
        echo -e "3. Make sure to consent to ALL scopes when prompted"
        echo -e "4. Re-run this script"
        exit 1
    fi
fi

# Verify authentication worked
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
    echo -e "\n${RED}Authentication verification failed.${NC}"
    echo -e "${YELLOW}The cloud-platform scope may not have been consented to.${NC}"
    echo -e "${YELLOW}Please run the following commands manually:${NC}"
    echo -e "1. ${YELLOW}gcloud auth application-default revoke${NC}"
    echo -e "2. ${YELLOW}gcloud auth application-default login${NC}"
    echo -e "3. Make sure to consent to ALL scopes, especially 'cloud-platform'"
    exit 1
fi

echo -e "${GREEN}✓ Authentication successful with proper scopes${NC}"

# Step 6: Set quota project first
echo -e "\n${YELLOW}Setting quota project...${NC}"
if gcloud auth application-default set-quota-project "$PROJECT_ID" 2>/dev/null; then
    echo -e "${GREEN}✓ Quota project set to: $PROJECT_ID${NC}"
else
    echo -e "${YELLOW}⚠ Could not set quota project. This may cause API quota issues.${NC}"
fi

# Step 7: Enable required APIs
echo -e "\n${YELLOW}Enabling required APIs for Prowler scanning...${NC}"

# Verify we have a valid project set
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ -z "$CURRENT_PROJECT" ]; then
    echo -e "${RED}✗ No project is set. Cannot enable APIs.${NC}"
    exit 1
fi

echo -e "Enabling APIs for project: ${GREEN}$CURRENT_PROJECT${NC}"

# Enable APIs with error handling
enable_api() {
    local api=$1
    local description=$2
    echo "Enabling $description..."
    if gcloud services enable "$api" --project "$CURRENT_PROJECT" 2>/dev/null; then
        echo -e "${GREEN}✓ $description enabled${NC}"
    else
        echo -e "${YELLOW}⚠ Could not enable $description${NC}"
    fi
}

enable_api "iam.googleapis.com" "Identity and Access Management (IAM) API"
enable_api "cloudresourcemanager.googleapis.com" "Cloud Resource Manager API"
enable_api "serviceusage.googleapis.com" "Service Usage API"
enable_api "logging.googleapis.com" "Cloud Logging API"
enable_api "monitoring.googleapis.com" "Cloud Monitoring API"
enable_api "compute.googleapis.com" "Compute Engine API"
enable_api "storage-api.googleapis.com" "Cloud Storage API"

# Step 8: Display current configuration
echo -e "\n${GREEN}=== Configuration Summary ===${NC}"
echo -e "Project ID: ${GREEN}$PROJECT_ID${NC}"
echo -e "Account: ${GREEN}$(gcloud config get-value account)${NC}"
echo -e "Application Default Credentials: ${GREEN}$(echo $HOME)/.config/gcloud/application_default_credentials.json${NC}"

# Step 9: Verify authentication
echo -e "\n${YELLOW}Verifying authentication...${NC}"
if gcloud auth application-default print-access-token >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Authentication successful!${NC}"
else
    echo -e "${RED}✗ Authentication verification failed. Please check your credentials.${NC}"
    exit 1
fi

# Step 10: Extract credentials for Prowler Cloud/App
echo -e "\n${YELLOW}Extracting credentials for Prowler Cloud/App...${NC}"

CREDS_FILE="$HOME/.config/gcloud/application_default_credentials.json"

if [ -f "$CREDS_FILE" ]; then
    # Extract the required values using jq or python
    if command_exists jq; then
        CLIENT_ID=$(jq -r '.client_id' "$CREDS_FILE")
        CLIENT_SECRET=$(jq -r '.client_secret' "$CREDS_FILE")
        REFRESH_TOKEN=$(jq -r '.refresh_token' "$CREDS_FILE")
    elif command_exists python3; then
        CLIENT_ID=$(python3 -c "import json; print(json.load(open('$CREDS_FILE'))['client_id'])")
        CLIENT_SECRET=$(python3 -c "import json; print(json.load(open('$CREDS_FILE'))['client_secret'])")
        REFRESH_TOKEN=$(python3 -c "import json; print(json.load(open('$CREDS_FILE'))['refresh_token'])")
    else
        echo -e "${YELLOW}jq or python3 not available. Displaying raw credentials file:${NC}"
        echo -e "${YELLOW}Please extract client_id, client_secret, and refresh_token manually:${NC}"
        cat "$CREDS_FILE"
        CLIENT_ID="<extract_manually>"
        CLIENT_SECRET="<extract_manually>"
        REFRESH_TOKEN="<extract_manually>"
    fi
    
    echo -e "\n${GREEN}=== Prowler Cloud/App Credentials ===${NC}"
    echo -e "${GREEN}Use these values in Prowler Cloud/App configuration:${NC}"
    echo -e "\nProject ID: ${YELLOW}$PROJECT_ID${NC}"
    echo -e "Client ID: ${YELLOW}$CLIENT_ID${NC}"
    echo -e "Client Secret: ${YELLOW}$CLIENT_SECRET${NC}"
    echo -e "Refresh Token: ${YELLOW}$REFRESH_TOKEN${NC}"
    
    # Save credentials to a file for easy copying
    cat > prowler-cloud-credentials.txt << EOF
=== Prowler Cloud/App Credentials ===
Project ID: $PROJECT_ID
Client ID: $CLIENT_ID
Client Secret: $CLIENT_SECRET
Refresh Token: $REFRESH_TOKEN

Instructions:
1. Go to Prowler Cloud/App
2. Navigate to Configuration > Cloud Providers
3. Click "Add Cloud Provider" and select "Google Cloud Platform"  
4. Enter the Project ID above
5. Enter the Client ID, Client Secret, and Refresh Token values above
6. Click "Next" and "Launch Scan"
EOF
    
    echo -e "\n${GREEN}✓ Credentials saved to prowler-cloud-credentials.txt${NC}"
else
    echo -e "${RED}✗ Credentials file not found at $CREDS_FILE${NC}"
fi

# Step 11: Create environment file for CLI usage
echo -e "\n${YELLOW}Creating environment configuration file for CLI usage...${NC}"
cat > prowler-gcp-env.sh << EOF
#!/bin/bash
# GCP Environment Configuration for Prowler CLI
# Source this file before running Prowler: source ./prowler-gcp-env.sh

export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
export GOOGLE_APPLICATION_CREDENTIALS="\$HOME/.config/gcloud/application_default_credentials.json"

echo "GCP environment configured for Prowler CLI:"
echo "  Project ID: \$GOOGLE_CLOUD_PROJECT"
echo "  Credentials: \$GOOGLE_APPLICATION_CREDENTIALS"
EOF

chmod +x prowler-gcp-env.sh

echo -e "${GREEN}✓ Created prowler-gcp-env.sh${NC}"

# Final instructions
echo -e "\n${GREEN}=== Setup Complete! ===${NC}"

echo -e "\n${GREEN}For Prowler Cloud/App:${NC}"
echo -e "- Copy the credentials from ${YELLOW}prowler-cloud-credentials.txt${NC}"
echo -e "- Or use the values displayed above in the Prowler Cloud/App interface"

echo -e "\n${GREEN}For Prowler CLI:${NC}"
echo -e "1. Source the environment file: ${YELLOW}source ./prowler-gcp-env.sh${NC}"
echo -e "2. Run Prowler: ${YELLOW}prowler gcp${NC}"
echo -e "\nAlternative CLI methods:"
echo -e "- With specific project: ${YELLOW}prowler gcp --project-ids $PROJECT_ID${NC}"
echo -e "- With access token: ${YELLOW}export CLOUDSDK_AUTH_ACCESS_TOKEN=\$(gcloud auth print-access-token) && prowler gcp${NC}"

echo -e "\n${YELLOW}Note:${NC} Ensure the authenticated account has the 'roles/viewer' IAM role for proper scanning."