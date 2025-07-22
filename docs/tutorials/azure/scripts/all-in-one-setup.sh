#!/bin/bash

# All-in-one setup script for Prowler Azure authentication
# This script handles:
# 1. Installation of Azure CLI (if needed)
# 2. Installation of jq (if needed)
# 3. Azure login (if needed)
# 4. Complete Prowler Azure authentication setup

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler for Azure - Complete Setup (All-in-One)     ${NC}"
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo

# Check operating system
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Windows;;
    MINGW*)     MACHINE=Windows;;
    *)          MACHINE="UNKNOWN"
esac

echo -e "${BLUE}${BOLD}Step 1: Checking and installing prerequisites...${NC}"

# Check and install Azure CLI if needed
if ! command -v az &> /dev/null; then
    echo -e "${YELLOW}Azure CLI not found. Installing...${NC}"
    
    case "${MACHINE}" in
        Mac)
            # Install Homebrew if needed
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew update && brew install azure-cli
            ;;
        Linux)
            # For Ubuntu/Debian
            if command -v apt-get &> /dev/null; then
                echo -e "${YELLOW}Installing on Debian/Ubuntu-based system...${NC}"
                curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
            # For RHEL/CentOS/Fedora
            elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
                echo -e "${YELLOW}Installing on RHEL/CentOS/Fedora-based system...${NC}"
                sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                echo -e "[azure-cli]\nname=Azure CLI\nbaseurl=https://packages.microsoft.com/yumrepos/azure-cli\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" | sudo tee /etc/yum.repos.d/azure-cli.repo
                if command -v dnf &> /dev/null; then
                    sudo dnf install azure-cli -y
                else
                    sudo yum install azure-cli -y
                fi
            else
                echo -e "${RED}Unsupported Linux distribution. Please install Azure CLI manually:${NC}"
                echo -e "${BLUE}https://docs.microsoft.com/en-us/cli/azure/install-azure-cli${NC}"
                exit 1
            fi
            ;;
        Windows)
            echo -e "${RED}For Windows, please install Azure CLI manually:${NC}"
            echo -e "${BLUE}https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows${NC}"
            echo "After installation, restart this script."
            exit 1
            ;;
        *)
            echo -e "${RED}Unsupported operating system. Please install Azure CLI manually:${NC}"
            echo -e "${BLUE}https://docs.microsoft.com/en-us/cli/azure/install-azure-cli${NC}"
            exit 1
            ;;
    esac
    
    # Verify installation was successful
    if ! command -v az &> /dev/null; then
        echo -e "${RED}Azure CLI installation failed. Please install manually:${NC}"
        echo -e "${BLUE}https://docs.microsoft.com/en-us/cli/azure/install-azure-cli${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Azure CLI installed successfully!${NC}"
else
    echo -e "${GREEN}Azure CLI is already installed.${NC}"
fi

# Check and install jq if needed
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}jq not found. Installing...${NC}"
    
    case "${MACHINE}" in
        Mac)
            if command -v brew &> /dev/null; then
                brew install jq
            else
                echo -e "${RED}Homebrew not found. Please install jq manually.${NC}"
                exit 1
            fi
            ;;
        Linux)
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y jq
            elif command -v yum &> /dev/null; then
                sudo yum install -y jq
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y jq
            else
                echo -e "${RED}Unsupported Linux distribution. Please install jq manually.${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Please install jq manually for your operating system.${NC}"
            exit 1
            ;;
    esac
    
    # Verify installation was successful
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}jq installation failed. Please install manually.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}jq installed successfully!${NC}"
else
    echo -e "${GREEN}jq is already installed.${NC}"
fi

# Check if logged in to Azure
echo -e "${YELLOW}Checking Azure login...${NC}"
AZURE_ACCOUNT=$(az account show 2>/dev/null)
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Not logged in to Azure. Please log in:${NC}"
    az login
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to log in to Azure. Please try again.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}${BOLD}Prerequisites check completed successfully!${NC}"
echo

# Now run the actual setup script
echo -e "${BLUE}${BOLD}Step 2: Setting up Prowler for Azure...${NC}"
echo

# Current directory
CURRENT_DIR=$(pwd)

# Check if we're in the right directory
if [[ "$CURRENT_DIR" != *"/prowler/docs/tutorials/azure/scripts"* ]]; then
    echo -e "${YELLOW}Not in the expected directory. Trying to find setup-prowler.sh...${NC}"
    
    # Try to find the setup script relative to this script first
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
    if [ -f "$SCRIPT_DIR/setup-prowler.sh" ]; then
        echo -e "${GREEN}Found setup-prowler.sh in the same directory as this script.${NC}"
        cd "$SCRIPT_DIR"
    else
        # Try to find from current location recursively down
        SCRIPT_PATH=$(find . -name "setup-prowler.sh" -type f 2>/dev/null | head -n 1)
        
        if [ -z "$SCRIPT_PATH" ]; then
            # If not found, try the absolute path as a last resort (might be slow)
            echo -e "${YELLOW}Searching for setup-prowler.sh in repository...${NC}"
            SCRIPT_PATH=$(find / -path "*/prowler/docs/tutorials/azure/scripts/setup-prowler.sh" -type f 2>/dev/null | head -n 1)
        fi
        
        if [ -z "$SCRIPT_PATH" ]; then
            echo -e "${RED}Could not find the setup-prowler.sh script.${NC}"
            echo "Please navigate to the prowler/docs/tutorials/azure/scripts directory and run this script again."
            exit 1
        else
            echo -e "${GREEN}Found setup script at: $SCRIPT_PATH${NC}"
            SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
            cd "$SCRIPT_DIR"
        fi
    fi
fi

# Make the setup script executable if it's not already
chmod +x setup-prowler.sh

# Execute the actual setup script
./setup-prowler.sh

SETUP_RESULT=$?
if [ $SETUP_RESULT -ne 0 ]; then
    echo -e "${RED}${BOLD}Prowler setup encountered an error (code $SETUP_RESULT).${NC}"
    echo -e "${YELLOW}Please check the error messages above and try again.${NC}"
    exit $SETUP_RESULT
fi

# Check if prowler-config.env was created
if [ -f "prowler-config.env" ]; then
    echo
    echo -e "${BLUE}${BOLD}=======================================================${NC}"
    echo -e "${GREEN}${BOLD}Setup completed successfully!${NC}"
    echo -e "${BLUE}${BOLD}=======================================================${NC}"
    echo
    echo -e "${BLUE}${BOLD}Prowler App Integration:${NC}"
    echo -e "${YELLOW}1. Open the Prowler App${NC}"
    echo -e "${YELLOW}2. Go to Configuration > Cloud Providers > Add Cloud Provider > Microsoft Azure${NC}"
    echo -e "${YELLOW}3. Enter the following credentials:${NC}"
    
    # Extract values from environment file
    CLIENT_ID=$(grep AZURE_CLIENT_ID prowler-config.env | cut -d'"' -f2)
    CLIENT_SECRET=$(grep AZURE_CLIENT_SECRET prowler-config.env | cut -d'"' -f2)
    TENANT_ID=$(grep AZURE_TENANT_ID prowler-config.env | cut -d'"' -f2)
    
    echo -e "${GREEN}   Client ID:     ${BOLD}$CLIENT_ID${NC}"
    echo -e "${GREEN}   Client Secret: ${BOLD}$CLIENT_SECRET${NC}"
    echo -e "${GREEN}   Tenant ID:     ${BOLD}$TENANT_ID${NC}"
    echo
    echo -e "${YELLOW}4. Click Next and complete the Prowler App setup${NC}"
    echo
    echo -e "${BLUE}${BOLD}Command Line Usage:${NC}"
    echo -e "${YELLOW}Run these commands to use Prowler CLI:${NC}"
    echo -e "${GREEN}source prowler-config.env${NC}"
    echo -e "${GREEN}prowler azure --sp-env-auth${NC}"
    echo
    echo -e "${BLUE}${BOLD}=======================================================${NC}"
else
    echo -e "${RED}${BOLD}Could not find prowler-config.env file after setup.${NC}"
    echo -e "${YELLOW}The setup might have encountered an issue. Please check the messages above.${NC}"
    exit 1
fi