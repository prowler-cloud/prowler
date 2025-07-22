#!/bin/bash

# All-in-one setup script for Prowler Azure authentication - Multiple Subscriptions Version
# This script handles:
# 1. Installation of Azure CLI (if needed)
# 2. Installation of jq (if needed)
# 3. Azure login (if needed)
# 4. Complete Prowler Azure authentication setup for multiple subscriptions

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo -e "${BLUE}${BOLD}   Prowler for Azure - Complete Setup (Multi-Sub)      ${NC}"
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

# Now run the multi-subscription setup script
echo -e "${BLUE}${BOLD}Step 2: Setting up Prowler for Azure (Multiple Subscriptions)...${NC}"
echo

# Current directory
CURRENT_DIR=$(pwd)

# Find the setup script
MULTI_SUB_SCRIPT="multi-subscription-setup.sh"

# Check if script exists in current directory
if [ -f "$MULTI_SUB_SCRIPT" ]; then
    chmod +x "$MULTI_SUB_SCRIPT"
    ./"$MULTI_SUB_SCRIPT"
else
    # Try to find from current location
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
    if [ -f "$SCRIPT_DIR/$MULTI_SUB_SCRIPT" ]; then
        echo -e "${GREEN}Found $MULTI_SUB_SCRIPT in the same directory as this script.${NC}"
        chmod +x "$SCRIPT_DIR/$MULTI_SUB_SCRIPT"
        "$SCRIPT_DIR/$MULTI_SUB_SCRIPT"
    else
        # Try to find the script relative to this script
        SCRIPT_PATH=$(find . -name "$MULTI_SUB_SCRIPT" -type f 2>/dev/null | head -n 1)
        
        if [ -z "$SCRIPT_PATH" ]; then
            # If not found locally, try searching in the repository
            SCRIPT_PATH=$(find / -path "*/prowler/docs/tutorials/azure/scripts/$MULTI_SUB_SCRIPT" -type f 2>/dev/null | head -n 1)
        fi
        
        if [ -z "$SCRIPT_PATH" ]; then
            # As a last resort, download the script
            echo -e "${YELLOW}Could not find $MULTI_SUB_SCRIPT locally. Downloading...${NC}"
            curl -s -o "$MULTI_SUB_SCRIPT" "https://raw.githubusercontent.com/kourosh-forti-hands/prowler/master/docs/tutorials/azure/scripts/$MULTI_SUB_SCRIPT"
            
            if [ ! -f "$MULTI_SUB_SCRIPT" ]; then
                echo -e "${RED}Failed to download the setup script.${NC}"
                exit 1
            fi
            
            chmod +x "$MULTI_SUB_SCRIPT"
            ./"$MULTI_SUB_SCRIPT"
        else
            echo -e "${GREEN}Found setup script at: $SCRIPT_PATH${NC}"
            chmod +x "$SCRIPT_PATH"
            "$SCRIPT_PATH"
        fi
    fi
fi

echo -e "${BLUE}${BOLD}=======================================================${NC}"
echo -e "${GREEN}${BOLD}All-in-one setup complete!${NC}"
echo -e "${BLUE}${BOLD}=======================================================${NC}"