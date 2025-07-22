#!/bin/bash

# Prowler Azure Terraform Deployment Script
set -e

echo "🔧 Prowler Azure Infrastructure Setup"
echo "======================================"

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v terraform &> /dev/null; then
    echo "❌ Terraform not found. Please install Terraform first."
    exit 1
fi

if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not found. Please install Azure CLI first."
    exit 1
fi

# Check if logged in to Azure
if ! az account show &> /dev/null; then
    echo "❌ Please log in to Azure CLI first: az login"
    exit 1
fi

echo "✅ Prerequisites met"

# Check for terraform.tfvars
if [[ ! -f "terraform.tfvars" ]]; then
    echo "❌ terraform.tfvars not found."
    echo "Please copy terraform.tfvars.example to terraform.tfvars and customize it with your subscription IDs."
    echo "Example:"
    echo "  cp terraform.tfvars.example terraform.tfvars"
    echo "  # Edit terraform.tfvars with your subscription IDs"
    exit 1
fi

# Display current Azure context
echo ""
echo "🔍 Current Azure Context:"
az account show --output table

echo ""
read -p "Continue with this Azure account? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

# Initialize Terraform
echo ""
echo "🚀 Initializing Terraform..."
terraform init

# Plan deployment
echo ""
echo "📋 Planning deployment..."
terraform plan -out=tfplan

echo ""
read -p "Apply this plan? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

# Apply deployment
echo ""
echo "🚀 Applying deployment..."
terraform apply tfplan

# Display outputs
echo ""
echo "✅ Deployment completed!"
echo ""
echo "📋 Prowler Configuration:"
terraform output prowler_env_commands

echo ""
echo "🔐 Security Note:"
echo "The client secret has been created and displayed above."
echo "Store it securely as it won't be shown again."
echo ""
echo "🎉 Prowler is now configured! You can run security scans with:"
echo "   prowler azure --sp-env-auth"