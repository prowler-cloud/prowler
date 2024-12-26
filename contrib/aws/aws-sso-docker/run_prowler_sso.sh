#!/bin/bash
set -e

# Set the profile name
PROFILE="twodragon"

# Set the Prowler output directory
OUTPUT_DIR=~/prowler-output
mkdir -p "$OUTPUT_DIR"

# Set the port for the local web server
WEB_SERVER_PORT=8000

# ----------------------------------------------
# Functions
# ----------------------------------------------

# Function to open the HTML report in the default browser
open_report() {
    local report_path="$1"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$report_path"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$report_path"
    elif [[ "$OSTYPE" == "msys" ]]; then
        start "" "$report_path"
    else
        echo "Automatic method to open Prowler HTML report is not supported on this OS."
        echo "Please open the report manually at: $report_path"
    fi
}

# Function to start a simple HTTP server to host the Prowler reports
start_web_server() {
    local directory="$1"
    local port="$2"

    echo "Starting local web server to host Prowler reports at http://localhost:$port"
    echo "Press Ctrl+C to stop the web server."

    # Change to the output directory
    cd "$directory"

    # Start the HTTP server in the foreground
    # Python 3 is required
    python3 -m http.server "$port"
}

# ----------------------------------------------
# Main Script
# ----------------------------------------------

# AWS SSO Login
echo "Logging into AWS SSO..."
aws sso login --profile "$PROFILE"

# Extract temporary credentials
echo "Extracting temporary credentials..."

# Find the most recently modified SSO cache file
CACHE_FILE=$(ls -t ~/.aws/sso/cache/*.json 2>/dev/null | head -n 1)
echo "Cache File: $CACHE_FILE"

if [ -z "$CACHE_FILE" ]; then
    echo "SSO cache file not found. Please ensure AWS SSO login was successful."
    exit 1
fi

# Extract accessToken using jq
ACCESS_TOKEN=$(jq -r '.accessToken' "$CACHE_FILE")
echo "Access Token: $ACCESS_TOKEN"

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo "Unable to extract accessToken. Please check your SSO login and cache file."
    exit 1
fi

# Extract role name and account ID from AWS CLI configuration
ROLE_NAME=$(aws configure get sso_role_name --profile "$PROFILE")
ACCOUNT_ID=$(aws configure get sso_account_id --profile "$PROFILE")
echo "Role Name: $ROLE_NAME"
echo "Account ID: $ACCOUNT_ID"

if [ -z "$ROLE_NAME" ] || [ -z "$ACCOUNT_ID" ]; then
    echo "Unable to extract sso_role_name or sso_account_id. Please check your profile configuration."
    exit 1
fi

# Obtain temporary credentials using AWS SSO
TEMP_CREDS=$(aws sso get-role-credentials \
    --role-name "$ROLE_NAME" \
    --account-id "$ACCOUNT_ID" \
    --access-token "$ACCESS_TOKEN" \
    --profile "$PROFILE")

echo "TEMP_CREDS: $TEMP_CREDS"

# Extract credentials from the JSON response
AWS_ACCESS_KEY_ID=$(echo "$TEMP_CREDS" | jq -r '.roleCredentials.accessKeyId')
AWS_SECRET_ACCESS_KEY=$(echo "$TEMP_CREDS" | jq -r '.roleCredentials.secretAccessKey')
AWS_SESSION_TOKEN=$(echo "$TEMP_CREDS" | jq -r '.roleCredentials.sessionToken')

# Verify that all credentials were extracted successfully
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ -z "$AWS_SESSION_TOKEN" ]; then
    echo "Unable to extract temporary credentials."
    exit 1
fi

# Export AWS credentials as environment variables
export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_SESSION_TOKEN

echo "AWS credentials have been set."

# Run Prowler in Docker container
echo "Running Prowler Docker container..."

docker run --platform linux/amd64 \
    -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
    -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    -e AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN" \
    -v "$OUTPUT_DIR":/home/prowler/output \
    toniblyx/prowler -M html -M csv -M json-ocsf --output-directory /home/prowler/output --output-filename prowler-output

echo "Prowler has finished running. Reports are saved in $OUTPUT_DIR."

# Open the HTML report in the default browser
REPORT_PATH="$OUTPUT_DIR/prowler-output.html"
echo "Opening Prowler HTML report..."
open_report "$REPORT_PATH" &

# Start the local web server to host the Prowler dashboard
# This will run in the foreground. To run it in the background, append an ampersand (&) at the end of the command.
start_web_server "$OUTPUT_DIR" "$WEB_SERVER_PORT"
