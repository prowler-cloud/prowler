#!/bin/bash
# GCP Environment Configuration for Prowler CLI
# Source this file before running Prowler: source ./prowler-gcp-env.sh

export GOOGLE_CLOUD_PROJECT="prowlertest-466917"
export GOOGLE_APPLICATION_CREDENTIALS="$HOME/.config/gcloud/application_default_credentials.json"

echo "GCP environment configured for Prowler CLI:"
echo "  Project ID: $GOOGLE_CLOUD_PROJECT"
echo "  Credentials: $GOOGLE_APPLICATION_CREDENTIALS"
