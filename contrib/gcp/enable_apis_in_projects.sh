#!/bin/bash

# List of project IDs
PROJECT_IDS=(
    "project-id-1"
    "project-id-2"
    "project-id-3"
    # Add more project IDs as needed
)

# List of Prowler APIs to enable
APIS=(
    "apikeys.googleapis.com"
    "artifactregistry.googleapis.com"
    "bigquery.googleapis.com"
    "sqladmin.googleapis.com"  # Cloud SQL
    "storage.googleapis.com"  # Cloud Storage
    "compute.googleapis.com"
    "dataproc.googleapis.com"
    "dns.googleapis.com"
    "containerregistry.googleapis.com"  # GCR (Google Container Registry)
    "container.googleapis.com"  # GKE (Google Kubernetes Engine)
    "iam.googleapis.com"
    "cloudkms.googleapis.com"  # KMS (Key Management Service)
    "logging.googleapis.com"
)

# Function to enable APIs for a given project
enable_apis_for_project() {
    local PROJECT_ID=$1

    echo "Enabling APIs for project: ${PROJECT_ID}"

    for API in "${APIS[@]}"; do
        echo "Enabling API: $API for project: ${PROJECT_ID}"
        if gcloud services enable "${API}" --project="${PROJECT_ID}"; then
            echo "Successfully enabled API $API for project ${PROJECT_ID}."
        else
            echo "Failed to enable API $API for project ${PROJECT_ID}."
        fi
    done
}

# Loop over each project and enable the APIs
for PROJECT_ID in "${PROJECT_IDS[@]}"; do
    enable_apis_for_project "${PROJECT_ID}"
done
