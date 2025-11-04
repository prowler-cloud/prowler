# IONOS Cloud Provider for Prowler

This document describes the implementation and configuration of the IONOS Cloud provider for Prowler.

## Overview

The IONOS Cloud provider allows Prowler to perform security assessments on IONOS Cloud infrastructure. It interacts with the IONOS Cloud API to gather information about your resources and evaluate their security configuration.

## Authentication Methods

The provider supports multiple authentication methods:

1. **ionosctl Configuration**:
    - The provider automatically reads credentials from the ionosctl configuration file:
      - MacOS: `~/Library/Application Support/ionosctl/config.json`
      - Linux: `~/.config/ionosctl/config.json`
      - Windows: `%APPDATA%/ionosctl/config.json`
      - WSL: `/mnt/c/Users/<USER>/AppData/Roaming/ionosctl/config.json`

2. **user and password**:
    - Use user and password parameters to authenticate if ionosctl configuration is not available
        - `--ionos-username`
        - `--ionos-password`

## Provider Configuration

### Configuration Options

- `ionos_username`: IONOS Cloud username
- `ionos_password`: IONOS Cloud password
- `ionos_datacenter_name`: Name of the datacenter to assess (optional), if not provided, first datacenter will be scanned
- `mutelist_path`: Path to mutelist file
- `mutelist_content`: Dictionary containing mutelist configuration

## Features

- Automatic credential discovery from environment variables and ionosctl
- Support for multiple platforms (Linux, MacOS, Windows, WSL)
- Datacenter management and selection
- Mutelist support for excluding specific checks
- Detailed logging and error handling

## Services implemented

- Compute Engine / Servers IONOS Cloud
- Object Storage (Buckets S3)

## Checks Available

- Server
    - Server Public IP: check presence of public IP addresses in servers for potential exposure 
    - Server Volume Snapshots Exists: verify if servers have volume snapshots for backup and recovery
    - Server Firewall Allow Ingress From Internet To TCP FTP Port 20 21: check if FTP ports are exposed to the internet
    - Server Firewall Allow Ingress From Internet To TCP SSH Port 22: identify if SSH port is accessible from the internet

- Object Storage
    - Object Storage Bucket Public Access: detect publicly accessible S3-compatible storage buckets

## Mutelist Configuration

The provider supports muting specific checks using a mutelist file:

```json
{
     "muted_checks": [
          "check_id_1",
          "check_id_2"
     ]
}
```

## Dependencies

- `ionoscloud`: IONOS Cloud Python SDK
- `prowler`: Core Prowler libraries

## Error Handling

The provider implements comprehensive error handling for:
- API authentication failures
- Connection issues
- Configuration file errors
- Missing credentials
- Invalid datacenter selection

## Logging

The provider uses Prowler's logging system to provide detailed information about:
- Initialization status
- Credential loading
- API connections
- Error conditions
