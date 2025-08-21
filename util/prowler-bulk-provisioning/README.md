# Prowler Provider Bulk Provisioning

A Python script to bulk-provision cloud providers in Prowler Cloud/App via REST API. This tool streamlines the process of adding multiple cloud providers to Prowler by reading configuration from YAML, JSON, or CSV files and making API calls with concurrency and retry support.

## Supported Providers

- **AWS** (Amazon Web Services)
- **Azure** (Microsoft Azure)
- **GCP** (Google Cloud Platform)
- **Kubernetes**
- **M365** (Microsoft 365)
- **GitHub**

## Features

- **Multiple Input Formats:** Supports YAML, JSON, and CSV input files
- **Concurrent Processing:** Configurable concurrency for faster bulk operations
- **Retry Logic:** Built-in retry mechanism for handling temporary API failures
- **Dry-Run Mode:** Test configuration without making actual API calls
- **Flexible Authentication:** Supports various authentication methods per provider
- **Error Handling:** Comprehensive error reporting and validation
- **Connection Testing:** Built-in provider connection verification

## How It Works

The script uses a two-step process to provision providers in Prowler:

1. **Provider Creation:** Creates the provider with basic information (provider type, UID, alias)
2. **Secret Creation:** Creates and links authentication credentials as a separate secret resource

This two-step approach follows the Prowler API design where providers and their credentials are managed as separate but linked resources, providing better security and flexibility.

## Installation

### Requirements

- Python 3.7 or higher
- Required packages (install via requirements.txt)

### Setup

1. Clone or navigate to the Prowler repository:
   ```bash
   cd contrib/other-contrib/provider-bulk-importer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Get your Prowler API token:
   - **Prowler Cloud:** Generate token at https://api.prowler.com
   - **Self-hosted Prowler App:** Generate token in your local instance

  ```bash
  export PROWLER_API_TOKEN=$(curl --location 'https://api.prowler.com/api/v1/tokens' \
    --header 'Content-Type: application/vnd.api+json' \
    --header 'Accept: application/vnd.api+json' \
    --data-raw '{
      "data": {
        "type": "tokens",
        "attributes": {
          "email": "your@email.com",
          "password": "your-password"
        }
      }
    }' | jq -r .data.attributes.access)
  ```


## Configuration

### Environment Variables

```bash
export PROWLER_API_TOKEN="your-prowler-token"
export PROWLER_API_BASE="https://api.prowler.com/api/v1"  # Optional, defaults to SaaS
```

### Provider Configuration Files

Create a configuration file (YAML recommended) listing the providers to add:

#### YAML Format (Recommended)

```yaml
# providers.yaml
- provider: aws
  uid: "123456789012"              # AWS Account ID
  alias: "prod-root"
  auth_method: role                # role | credentials
  credentials:
    role_arn: "arn:aws:iam::123456789012:role/ProwlerScan"
    external_id: "ext-abc123"      # optional
    session_name: "prowler-bulk"   # optional
    duration_seconds: 3600         # optional

- provider: aws
  uid: "210987654321"
  alias: "dev"
  auth_method: credentials         # long/short-lived keys
  credentials:
    access_key_id: "AKIA..."
    secret_access_key: "..."
    session_token: "..."           # optional

- provider: azure
  uid: "00000000-1111-2222-3333-444444444444" # Subscription ID
  alias: "sub-eastus"
  auth_method: service_principal
  credentials:
    tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    client_id: "ffffffff-1111-2222-3333-444444444444"
    client_secret: "..."

- provider: gcp
  uid: "my-gcp-project-id"         # Project ID
  alias: "gcp-prod"
  auth_method: service_account     # Service Account authentication
  credentials:
    service_account_key_json_path: "./gcp-key.json"

- provider: kubernetes
  uid: "my-eks-context"            # kubeconfig context name
  alias: "eks-prod"
  auth_method: kubeconfig
  credentials:
    kubeconfig_path: "~/.kube/config"

- provider: m365
  uid: "contoso.onmicrosoft.com"   # Domain ID
  alias: "contoso"
  auth_method: service_principal
  credentials:
    tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    client_id: "ffffffff-1111-2222-3333-444444444444"
    client_secret: "..."

- provider: github
  uid: "my-org"                    # organization or username
  alias: "gh-org"
  auth_method: personal_access_token  # oauth_app_token | github_app
  credentials:
    token: "ghp_..."
```

#### JSON Format

```json
[
  {
    "provider": "aws",
    "uid": "123456789012",
    "alias": "prod-root",
    "auth_method": "role",
    "credentials": {
      "role_arn": "arn:aws:iam::123456789012:role/ProwlerScan",
      "external_id": "ext-abc123"
    }
  }
]
```

#### CSV Format

```csv
provider,uid,alias,auth_method,credentials
aws,123456789012,prod-root,role,"{\"role_arn\": \"arn:aws:iam::123456789012:role/ProwlerScan\"}"
```

## Usage

### Basic Usage

```bash
python prowler_bulk_provisioning.py providers.yaml
```

### Advanced Usage

```bash
python prowler_bulk_provisioning.py providers.yaml \
  --base-url https://api.prowler.com/api/v1 \
  --providers-endpoint /providers \
  --concurrency 6 \
  --timeout 120
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `input_file` | YAML/JSON/CSV file with provider entries | Required |
| `--base-url` | API base URL | `https://api.prowler.com/api/v1` |
| `--token` | Bearer token | `PROWLER_API_TOKEN` env var |
| `--providers-endpoint` | Providers API endpoint | `/providers` |
| `--concurrency` | Number of concurrent requests | `5` |
| `--timeout` | Per-request timeout in seconds | `60` |
| `--insecure` | Disable TLS verification | `False` |
| `--dry-run` | Print payloads without sending | `False` |
| `--test-provider` | Test connection after creating each provider (true/false) | `true` (enabled by default) |
| `--test-provider-only` | Only test connections for existing providers (skip creation) | `False` |

### Self-hosted Prowler App

For self-hosted installations:

```bash
python prowler_bulk_provisioning.py providers.yaml \
  --base-url http://localhost:8080/api/v1
```

## Provider-Specific Configuration

### AWS Authentication Methods

#### IAM Role (Recommended)
```yaml
- provider: aws
  uid: "123456789012"
  alias: "prod"
  auth_method: role
  credentials:
    role_arn: "arn:aws:iam::123456789012:role/ProwlerScan"
    external_id: "optional-external-id"
```

#### Access Keys
```yaml
- provider: aws
  uid: "123456789012"
  alias: "dev"
  auth_method: credentials
  credentials:
    access_key_id: "AKIA..."
    secret_access_key: "..."
    session_token: "..."  # optional for temporary credentials
```

### Azure Authentication

```yaml
- provider: azure
  uid: "subscription-uuid"
  alias: "azure-prod"
  auth_method: service_principal
  credentials:
    tenant_id: "tenant-uuid"
    client_id: "client-uuid"
    client_secret: "client-secret"
```

### GCP Authentication

The Prowler API supports the following authentication methods for GCP:

#### Method 1: Service Account JSON (Recommended)
```yaml
- provider: gcp
  uid: "project-id"
  alias: "gcp-prod"
  auth_method: service_account  # or 'service_account_json'
  credentials:
    service_account_key_json_path: "/path/to/key.json"
    # OR inline:
    # inline_json:
    #   type: "service_account"
    #   project_id: "your-project"
    #   private_key_id: "key-id"
    #   private_key: "-----BEGIN PRIVATE KEY-----\n..."
    #   client_email: "service-account@project.iam.gserviceaccount.com"
    #   client_id: "1234567890"
    #   auth_uri: "https://accounts.google.com/o/oauth2/auth"
    #   token_uri: "https://oauth2.googleapis.com/token"
    #   auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs"
    #   client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/..."
```

#### Method 2: OAuth2 Credentials
```yaml
- provider: gcp
  uid: "project-id"
  alias: "gcp-prod"
  auth_method: oauth2  # or 'adc' for Application Default Credentials
  credentials:
    client_id: "123456789012345678901.apps.googleusercontent.com"
    client_secret: "GOCSPX-xxxxxxxxxxxxxxxxx"
    refresh_token: "1//0exxxxxxxxxxxxxxxxx"
```

### Kubernetes Authentication

```yaml
- provider: kubernetes
  uid: "context-name"
  alias: "k8s-prod"
  auth_method: kubeconfig
  credentials:
    kubeconfig_path: "~/.kube/config"
    # OR
    # kubeconfig_inline: |
    #   apiVersion: v1
    #   clusters: ...
```

### Microsoft 365 Authentication

```yaml
- provider: m365
  uid: "domain.onmicrosoft.com"
  alias: "m365-tenant"
  auth_method: service_principal
  credentials:
    tenant_id: "tenant-uuid"
    client_id: "client-uuid"
    client_secret: "client-secret"
```

### GitHub Authentication

#### Personal Access Token
```yaml
- provider: github
  uid: "organization-name"
  alias: "gh-org"
  auth_method: personal_access_token
  credentials:
    token: "ghp_..."
```

#### GitHub App
```yaml
- provider: github
  uid: "organization-name"
  alias: "gh-org"
  auth_method: github_app
  credentials:
    app_id: "123456"
    private_key_path: "/path/to/private-key.pem"
    # OR
    # private_key_inline: "-----BEGIN RSA PRIVATE KEY-----\n..."
```

## Connection Testing

The script includes built-in connection testing to verify that providers can successfully authenticate with their respective cloud services.

By default, the script tests connections immediately after creating providers:

```bash
python prowler_bulk_provisioning.py providers.yaml
```

This will:
1. Create the provider
2. Add credentials
3. Test the connection
4. Report connection status

To skip connection testing, use:

```bash
python prowler_bulk_provisioning.py providers.yaml --test-provider false
```

### Test Existing Providers

Test connections for already existing providers without creating new ones:

```bash
python prowler_bulk_provisioning.py providers.yaml --test-provider-only
```

This is useful for:
- Verifying existing provider configurations
- Debugging authentication issues
- Regular connection health checks
- Testing after credential updates

### Example Output

```
[1] ✅ Created provider (id=db9a8985-f9ec-4dd8-b5a0-e05ab3880bed)
[1] ✅ Created secret (id=466f76c6-5878-4602-a4bc-13f9522c1fd2)
[1] ✅ Connection test: Connected

[2] ✅ Created provider (id=7a99f789-0cf5-4329-8279-2d443a962676)
[2] ✅ Created secret (id=c5702180-f7c4-40fd-be0e-f6433479b126)
[2] ❌ Connection test: Not connected
```

## Advanced Features

### Dry Run Mode

Test your configuration without making API calls:

```bash
python prowler_bulk_provisioning.py providers.yaml --dry-run
```

## Troubleshooting

### Common Issues

1. **Invalid API Token**
   ```
   Error: 401 Unauthorized
   Solution: Check your PROWLER_API_TOKEN or --token parameter
   ```

2. **Network Timeouts**
   ```
   Error: Request timeout
   Solution: Increase --timeout value or check network connectivity
   ```

3. **Invalid Provider Configuration**
   ```
   Error: Each item must include 'provider' and 'uid'
   Solution: Verify all required fields are present in your config file
   ```

4. **File Not Found Errors**
   ```
   Error: No such file or directory
   Solution: Check file paths for credentials files (JSON keys, kubeconfig, etc.)
   ```

## Examples

See the `examples/` directory for sample configuration files:

- `examples/simple-providers.yaml` - Basic example with minimal configuration

## Support

For issues and questions:

1. Check the [Prowler documentation](https://docs.prowler.com)
2. Review the [API documentation](https://api.prowler.com/api/v1/docs)
3. Open an issue in the [Prowler repository](https://github.com/prowler-cloud/prowler)

## License

This tool is part of the Prowler project and follows the same licensing terms.
