# MongoDB Atlas Provider for Prowler

The MongoDB Atlas provider enables Prowler to perform security assessments of MongoDB Atlas cloud database deployments.

## Features

- **Authentication**: Supports MongoDB Atlas API key authentication
- **Services**: Projects and Clusters services
- **Checks**: Network access security and encryption at rest validation
- **Pagination**: Handles large numbers of resources efficiently
- **Error Handling**: Comprehensive error handling and retry logic

## Authentication

The MongoDB Atlas provider uses HTTP Digest Authentication with API key pairs consisting of a public key and private key.

### Authentication Methods

1. **Command-line arguments**:
   ```bash
   prowler mongodbatlas --atlas-public-key <public_key> --atlas-private-key <private_key>
   ```

2. **Environment variables**:
   ```bash
   export ATLAS_PUBLIC_KEY=<public_key>
   export ATLAS_PRIVATE_KEY=<private_key>
   prowler mongodbatlas
   ```

### Creating API Keys

1. Log into MongoDB Atlas
2. Navigate to Access Manager
3. Select "API Keys" tab
4. Click "Create API Key"
5. Set permissions (Project permissions recommended)
6. Note the public key and private key

## Configuration Options

- `--atlas-organization-id`: Filter results to specific organization
- `--atlas-project-id`: Filter results to specific project

## Services

### Projects Service

Manages MongoDB Atlas projects (groups) and their configurations:

- Lists all projects or filters by organization/project ID
- Retrieves network access lists
- Counts clusters per project
- Fetches project settings

### Clusters Service

Manages MongoDB Atlas clusters:

- Lists all clusters across projects
- Retrieves cluster configuration details
- Checks encryption settings
- Validates backup configurations

## Security Checks

### Network Access List Security

**Check**: `projects_network_access_list_not_open_to_world`

Ensures that MongoDB Atlas projects don't have network access entries that allow unrestricted access from the internet.

- **Severity**: High
- **Fails if**:
  - Network access list contains `0.0.0.0/0` or `::/0`
  - IP addresses like `0.0.0.0` or `::`
  - No network access entries are configured

### Encryption at Rest

**Check**: `clusters_encryption_at_rest_enabled`

Verifies that MongoDB Atlas clusters have encryption at rest enabled to protect data stored on disk.

- **Severity**: High
- **Fails if**:
  - Encryption at rest is explicitly disabled (`NONE`)
  - No encryption provider is configured
  - Unsupported encryption provider is used
- **Passes if**:
  - Valid encryption provider (AWS, AZURE, GCP)
  - EBS volume encryption is enabled
  - Cluster is paused (skipped)

## Usage Examples

### Basic Usage

```bash
# Scan all projects and clusters
prowler mongodbatlas --atlas-public-key <key> --atlas-private-key <secret>

# Scan specific organization
prowler mongodbatlas --atlas-organization-id <org_id>

# Scan specific project
prowler mongodbatlas --atlas-project-id <project_id>
```

### With Filters

```bash
# Run only network access checks
prowler mongodbatlas --checks projects_network_access_list_not_open_to_world

# Run only encryption checks
prowler mongodbatlas --checks clusters_encryption_at_rest_enabled

# Run checks for specific service
prowler mongodbatlas --services projects
```

## Error Handling

The provider includes comprehensive error handling:

- **Rate Limiting**: Automatic retry with exponential backoff
- **Authentication Errors**: Clear error messages for invalid credentials
- **API Errors**: Detailed error reporting for API failures
- **Network Errors**: Retry logic for transient network issues

## Configuration

### API Settings

- **Base URL**: `https://cloud.mongodb.com/api/atlas/v2`
- **API Version**: `2025-01-01`
- **Default Timeout**: 30 seconds
- **Default Page Size**: 100 items
- **Max Retries**: 3 attempts

### Rate Limiting

The provider respects MongoDB Atlas API rate limits:

- Automatic retry on 429 (Too Many Requests)
- Exponential backoff starting at 1 second
- Maximum of 3 retry attempts

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Verify API key permissions
   - Check if API key is enabled
   - Ensure IP address is in access list

2. **No Resources Found**:
   - Check organization/project ID filters
   - Verify API key has access to resources
   - Ensure resources exist in MongoDB Atlas

3. **Rate Limit Errors**:
   - Reduce concurrent requests
   - Increase retry delays
   - Contact MongoDB Atlas support for rate limit increases

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
prowler mongodbatlas --log-level DEBUG
```

## Contributing

When contributing to the MongoDB Atlas provider:

1. Follow existing code patterns
2. Add comprehensive tests for new checks
3. Update documentation for new features
4. Ensure error handling is consistent
5. Test with various MongoDB Atlas configurations

## Security Considerations

- Store API keys securely (use environment variables)
- Limit API key permissions to required resources
- Regularly rotate API keys
- Monitor API key usage in MongoDB Atlas
- Use network access lists to restrict API access

## Support

For issues specific to the MongoDB Atlas provider, please refer to:

- MongoDB Atlas API Documentation
- Prowler GitHub Issues
- MongoDB Atlas Support (for API-related issues)

## License

This provider is part of Prowler and follows the same license terms.
