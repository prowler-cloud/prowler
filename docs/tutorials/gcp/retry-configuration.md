# GCP Retry Configuration in Prowler

Prowler's GCP Provider leverages Google Cloud Python SDK's integrated retry mechanism to automatically retry client calls to Google Cloud services when encountering rate limiting errors or quota exceeded exceptions.

## Retry Behavior Overview

Prowler's GCP retry mechanism uses the built-in retry functionality of the Google Cloud Python SDK:

- **Maximum Retry Attempts**: Default value set to 3 attempts (configurable in `config.py`)
- **Exponential Backoff Strategy**: Each retry attempt follows exponential backoff with randomized timing
- **Automatic Error Detection**: Handles HTTP 429 errors and quota exceeded messages automatically
- **Transparent Operation**: No additional configuration needed in service code

## Error Handling

The retry mechanism automatically handles the following GCP API errors:

### Rate Limiting Errors
- HTTP 429 status codes (Too Many Requests)
- Errors containing "quota exceeded" in the error message
- Errors containing "rate limit" in the error message

### Examples of Handled Errors
```
HttpError 429 when requesting https://cloudresourcemanager.googleapis.com/v1/projects/vms-uat-eiger:getIamPolicy?alt=json returned "Quota exceeded for quota metric 'Read requests' and limit 'Read requests per minute' of service 'cloudresourcemanager.googleapis.com' for consumer 'project_number:764086051850'."
```

## Implementation Details

### Configuration
The retry mechanism is centrally configured in `prowler/providers/gcp/config.py`:

```python
# GCP Provider Configuration
# Default retry configuration
DEFAULT_RETRY_ATTEMPTS = 3
```

This value can be modified to adjust the number of retry attempts across all GCP services.

### Client-Level Retry
The retry mechanism is configured at the client creation level using the `num_retries` parameter:

```python
# In discovery.build()
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS

client = discovery.build(
    service,
    version,
    credentials=credentials,
    num_retries=DEFAULT_RETRY_ATTEMPTS  # ← Uses centralized configuration
)
```

### Request-Level Retry
Individual requests can also specify retry behavior using the centralized configuration:

```python
# In request.execute()
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS

response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)  # ← Uses centralized configuration
```

### Automatic Retry Logic
The Google Cloud SDK automatically:

1. **Detects Retryable Errors**: Identifies HTTP 429 and quota exceeded errors
2. **Implements Exponential Backoff**: Uses randomized exponential backoff
3. **Handles Timeouts**: Manages request timeouts appropriately
4. **Logs Retry Attempts**: Provides built-in logging for retry operations

## Services with Retry Support

The following GCP services have been updated with integrated retry support:

- **Cloud Resource Manager**: `getIamPolicy()`, `organizations().search()`, project listing
- **Compute Engine**: All API calls for instances, networks, subnets, firewalls, etc.
- **Service Usage**: Service listing and API status checks
- **IAM**: Service account management and key operations
- **BigQuery**: Dataset and table operations
- **KMS**: Key management and encryption operations
- **Cloud Storage**: Bucket operations and IAM policies
- **Monitoring**: Alert policies and metrics
- **DNS**: Managed zones and policies
- **Logging**: Sinks and metrics
- **Cloud SQL**: Instance operations
- **GKE**: Cluster and node pool operations
- **API Keys**: Key management
- **DataProc**: Cluster operations

## Configuration

The retry mechanism uses a centralized configuration approach:

- **Configuration File**: `prowler/providers/gcp/config.py`
- **Default Retry Attempts**: 3 attempts (modifiable)
- **Exponential Backoff**: Randomized with base delay and maximum delay
- **Error Filtering**: Only retries on specific error types (429, quota exceeded)
- **Timeout Management**: Automatic timeout handling

### Modifying Retry Configuration

To change the number of retry attempts, modify the `DEFAULT_RETRY_ATTEMPTS` value in `prowler/providers/gcp/config.py`:

```python
# GCP Provider Configuration
# Default retry configuration
DEFAULT_RETRY_ATTEMPTS = 5  # ← Change from 3 to 5 attempts
```

This change will apply to all GCP services automatically.

## Validating Retry Attempts

For testing or modifying Prowler's behavior, use the following steps to confirm whether requests are being retried or abandoned:

### Step 1: Run Prowler with Debug Logging
```bash
python3 prowler-cli.py gcp --log-level DEBUG --log-file debuglogs.txt --project-id your-project-id
```

### Step 2: Search for Retry Messages
Search for retry attempts using:
```bash
grep -i "sleeping\|retry\|quota exceeded\|rate limit" debuglogs.txt
```

### Step 3: Look for Specific Retry Indicators
The Google Cloud SDK provides built-in logging for retry operations. Look for messages like:

```
"Sleeping 1.52 seconds before retry 1 of 3"
"Sleeping 3.23 seconds before retry 2 of 3"
"Sleeping 6.44 seconds before retry 3 of 3"
```

### Step 4: Verify Quota Exceeded Errors
Search for quota exceeded errors that trigger retries:
```bash
grep -i "quota exceeded" debuglogs.txt
```

### Example Debug Output
When retry is working correctly, you should see output similar to:
```
"Quota exceeded for quota metric 'Read requests' and limit 'Read requests per minute'"
"Sleeping 1.52 seconds before retry 1 of 3"
"Sleeping 3.23 seconds before retry 2 of 3"
"Sleeping 6.44 seconds before retry 3 of 3"
```

### Testing Retry in Real Environment
To force retry behavior for testing:

1. **Reduce API Quotas**: Temporarily reduce quotas in GCP Console
   - Go to APIs & Services > Quotas
   - Reduce "Read requests per minute" for Compute Engine API
   - Reduce "Policy Read Requests per minute" for IAM API

2. **Run Prowler**: Execute Prowler with debug logging
3. **Monitor Logs**: Check for retry messages in the debug output

This approach follows the same pattern as AWS documentation, providing clear indicators when retry mechanisms are active.

## Best Practices

1. **Use Default Settings**: The default `DEFAULT_RETRY_ATTEMPTS=3` is sufficient for most use cases
2. **Monitor Logs**: Watch for retry warnings in Google Cloud SDK logs
3. **Adjust Quotas**: Consider requesting higher quotas for frequently used APIs
4. **Optimize Calls**: Batch API calls where possible to reduce rate limiting
5. **Centralized Configuration**: Modify retry settings only in `config.py` for consistency
6. **Test Retry Behavior**: Use debug logging to verify retry functionality

## Troubleshooting

If you're still experiencing rate limiting issues:

1. **Check SDK Logs**: Look for retry messages in Google Cloud SDK logs
2. **Increase Retry Attempts**: Modify `DEFAULT_RETRY_ATTEMPTS` in `config.py` if needed
3. **Request Quota Increase**: Contact Google Cloud support for quota increases
4. **Optimize Scanning**: Consider scanning fewer resources simultaneously
5. **Verify Retry Functionality**: Use debug logging to confirm retry is working

## Example Usage

```python
from googleapiclient import discovery
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS

# Client-level retry using centralized configuration
client = discovery.build(
    "cloudresourcemanager",
    "v1",
    credentials=credentials,
    num_retries=DEFAULT_RETRY_ATTEMPTS
)

# Request-level retry using centralized configuration
response = client.projects().list().execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
```

## Official Documentation References

- **Google Cloud Python Client Libraries**: https://cloud.google.com/python/docs
- **Google API Python Client**: https://googleapis.github.io/google-api-python-client/
- **Google Cloud Quotas**: https://cloud.google.com/docs/quotas
- **Google Cloud API Design**: https://cloud.google.com/apis/design
- **Google API Core Retry**: https://googleapis.dev/python/google-api-core/latest/retry.html
