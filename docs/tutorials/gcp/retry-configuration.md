# GCP Retry Configuration in Prowler

Prowler's GCP Provider uses Google Cloud Python SDK's integrated retry mechanism to automatically retry API calls when encountering rate limiting errors (HTTP 429).

## Quick Configuration

### Using Command Line Flag (Recommended)
```bash
prowler gcp --gcp-retries-max-attempts 5
```

### Using Configuration File
Modify `prowler/providers/gcp/config.py`:
```python
DEFAULT_RETRY_ATTEMPTS = 5  # Default: 3
```

## How It Works

- **Automatic Detection**: Handles HTTP 429 and quota exceeded errors
- **Exponential Backoff**: Each retry uses randomized exponential backoff
- **Centralized Config**: All GCP services use the same retry configuration
- **Transparent**: No additional code needed in services

## Error Examples Handled

```
HttpError 429 when requesting https://cloudresourcemanager.googleapis.com/v1/projects/vms-uat-eiger:getIamPolicy?alt=json returned "Quota exceeded for quota metric 'Read requests' and limit 'Read requests per minute'"
```

## Implementation

### Client-Level Configuration
```python
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS

client = discovery.build(
    service, version, credentials=credentials,
    num_retries=DEFAULT_RETRY_ATTEMPTS
)
```

### Request-Level Configuration
```python
response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
```

## Services with Retry Support

All major GCP services are covered:
- Cloud Resource Manager, Compute Engine, IAM
- BigQuery, KMS, Cloud Storage, Monitoring
- DNS, Logging, Cloud SQL, GKE, API Keys, DataProc

## Validation

### Debug Logging
```bash
prowler gcp --log-level DEBUG --log-file debuglogs.txt --project-id your-project-id
```

### Check for Retry Messages
```bash
grep -i "sleeping\|retry\|quota exceeded" debuglogs.txt
```

### Expected Output
```
"Sleeping 1.52 seconds before retry 1 of 3"
"Sleeping 3.23 seconds before retry 2 of 3"
```

## Testing in Real Environment

1. **Reduce API Quotas** in GCP Console:
   - APIs & Services > Quotas
   - Reduce "Read requests per minute" for Compute Engine API
   - Reduce "Policy Read Requests per minute" for IAM API

2. **Run Prowler** with debug logging
3. **Monitor logs** for retry messages

## Troubleshooting

If experiencing rate limiting:
1. Use `--gcp-retries-max-attempts` flag to increase attempts
2. Request quota increases from Google Cloud support
3. Optimize scanning to reduce simultaneous API calls
4. Verify retry functionality with debug logging

## Official References

- [Google Cloud Python Client Libraries](https://cloud.google.com/python/docs)
- [Google Cloud Quotas](https://cloud.google.com/docs/quotas)
- [Google API Core Retry](https://googleapis.dev/python/google-api-core/latest/retry.html)
