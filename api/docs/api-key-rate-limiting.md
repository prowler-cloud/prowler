# API Key Rate Limiting

The Prowler API includes built-in rate limiting for API key authentication to protect against abuse, accidental loops in automation, and credential leaks. This feature provides configurable limits per time window with proper error responses and admin bypass functionality.

## Overview

Rate limiting is applied only to requests authenticated with API keys (not JWT tokens). It tracks usage across multiple time windows:

- **Per minute**: Short-term burst protection
- **Per hour**: Medium-term usage control  
- **Per day**: Long-term quota management

Each API key has separate rate limit counters, and only successful requests (2xx status codes) count toward the limits.

## Configuration

Rate limiting is configured through environment variables:

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_RATE_LIMIT_ENABLED` | `true` | Enable/disable rate limiting globally |
| `API_RATE_LIMIT_REQUESTS_PER_MINUTE` | `120` | Maximum requests per minute per API key |
| `API_RATE_LIMIT_REQUESTS_PER_HOUR` | `3600` | Maximum requests per hour per API key |
| `API_RATE_LIMIT_REQUESTS_PER_DAY` | `50000` | Maximum requests per day per API key |
| `VALKEY_CACHE_DB` | `1` | Redis/Valkey database number for caching |

### Disabling Specific Limits

Set any limit to `0` or negative value to disable that specific time window:

```bash
# Disable per-minute limits but keep hourly and daily
API_RATE_LIMIT_REQUESTS_PER_MINUTE=0
API_RATE_LIMIT_REQUESTS_PER_HOUR=1000
API_RATE_LIMIT_REQUESTS_PER_DAY=10000
```

### Example Configuration

```bash
# Conservative limits for production
API_RATE_LIMIT_ENABLED=true
API_RATE_LIMIT_REQUESTS_PER_MINUTE=60
API_RATE_LIMIT_REQUESTS_PER_HOUR=2000
API_RATE_LIMIT_REQUESTS_PER_DAY=20000

# Development/testing with higher limits
API_RATE_LIMIT_REQUESTS_PER_MINUTE=300
API_RATE_LIMIT_REQUESTS_PER_HOUR=10000
API_RATE_LIMIT_REQUESTS_PER_DAY=100000
```

## Behavior

### Admin Bypass

Users with roles that have `unlimited_visibility` permission automatically bypass all rate limits. This ensures admin users and service accounts with elevated privileges are not restricted.

### Time Windows

Rate limits use fixed time windows:

- **Minute**: 60-second windows (e.g., 12:00:00-12:00:59)
- **Hour**: 3600-second windows (e.g., 12:00:00-12:59:59)  
- **Day**: 86400-second windows (e.g., 00:00:00-23:59:59 UTC)

### Request Counting

- Only successful requests (HTTP 2xx status codes) count toward limits
- Failed requests (4xx, 5xx errors) do not consume quota
- Each API key has independent counters
- Counters reset at the start of each time window

## Error Response

When rate limits are exceeded, the API returns an HTTP 429 status with a JSON:API compliant error response:

```json
{
  "errors": [
    {
      "status": "429",
      "code": "rate_limit_exceeded", 
      "title": "Rate Limit Exceeded",
      "detail": "API key has exceeded the rate limit of 120 requests per minute. Please try again later.",
      "meta": {
        "limit": 120,
        "window": "minute",
        "retry_after": 45
      }
    }
  ]
}
```

### Response Headers

Rate limit responses include helpful headers:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 45
X-RateLimit-Limit: 120
X-RateLimit-Window: minute
X-RateLimit-Retry-After: 45
```

## Best Practices

### For API Consumers

1. **Implement exponential backoff** when receiving 429 responses
2. **Respect the `Retry-After` header** before making new requests
3. **Monitor your usage patterns** to stay within limits
4. **Cache responses** when possible to reduce API calls
5. **Use batch operations** when available instead of individual requests

### For Platform Operators

1. **Start with conservative limits** and adjust based on usage patterns
2. **Monitor rate limit violations** in logs to identify abusive patterns
3. **Set appropriate limits per environment**:
   - Development: Higher limits for testing
   - Staging: Production-like limits
   - Production: Conservative limits with monitoring
4. **Consider usage patterns**:
   - Automation scripts may need higher daily limits
   - Interactive applications may need higher per-minute limits

### Example Implementation (Python)

```python
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class RateLimitedSession(requests.Session):
    def __init__(self):
        super().__init__()
        # Configure retry strategy for rate limits
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429],
            backoff_factor=1,
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

# Usage
session = RateLimitedSession()
session.headers.update({
    'Authorization': 'ApiKey pk_your_api_key_here',
    'Content-Type': 'application/vnd.api+json'
})

response = session.get('https://api.prowler.com/api/v1/scans')
```

## Monitoring and Alerting

### Log Messages

Rate limit violations are logged with structured data:

```json
{
  "level": "WARNING",
  "message": "API key rate limit exceeded: minute",
  "api_key_id": "uuid-of-api-key",
  "window": "minute",
  "limit": 120,
  "current_count": 121,
  "path": "/api/v1/scans",
  "method": "GET",
  "ip": "192.168.1.100"
}
```

### Metrics to Monitor

- Rate limit violation frequency by API key
- Distribution of usage across time windows
- Cache hit/miss rates for rate limit counters
- Response time impact of rate limiting middleware

## Troubleshooting

### Common Issues

**Q: API key always hits rate limits immediately**
- Check if the cache (Redis/Valkey) is working properly
- Verify time synchronization between servers
- Check for multiple instances using the same API key

**Q: Admin users are being rate limited**
- Verify the user's role has `unlimited_visibility` permission
- Check logs for role lookup errors
- Ensure the user is properly authenticated

**Q: Rate limits seem inconsistent**  
- Rate limits use fixed time windows, not sliding windows
- Counters reset at window boundaries (e.g., start of each minute)
- Multiple API keys have separate counters

### Cache Dependencies

Rate limiting requires a functioning cache backend (Redis/Valkey):

- If cache is unavailable, requests will still succeed but limits won't be enforced
- Cache errors are logged but don't block requests
- Ensure cache has sufficient memory for rate limit counters

## Security Considerations

- Rate limiting is only one layer of protection
- Monitor for distributed attacks using multiple API keys
- Consider additional WAF/proxy-level rate limiting for infrastructure protection
- Regularly audit API key usage and revoke unused keys
- Implement alerting for unusual usage patterns

## Configuration Examples by Use Case

### High-Volume Automation
```bash
API_RATE_LIMIT_REQUESTS_PER_MINUTE=300
API_RATE_LIMIT_REQUESTS_PER_HOUR=10000  
API_RATE_LIMIT_REQUESTS_PER_DAY=100000
```

### Interactive Applications
```bash
API_RATE_LIMIT_REQUESTS_PER_MINUTE=120
API_RATE_LIMIT_REQUESTS_PER_HOUR=3600
API_RATE_LIMIT_REQUESTS_PER_DAY=25000
```

### Restrictive Production Environment
```bash
API_RATE_LIMIT_REQUESTS_PER_MINUTE=60
API_RATE_LIMIT_REQUESTS_PER_HOUR=1800
API_RATE_LIMIT_REQUESTS_PER_DAY=10000
```

For questions or support with rate limiting configuration, please refer to the Prowler documentation or contact support. 