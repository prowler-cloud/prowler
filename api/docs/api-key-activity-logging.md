# API Key Activity Logging

The Prowler API provides comprehensive activity logging for all API key usage to support security auditing, compliance requirements, and incident response. This feature captures detailed information about every API request made with an API key, providing complete visibility into API key usage patterns.

## Overview

API key activity logging serves several critical purposes:

- **Security Auditing**: Track all API key usage for security monitoring and threat detection
- **Compliance**: Meet regulatory requirements for access logging and audit trails
- **Incident Response**: Provide detailed forensic data for investigating security incidents
- **Usage Analysis**: Understand API usage patterns and identify potential abuse
- **Compromised Key Detection**: Detect unusual activity patterns that may indicate compromised keys

## What is Logged

Every API request authenticated with an API key generates both:

1. **Structured log entries** for real-time monitoring
2. **Persistent database records** for long-term analysis and compliance

### Logged Information

For each API key request, the following information is captured:

#### Authentication Details
- **API Key ID**: Unique identifier of the API key used
- **API Key Name**: Human-readable name for the API key
- **User ID**: ID of the user who owns the API key
- **Tenant ID**: Tenant context for multi-tenancy support

#### Request Details
- **HTTP Method**: GET, POST, PUT, DELETE, etc.
- **Endpoint**: Full API endpoint path that was accessed
- **Query Parameters**: All query parameters for audit purposes
- **Timestamp**: Precise time when the request was made
- **Source IP Address**: IP address of the client making the request
- **User Agent**: Client application information

#### Response Details
- **Status Code**: HTTP response status (200, 401, 429, etc.)
- **Response Size**: Size of the response in bytes (when available)
- **Duration**: Request processing time in milliseconds
- **Rate Limited**: Whether the request was rate limited

## Logging Formats

### Structured Log Output

API key requests generate structured log entries in NDJSON format:

```json
{
  "timestamp": "2024-01-15 14:30:22",
  "level": "INFO",
  "message": "API Request: GET /api/v1/scans [API Key: Production Scanner]",
  "logger": "api",
  "api_key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "api_key_name": "Production Scanner",
  "user_id": "f1e2d3c4-b5a6-9876-dcba-543210fedcba",
  "tenant_id": "1a2b3c4d-5e6f-7890-abcd-1234567890ef",
  "authentication_method": "api_key",
  "is_api_key_request": true,
  "method": "GET",
  "path": "/api/v1/scans",
  "query_params": {"provider": "aws", "limit": "100"},
  "status_code": 200,
  "duration": 0.245,
  "source_ip": "192.168.1.100",
  "user_agent": "ProwlerClient/1.0"
}
```

### Database Schema

API key activity is also stored in the `api_key_activities` table:

```sql
CREATE TABLE api_key_activities (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    api_key_id UUID NOT NULL REFERENCES api_keys(id),
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id UUID NOT NULL,
    method VARCHAR(10) NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    source_ip INET NOT NULL,
    user_agent TEXT,
    status_code INTEGER NOT NULL,
    response_size INTEGER,
    duration_ms INTEGER,
    query_params JSONB DEFAULT '{}',
    is_rate_limited BOOLEAN DEFAULT FALSE
);
```

## Security Use Cases

### Compromised Key Detection

Monitor for unusual patterns that may indicate a compromised API key:

```sql
-- Detect API key usage from multiple IP addresses
SELECT api_key_id, COUNT(DISTINCT source_ip) as ip_count
FROM api_key_activities 
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY api_key_id 
HAVING COUNT(DISTINCT source_ip) > 3;

-- Detect unusual request volumes
SELECT api_key_id, COUNT(*) as request_count
FROM api_key_activities 
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY api_key_id 
HAVING COUNT(*) > 1000;
```

### Geographic Analysis

Identify requests from unexpected geographic locations:

```sql
-- Find API key usage by source IP patterns
SELECT api_key_id, source_ip, COUNT(*) as request_count
FROM api_key_activities 
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY api_key_id, source_ip
ORDER BY request_count DESC;
```

### Failed Authentication Tracking

Monitor for repeated failed authentication attempts:

```sql
-- Track failed requests per API key
SELECT api_key_id, COUNT(*) as failed_requests
FROM api_key_activities 
WHERE status_code IN (401, 403, 429)
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY api_key_id
ORDER BY failed_requests DESC;
```

## Compliance Features

### Audit Trail Requirements

The logging system meets common compliance requirements:

- **SOC 2 Type II**: Comprehensive access logging with tamper-evident storage
- **GDPR**: User activity tracking with appropriate data retention policies  
- **HIPAA**: Detailed audit logs for healthcare compliance
- **PCI DSS**: Access monitoring for payment card industry compliance

### Data Retention

Configure data retention policies based on compliance requirements:

```python
# Example retention policy configuration
API_KEY_ACTIVITY_RETENTION_DAYS = 2555  # 7 years for financial compliance
```

### Immutable Audit Log

API key activity records are designed to be immutable:

- Records cannot be updated after creation
- Deletion is restricted to automated retention policies
- All access to audit data is logged

## Performance Considerations

### Database Optimization

The system includes optimized indexes for common queries:

```sql
-- Primary lookup patterns
CREATE INDEX api_key_activity_key_time_idx ON api_key_activities (api_key_id, timestamp DESC);
CREATE INDEX api_key_activity_user_time_idx ON api_key_activities (user_id, timestamp DESC);
CREATE INDEX api_key_activity_tenant_time_idx ON api_key_activities (tenant_id, timestamp DESC);

-- Security analysis indexes
CREATE INDEX api_key_activity_ip_time_idx ON api_key_activities (source_ip, timestamp DESC);
CREATE INDEX api_key_activity_endpoint_time_idx ON api_key_activities (endpoint, timestamp DESC);
CREATE INDEX api_key_activity_status_time_idx ON api_key_activities (status_code, timestamp DESC);

-- Incident response indexes
CREATE INDEX api_key_activity_incident_idx ON api_key_activities (tenant_id, api_key_id, source_ip, timestamp DESC);
CREATE INDEX api_key_activity_rate_limit_idx ON api_key_activities (tenant_id, is_rate_limited, timestamp DESC);
```

### Asynchronous Logging

Database logging is designed to minimize request latency:

- Logging occurs after the response is sent to the client
- Database errors do not impact API request success
- Failed logging attempts are recorded in application logs

## Configuration

### Environment Variables

Control logging behavior with environment variables:

```bash
# Enable/disable activity logging (default: true)
API_KEY_ACTIVITY_LOGGING_ENABLED=true

# Log level for API key activities (default: INFO)
DJANGO_LOGGING_LEVEL=INFO

# Database retention period in days (default: 365)
API_KEY_ACTIVITY_RETENTION_DAYS=365
```

### Log Format Configuration

Choose between human-readable and machine-readable log formats:

```bash
# Use NDJSON format for structured logging (default)
DJANGO_LOGGING_FORMATTER=ndjson

# Use human-readable format for development
DJANGO_LOGGING_FORMATTER=human_readable
```

## Monitoring and Alerting

### Security Monitoring

Set up alerts for suspicious activity patterns:

#### High Request Volume Alert
```sql
-- Alert if any API key exceeds 1000 requests per hour
SELECT api_key_id, COUNT(*) as requests
FROM api_key_activities 
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY api_key_id 
HAVING COUNT(*) > 1000;
```

#### Geographic Anomaly Alert
```sql
-- Alert if API key used from more than 5 different IPs in 24 hours
SELECT api_key_id, COUNT(DISTINCT source_ip) as unique_ips
FROM api_key_activities 
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY api_key_id 
HAVING COUNT(DISTINCT source_ip) > 5;
```

#### Failed Authentication Alert
```sql
-- Alert on high failure rates
SELECT api_key_id, 
       COUNT(*) as total_requests,
       COUNT(*) FILTER (WHERE status_code >= 400) as failed_requests,
       ROUND(COUNT(*) FILTER (WHERE status_code >= 400) * 100.0 / COUNT(*), 2) as failure_rate
FROM api_key_activities 
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY api_key_id 
HAVING COUNT(*) FILTER (WHERE status_code >= 400) * 100.0 / COUNT(*) > 20;
```

### Log Analysis Tools

#### Popular SIEM Integration

Export logs to Security Information and Event Management (SIEM) systems:

- **Splunk**: Parse NDJSON logs for real-time security analysis
- **ELK Stack**: Index logs in Elasticsearch for search and visualization
- **AWS CloudWatch**: Stream logs for AWS-native monitoring
- **DataDog**: Forward logs for comprehensive application monitoring

#### Custom Analysis Scripts

Example Python script for analyzing API key activity:

```python
import json
import pandas as pd
from datetime import datetime, timedelta

def analyze_api_key_activity(log_file):
    """Analyze API key activity for security patterns."""
    activities = []
    
    with open(log_file, 'r') as f:
        for line in f:
            if 'api_key_id' in line:
                activities.append(json.loads(line))
    
    df = pd.DataFrame(activities)
    
    # Analyze request patterns
    hourly_requests = df.groupby([
        df['timestamp'].str[:13],  # Group by hour
        'api_key_id'
    ]).size().reset_index(name='request_count')
    
    # Identify high-volume keys
    high_volume = hourly_requests[
        hourly_requests['request_count'] > 100
    ]
    
    return high_volume
```

## Privacy and Data Protection

### Sensitive Data Handling

The logging system is designed with privacy in mind:

- **No sensitive data logging**: Request/response bodies are not logged
- **IP address anonymization**: Can be configured for GDPR compliance
- **Tenant isolation**: Strict row-level security ensures data separation
- **Access controls**: Audit log access requires appropriate permissions

### GDPR Compliance

Support for European data protection regulations:

```python
# Example configuration for GDPR compliance
ANONYMIZE_IP_ADDRESSES = True
DATA_RETENTION_DAYS = 1095  # 3 years maximum
ALLOW_DATA_EXPORT = True
ALLOW_DATA_DELETION = True
```

## Troubleshooting

### Common Issues

#### Missing Activity Records

If API key activity is not being logged:

1. **Check logging configuration**:
   ```bash
   # Verify logging is enabled
   echo $API_KEY_ACTIVITY_LOGGING_ENABLED
   
   # Check log level
   echo $DJANGO_LOGGING_LEVEL
   ```

2. **Verify database connectivity**:
   ```python
   from api.models import APIKeyActivity
   APIKeyActivity.objects.count()
   ```

3. **Check middleware order**:
   Ensure `APILoggingMiddleware` is properly configured in `MIDDLEWARE` setting.

#### High Database Load

If activity logging causes performance issues:

1. **Review indexes**: Ensure appropriate indexes exist for your query patterns
2. **Consider partitioning**: For very high volumes, implement table partitioning
3. **Adjust retention**: Shorter retention periods reduce storage requirements

#### Log Volume Management

For high-traffic APIs:

```python
# Implement sampling for very high volume environments
SAMPLE_RATE = 0.1  # Log 10% of requests

# Or implement smart sampling based on patterns
SAMPLE_RATE_BY_STATUS = {
    200: 0.01,  # 1% of successful requests
    429: 1.0,   # 100% of rate limited requests
    500: 1.0,   # 100% of errors
}
```

## API Access to Activity Data

### REST API Endpoints

Access API key activity through dedicated endpoints:

```http
GET /api/v1/api-keys/{id}/activities
```

Query parameters:
- `start_date`: Filter activities from this date
- `end_date`: Filter activities until this date  
- `source_ip`: Filter by source IP address
- `status_code`: Filter by HTTP status code
- `limit`: Limit number of results
- `offset`: Pagination offset

Example response:
```json
{
  "data": [
    {
      "type": "api-key-activities",
      "id": "activity-id",
      "attributes": {
        "timestamp": "2024-01-15T14:30:22Z",
        "method": "GET",
        "endpoint": "/api/v1/scans",
        "source_ip": "192.168.1.100",
        "status_code": 200,
        "duration_ms": 245,
        "is_rate_limited": false
      },
      "relationships": {
        "api_key": {"data": {"type": "api-keys", "id": "key-id"}},
        "user": {"data": {"type": "users", "id": "user-id"}}
      }
    }
  ]
}
```

### Filtering and Search

Advanced filtering capabilities:

```http
# Find all failed requests in the last 24 hours
GET /api/v1/api-key-activities?filter[status_code__gte]=400&filter[timestamp__gte]=2024-01-14T14:30:22Z

# Find requests from specific IP range
GET /api/v1/api-key-activities?filter[source_ip__startswith]=192.168.1

# Find rate-limited requests
GET /api/v1/api-key-activities?filter[is_rate_limited]=true
```

## Best Practices

### Security Monitoring

1. **Set up automated alerts** for unusual activity patterns
2. **Review logs regularly** for security anomalies
3. **Correlate with rate limiting** data for comprehensive analysis
4. **Monitor geographic patterns** for unauthorized access

### Compliance Management

1. **Define retention policies** based on regulatory requirements
2. **Implement access controls** for audit log data
3. **Regular compliance audits** of logging effectiveness
4. **Document procedures** for incident response using logs

### Performance Optimization

1. **Use appropriate indexes** for common query patterns
2. **Implement log archiving** for long-term storage
3. **Monitor database performance** impact of logging
4. **Consider log sampling** for very high-volume environments

### Data Privacy

1. **Minimize logged data** to essential security information
2. **Implement data anonymization** where required
3. **Regular data purging** according to retention policies
4. **Access logging** for audit trail data itself

This comprehensive logging system provides the security visibility and compliance capabilities needed for enterprise API key management while maintaining high performance and privacy standards. 