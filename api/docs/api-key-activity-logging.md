# API Key Activity Logging

The Prowler API provides structured activity logging for all API key usage to support security auditing, compliance requirements, and incident response. This feature captures detailed information about every API request made with an API key through structured application logs.

## Overview

API key activity logging serves several critical purposes:

- **Security Auditing**: Track all API key usage for security monitoring and threat detection
- **Compliance**: Meet regulatory requirements for access logging and audit trails  
- **Incident Response**: Provide detailed forensic data for investigating security incidents
- **Usage Analysis**: Understand API usage patterns and identify potential abuse
- **Compromised Key Detection**: Detect unusual activity patterns that may indicate compromised keys

## What is Logged

Every API request authenticated with an API key generates structured log entries that include:

### Authentication Details
- **API Key ID**: Unique identifier of the API key used
- **API Key Name**: Human-readable name for the API key
- **Tenant ID**: Tenant context for multi-tenancy support

### Request Details
- **HTTP Method**: GET, POST, PUT, DELETE, etc.
- **Endpoint**: Full API endpoint path that was accessed
- **Query Parameters**: All query parameters for audit purposes
- **Timestamp**: Precise time when the request was made
- **Source IP Address**: IP address of the client making the request
- **User Agent**: Client application information

### Response Details
- **Status Code**: HTTP response status (200, 401, 429, etc.)
- **Duration**: Request processing time in seconds

## Log Format

API key requests generate structured log entries in NDJSON format:

```json
{
  "timestamp": "2024-01-15 14:30:22",
  "level": "INFO",
  "message": "API Request: GET /api/v1/scans [API Key: Production Scanner]",
  "logger": "api",
  "api_key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "api_key_name": "Production Scanner",
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

## Security Monitoring

### Log Analysis for Security Patterns

Use log aggregation tools to analyze patterns and detect security issues:

#### Compromised Key Detection

Look for unusual patterns in logs:

```bash
# Using jq to analyze logs - detect multiple IPs for same API key
cat api.log | jq -r 'select(.is_api_key_request == true) | "\(.api_key_id) \(.source_ip)"' | \
  sort | uniq -c | awk '$1 > 5 {print $2 " used from " $1 " different IPs"}'

# Detect high request volumes
cat api.log | jq -r 'select(.is_api_key_request == true and .timestamp > "2024-01-15T13:00:00") | .api_key_id' | \
  sort | uniq -c | awk '$1 > 1000 {print $2 " made " $1 " requests in last hour"}'
```

#### Failed Authentication Tracking

```bash
# Track failed requests by API key
cat api.log | jq -r 'select(.is_api_key_request == true and .status_code >= 400) | "\(.api_key_id) \(.status_code)"' | \
  sort | uniq -c | sort -nr
```

### Popular SIEM Integration

Export logs to Security Information and Event Management (SIEM) systems:

- **Splunk**: Parse NDJSON logs for real-time security analysis
- **ELK Stack**: Index logs in Elasticsearch for search and visualization  
- **AWS CloudWatch**: Stream logs for AWS-native monitoring
- **DataDog**: Forward logs for comprehensive application monitoring

### Example Analysis Script

```python
import json
import pandas as pd
from datetime import datetime, timedelta

def analyze_api_key_activity(log_file):
    """Analyze API key activity for security patterns."""
    activities = []
    
    with open(log_file, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                if log_entry.get('is_api_key_request'):
                    activities.append(log_entry)
            except json.JSONDecodeError:
                continue
    
    df = pd.DataFrame(activities)
    
    # Analyze request patterns by hour
    df['hour'] = pd.to_datetime(df['timestamp']).dt.floor('H')
    hourly_requests = df.groupby(['hour', 'api_key_id']).size().reset_index(name='request_count')
    
    # Identify high-volume keys (>100 requests/hour)
    high_volume = hourly_requests[hourly_requests['request_count'] > 100]
    
    # Identify keys used from multiple IPs
    ip_analysis = df.groupby('api_key_id')['source_ip'].nunique().reset_index(name='unique_ips')
    suspicious_ips = ip_analysis[ip_analysis['unique_ips'] > 3]
    
    return {
        'high_volume_keys': high_volume,
        'suspicious_ip_patterns': suspicious_ips,
        'failed_requests': df[df['status_code'] >= 400]
    }
```

## Configuration

### Environment Variables

Control logging behavior with environment variables:

```bash
# Log level for API key activities (default: INFO)
DJANGO_LOGGING_LEVEL=INFO

# Choose log format (default: ndjson)
DJANGO_LOGGING_FORMATTER=ndjson  # or human_readable
```

### Log Format Options

Choose between structured (NDJSON) and human-readable formats:

```bash
# NDJSON format for machine processing (recommended)
DJANGO_LOGGING_FORMATTER=ndjson

# Human-readable format for development
DJANGO_LOGGING_FORMATTER=human_readable
```

## Compliance Features

### Audit Trail Requirements

The structured logging system supports common compliance frameworks:

- **SOC 2 Type II**: Comprehensive access logging for security controls
- **GDPR**: User activity tracking with appropriate data handling
- **HIPAA**: Detailed audit logs for healthcare compliance
- **PCI DSS**: Access monitoring for payment card industry compliance

### Data Retention

Configure log retention using your log management system:

- **Application logs**: Configure through your logging infrastructure
- **Log aggregation**: Set retention policies in your SIEM/log platform
- **Archival**: Use your organization's log archival strategy

## Privacy and Data Protection

### Sensitive Data Handling

The logging system is designed with privacy in mind:

- **No sensitive data logging**: Request/response bodies are not logged
- **IP address handling**: Can be anonymized through log processing
- **Tenant isolation**: Logs include tenant context for proper segregation
- **Access controls**: Implement appropriate access controls for log data

## Best Practices

### Security Monitoring

1. **Set up automated alerts** for unusual activity patterns in your SIEM
2. **Review logs regularly** for security anomalies
3. **Correlate with rate limiting** events for comprehensive analysis
4. **Monitor geographic patterns** for unauthorized access

### Performance Considerations

1. **Use structured logging** for better parsing performance
2. **Implement log sampling** for very high-volume environments if needed
3. **Configure appropriate log levels** to control verbosity
4. **Use asynchronous log shipping** to external systems

### Compliance Management

1. **Define retention policies** based on regulatory requirements
2. **Implement access controls** for audit log data
3. **Regular compliance audits** of logging effectiveness
4. **Document procedures** for incident response using logs

This simplified logging approach provides the essential security visibility needed for API key management while maintaining simplicity and avoiding database complexity. 