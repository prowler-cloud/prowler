# API Key Testing Guide for Local Docker Deployment

This guide walks you through setting up and testing API keys on your local Prowler Docker deployment.

## Prerequisites

- Docker and docker-compose installed
- Basic understanding of REST API testing tools (curl, Postman, etc.)

## 1. Environment Setup

### Create Environment File

Create a `.env` file in the project root with the required environment variables:

```bash
# Database Configuration
POSTGRES_DB=prowler_db
POSTGRES_ADMIN_USER=prowler
POSTGRES_ADMIN_PASSWORD=S3cret
POSTGRES_USER=prowler_user
POSTGRES_PASSWORD=prowler
POSTGRES_HOST=postgres-db
POSTGRES_PORT=5432

# Redis/Valkey Configuration
VALKEY_HOST=valkey
VALKEY_PORT=6379
VALKEY_DB=0

# Django Configuration
SECRET_KEY=your-super-secret-key-here
DJANGO_DEBUG=true
DJANGO_SETTINGS_MODULE=config.django.devel
DJANGO_PORT=8080
DJANGO_SECRETS_ENCRYPTION_KEY=ZMiYVo7m4Fbe2eXXPyrwxdJss2WSalXSv3xHBcJkPl0=

# JWT Configuration (for development)
DJANGO_TOKEN_SIGNING_KEY=""
DJANGO_TOKEN_VERIFYING_KEY=""
DJANGO_JWT_AUDIENCE=https://api.prowler.com
DJANGO_JWT_ISSUER=https://api.prowler.com
```

## 2. Start the Local Docker Environment

### Start Development Services

```bash
# Start all services in development mode
docker-compose -f docker-compose-dev.yml up -d

# Or start individual services for debugging
docker-compose -f docker-compose-dev.yml up postgres valkey -d
docker-compose -f docker-compose-dev.yml up api-dev -d
```

### Verify Services Are Running

```bash
# Check all services are healthy
docker-compose -f docker-compose-dev.yml ps

# Check API logs
docker logs -f $(docker ps --format "{{.Names}}" | grep 'api-dev')
```

The API should be accessible at `http://localhost:8080`

## 3. Quick Setup Script

For convenience, here's a complete script that sets up everything at once:

```bash
#!/bin/bash

# Step 1: Create user account
echo "Creating user account..."
curl -s -X POST http://localhost:8080/api/v1/users/ \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "users",
      "attributes": {
        "name": "Test User",
        "email": "test@example.com",
        "password": "TestPassword123!"
      }
    }
  }' > /dev/null

# Step 2: Get JWT token and tenant ID
echo "Getting JWT token and tenant ID..."
JWT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/login/ \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "tokens",
      "attributes": {
        "email": "test@example.com",
        "password": "TestPassword123!"
      }
    }
  }')

JWT_TOKEN=$(echo $JWT_RESPONSE | jq -r '.data.attributes.access')
TENANT_ID=$(echo $JWT_RESPONSE | jq -r '.data.relationships.tenant.data.id')

# Step 3: Create API key
echo "Creating API key..."
API_KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/ \
  -H "Content-Type: application/vnd.api+json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "data": {
      "type": "api-keys",
      "attributes": {
        "name": "My Test API Key",
        "expires_at": null
      }
    }
  }')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.data.attributes.key')
API_KEY_ID=$(echo $API_KEY_RESPONSE | jq -r '.data.id')

# Display results
echo "============================================"
echo "Setup Complete! Your variables:"
echo "JWT_TOKEN=$JWT_TOKEN"
echo "TENANT_ID=$TENANT_ID"
echo "API_KEY=$API_KEY"
echo "API_KEY_ID=$API_KEY_ID"
echo "============================================"

# Test the API key
echo "Testing API key..."
curl -X GET http://localhost:8080/api/v1/providers/ \
  -H "Authorization: ApiKey $API_KEY"
```

Copy this script to a file (e.g., `setup-api-test.sh`), make it executable (`chmod +x setup-api-test.sh`), and run it (`./setup-api-test.sh`).

## 4. Step-by-Step Setup (Alternative)

If you prefer to do each step manually:

### Create Test User Account

First, create a user account to manage API keys:

```bash
curl -X POST http://localhost:8080/api/v1/users/ \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "users",
      "attributes": {
        "name": "Test User",
        "email": "test@example.com",
        "password": "TestPassword123!"
      }
    }
  }'
```

### Get JWT Token for Authentication

```bash
# Get JWT token and store in variable
JWT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/login/ \
  -H "Content-Type: application/vnd.api+json" \
  -d '{
    "data": {
      "type": "tokens",
      "attributes": {
        "email": "test@example.com",
        "password": "TestPassword123!"
      }
    }
  }')

# Extract and store the JWT token
JWT_TOKEN=$(echo $JWT_RESPONSE | jq -r '.data.attributes.access')
echo "JWT Token: $JWT_TOKEN"

# Extract and store the tenant ID
TENANT_ID=$(echo $JWT_RESPONSE | jq -r '.data.relationships.tenant.data.id')
echo "Tenant ID: $TENANT_ID"
```

**Note:** Make sure you have `jq` installed for JSON parsing: `sudo apt-get install jq` (Ubuntu/Debian) or `brew install jq` (macOS)

## 5. API Key Management

### Create an API Key

Use your stored JWT token to create an API key:

```bash
# Create API key and store response
API_KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/ \
  -H "Content-Type: application/vnd.api+json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "data": {
      "type": "api-keys",
      "attributes": {
        "name": "My Test API Key",
        "expires_at": null
      }
    }
  }')

# Extract and store the API key and its ID
API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.data.attributes.key')
API_KEY_ID=$(echo $API_KEY_RESPONSE | jq -r '.data.id')

echo "API Key: $API_KEY"
echo "API Key ID: $API_KEY_ID"
```

**Important:** This is the only time you'll see the full API key! The variables above store it for immediate testing.

### API Key Format

API keys follow this format: `pk_XXXXXXXX.YYYYYYYY...`
- `pk_` - Fixed prefix
- `XXXXXXXX` - 8-character unique prefix for database lookups
- `YYYYYYYY...` - 32-character random secret

### List Your API Keys

```bash
curl -X GET http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/ \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Retrieve Specific API Key Details

```bash
curl -X GET http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/$API_KEY_ID/ \
  -H "Authorization: Bearer $JWT_TOKEN"
```

## 6. Testing API Key Authentication

### Basic API Key Usage

Use your stored API key to authenticate API requests:

```bash
# Test basic API key authentication
curl -X GET http://localhost:8080/api/v1/providers/ \
  -H "Authorization: ApiKey $API_KEY"
```

### Test Different Endpoints

```bash
# List tenants
curl -X GET http://localhost:8080/api/v1/tenants/ \
  -H "Authorization: ApiKey $API_KEY"

# Get tenant details
curl -X GET http://localhost:8080/api/v1/tenants/$TENANT_ID/ \
  -H "Authorization: ApiKey $API_KEY"

# List scans (if any exist)
curl -X GET http://localhost:8080/api/v1/scans/ \
  -H "Authorization: ApiKey $API_KEY"
```

### Verify API Key Activity Logging

Check the API logs to see your API key usage being tracked:

```bash
docker logs $(docker ps --format "{{.Names}}" | grep 'api-dev') | grep "API Key"
```

You should see structured log entries showing:
- API key ID and name
- Request details (method, path, IP)
- Response status and timing
- Authentication method confirmation

## 7. Testing Security Features

### Test Invalid API Key

```bash
# Should return 401 Unauthorized
curl -X GET http://localhost:8080/api/v1/providers/ \
  -H "Authorization: ApiKey pk_invalid.key12345"
```

### Test Missing Authorization

```bash
# Should return 401 Unauthorized
curl -X GET http://localhost:8080/api/v1/providers/
```

### Test Wrong Authorization Format

```bash
# Should return 401 Unauthorized (wrong keyword)
curl -X GET http://localhost:8080/api/v1/providers/ \
  -H "Authorization: Bearer $API_KEY"
```

### Test Expired API Key

Create an API key with short expiration:

```bash
# Create key that expires in 1 minute
EXPIRE_TIME=$(date -u -d '+1 minute' +%Y-%m-%dT%H:%M:%SZ)

EXPIRED_KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/ \
  -H "Content-Type: application/vnd.api+json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d "{
    \"data\": {
      \"type\": \"api-keys\",
      \"attributes\": {
        \"name\": \"Short-lived Test Key\",
        \"expires_at\": \"$EXPIRE_TIME\"
      }
    }
  }")

# Extract the expiring key
EXPIRING_API_KEY=$(echo $EXPIRED_KEY_RESPONSE | jq -r '.data.attributes.key')
echo "Created expiring key: $EXPIRING_API_KEY"
echo "Wait 1 minute, then test with: curl -X GET http://localhost:8080/api/v1/providers/ -H \"Authorization: ApiKey $EXPIRING_API_KEY\""
```

## 8. Advanced Testing Scenarios

### Test Concurrent API Key Usage

Create multiple concurrent requests:

```bash
# Run multiple requests in parallel
for i in {1..5}; do
  curl -X GET http://localhost:8080/api/v1/providers/ \
    -H "Authorization: ApiKey $API_KEY" &
done
wait
```

### Test Rate Limiting (if configured)

Make rapid requests to test rate limiting:

```bash
# Make 20 rapid requests
for i in {1..20}; do
  curl -X GET http://localhost:8080/api/v1/providers/ \
    -H "Authorization: ApiKey $API_KEY"
  sleep 0.1
done
```

### Test API Key Revocation

Revoke an API key and verify it stops working:

```bash
# Revoke the API key
curl -X DELETE http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/$API_KEY_ID/ \
  -H "Authorization: Bearer $JWT_TOKEN"

# Test that revoked key no longer works (should return 401)
curl -X GET http://localhost:8080/api/v1/providers/ \
  -H "Authorization: ApiKey $API_KEY"
```

## 9. Testing with Different Tools

### Using Postman

1. Create a new collection
2. Set up environment variables:
   - `api_base_url`: `http://localhost:8080`
   - `api_key`: Your actual API key
3. Add Authorization header: `ApiKey {{api_key}}`
4. Test various endpoints

### Using Python requests

```python
import requests
import os

# Use your stored API key from the environment
api_key = os.environ.get('API_KEY', 'pk_XXXXXXXX.YYYYYYYY...')
base_url = "http://localhost:8080"

headers = {
    "Authorization": f"ApiKey {api_key}",
    "Content-Type": "application/vnd.api+json"
}

# Test API key authentication
response = requests.get(f"{base_url}/api/v1/providers/", headers=headers)
print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
```

Before running the Python script, export your API key:
```bash
export API_KEY=$API_KEY
```

### Using JavaScript/Node.js

```javascript
const axios = require('axios');

// Use your stored API key from environment
const apiKey = process.env.API_KEY || 'pk_XXXXXXXX.YYYYYYYY...';
const baseURL = 'http://localhost:8080';

const headers = {
  'Authorization': `ApiKey ${apiKey}`,
  'Content-Type': 'application/vnd.api+json'
};

// Test API key authentication
axios.get(`${baseURL}/api/v1/providers/`, { headers })
  .then(response => {
    console.log('Status:', response.status);
    console.log('Data:', response.data);
  })
  .catch(error => {
    console.error('Error:', error.response?.status, error.response?.data);
  });
```

Before running the Node.js script, export your API key:
```bash
export API_KEY=$API_KEY
```

## 10. Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check API key format: `ApiKey pk_XXXXXXXX.YYYYYYYY...`
   - Verify key hasn't expired or been revoked
   - Ensure correct Authorization header format

2. **Database Connection Errors**
   - Verify PostgreSQL container is running: `docker ps | grep postgres`
   - Check database credentials in `.env` file
   - Wait for migrations to complete: `docker logs api-dev-container`

3. **Service Not Responding**
   - Check all containers are healthy: `docker-compose ps`
   - Verify port 8080 is not in use: `lsof -i :8080`
   - Check API container logs: `docker logs api-dev-container`

### Debug API Key Issues

Enable debug logging to see detailed authentication flow:

```bash
# Set debug logging environment variable
echo "DJANGO_LOGGING_LEVEL=debug" >> .env

# Restart the API service
docker-compose -f docker-compose-dev.yml restart api-dev

# Monitor logs for detailed authentication info
docker logs -f api-dev-container | grep -i "apikey\|auth"
```

### Verify Database State

Check API keys directly in the database:

```bash
# Connect to PostgreSQL
docker exec -it postgres-container psql -U prowler -d prowler_db

# List API keys
SELECT id, name, prefix, expires_at, last_used_at, revoked_at FROM api_keys;

# Check API key activity
SELECT * FROM api_key_activities ORDER BY timestamp DESC LIMIT 10;
```

## 11. Security Best Practices

### For Testing
- Use short-lived API keys for testing
- Revoke test keys immediately after testing
- Never commit API keys to version control
- Use different keys for different test scenarios

### For Production
- Set appropriate expiration times
- Monitor API key usage through logs
- Implement rate limiting
- Regularly rotate API keys
- Use HTTPS in production

## 12. Available API Endpoints

Here are the main endpoints you can test with your API keys:

### Core Resources
- `GET /api/v1/tenants/` - List tenants
- `GET /api/v1/providers/` - List cloud providers
- `GET /api/v1/scans/` - List scans
- `GET /api/v1/findings/` - List security findings

### Provider Management
- `POST /api/v1/providers/` - Add new provider
- `GET /api/v1/providers/{id}/` - Get provider details
- `PUT /api/v1/providers/{id}/` - Update provider
- `DELETE /api/v1/providers/{id}/` - Remove provider

### Scan Management
- `POST /api/v1/scans/` - Start new scan
- `GET /api/v1/scans/{id}/` - Get scan status
- `GET /api/v1/scans/{id}/findings/` - Get scan findings

All endpoints require proper authentication using your API key in the format:
```
Authorization: ApiKey pk_XXXXXXXX.YYYYYYYY...
```

## 13. Summary

This guide covers comprehensive API key testing for your local Prowler deployment. You now know how to:

1. Set up the Docker environment
2. Create and manage API keys
3. Test authentication and authorization
4. Verify security features
5. Troubleshoot common issues
6. Use various testing tools

Start with the basic authentication tests and gradually move to more complex scenarios. Monitor the logs to understand how API key activity is tracked and ensure your implementation is working correctly. 