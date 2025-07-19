# API Key Testing Guide for Local Docker Deployment

This guide walks you through setting up and testing API keys on your local Prowler Docker deployment.

## Prerequisites

- Docker and docker-compose installed
- Basic understanding of REST API testing tools (curl, Postman, etc.)

## Start the Local Docker Environment

```bash
# Start all services in development mode
docker-compose -f docker-compose-dev.yml up -d
```

## Quick Setup Script

For convenience, here's a complete script that sets up everything at once:

```bash
#!/bin/bash

# Step 1: Create user account
echo "Creating user account..."
USER_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/users \
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
  }')

# Check if user creation was successful
if echo "$USER_RESPONSE" | grep -q '"type":"users"'; then
  echo "✓ User created successfully"
else
  echo "✗ User creation failed:"
  echo "$USER_RESPONSE"
fi

# Step 2: Get JWT token
echo "Getting JWT token..."
JWT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/tokens \
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
echo "JWT Token: $JWT_TOKEN"

# Step 3: Get tenant ID
echo "Getting tenant ID..."
TENANT_RESPONSE=$(curl -s -X GET http://localhost:8080/api/v1/tenants \
  -H "Authorization: Bearer $JWT_TOKEN")

TENANT_ID=$(echo $TENANT_RESPONSE | jq -r '.data[0].id')
echo "Tenant ID: $TENANT_ID"

# Step 4: Create API key
echo "Creating API key..."
API_KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/create \
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
echo "API Key: $API_KEY"
API_KEY_ID=$(echo $API_KEY_RESPONSE | jq -r '.data.id')
echo "API Key ID: $API_KEY_ID"

# Test the API key
echo "Testing API key..."

# List providers
curl -X GET http://localhost:8080/api/v1/providers \
  -H "Authorization: ApiKey $API_KEY"

# List scans (if any exist)
curl -X GET http://localhost:8080/api/v1/scans \
  -H "Authorization: ApiKey $API_KEY"

# List all findings
curl -X GET http://localhost:8080/api/v1/findings \
  -H "Authorization: ApiKey $API_KEY"

# List compliance overviews
curl -X GET http://localhost:8080/api/v1/compliance-overviews?filter%5Bscan_id%5D=1 \
  -H "Authorization: ApiKey $API_KEY"

# List compliance overviews attributes
curl -X GET "http://localhost:8080/api/v1/compliance-overviews/attributes?filter%5Bcompliance_id%5D=1" \
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
curl -X GET http://localhost:8080/api/v1/providers \
  -H "Authorization: ApiKey pk_invalid.key12345"
```

### Test Missing Authorization

```bash
# Should return 401 Unauthorized
curl -X GET http://localhost:8080/api/v1/providers
```

### Test Wrong Authorization Format

```bash
# Should return 401 Unauthorized (wrong keyword)
curl -X GET http://localhost:8080/api/v1/providers \
  -H "Authorization: Bearer $API_KEY"
```

### Test Expired API Key

Create an API key with short expiration:

```bash
# Create key that expires in 1 minute
EXPIRE_TIME=$(date -u -d '+1 minute' +%Y-%m-%dT%H:%M:%SZ)

EXPIRED_KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/create \
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
echo "Wait 1 minute, then test with: curl -X GET http://localhost:8080/api/v1/providers -H \"Authorization: ApiKey $EXPIRING_API_KEY\""
```

## 8. Advanced Testing Scenarios

### Test Concurrent API Key Usage

Create multiple concurrent requests:

```bash
# Run multiple requests in parallel
for i in {1..5}; do
  curl -X GET http://localhost:8080/api/v1/providers \
    -H "Authorization: ApiKey $API_KEY" &
done
wait
```

### Test Rate Limiting (if configured)

Make rapid requests to test rate limiting:

```bash
# Make 20 rapid requests
for i in {1..20}; do
  curl -X GET http://localhost:8080/api/v1/providers \
    -H "Authorization: ApiKey $API_KEY"
  sleep 0.1
done
```

### Test API Key Revocation

Revoke an API key and verify it stops working:

```bash
# Revoke the API key
curl -X DELETE http://localhost:8080/api/v1/tenants/$TENANT_ID/api-keys/$API_KEY_ID \
  -H "Authorization: Bearer $JWT_TOKEN"

# Test that revoked key no longer works (should return 401)
curl -X GET http://localhost:8080/api/v1/providers \
  -H "Authorization: ApiKey $API_KEY"
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
