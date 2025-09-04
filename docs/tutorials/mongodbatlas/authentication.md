# MongoDB Atlas Authentication

MongoDB Atlas provider uses [HTTP Digest Authentication with API key pairs consisting of a public key and private key](https://www.mongodb.com/docs/atlas/configure-api-access/#grant-programmatic-access-to-service).

## Authentication Methods

### Command-Line Arguments

```bash
prowler mongodbatlas --atlas-public-key <public_key> --atlas-private-key <private_key>
```

### Environment Variables

```bash
export ATLAS_PUBLIC_KEY=<public_key>
export ATLAS_PRIVATE_KEY=<private_key>
prowler mongodbatlas
```

## Creating API Keys

### Step-by-Step Guide

1. **Log into MongoDB Atlas**
      - Access the MongoDB Atlas console

2. **Navigate to Access Manager**
      - Go to the organization or project access management section

3. **Select API Keys Tab**
      - Click on the "API Keys" tab

4. **Create API Key**
      - Click "Create API Key"
      - Provide a description for the key

5. **Set Permissions**
      - Grant minimum required permissions

6. **Save Credentials**
      - Note the public key and private key
      - Store credentials securely

For more details about MongoDB Atlas, see the [MongoDB Atlas Tutorial](../tutorials/mongodbatlas/getting-started-mongodbatlas.md).
