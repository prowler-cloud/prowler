<!--
This README is the one shown on Artifact Hub.
Images should use absolute URLs.
-->

# Prowler App Helm Chart

![Version: 0.0.1](https://img.shields.io/badge/Version-0.0.1-informational?style=flat-square)
![AppVersion: 5.17.0](https://img.shields.io/badge/AppVersion-5.17.0-informational?style=flat-square)

Prowler is an Open Cloud Security tool for AWS, Azure, GCP and Kubernetes. It helps for continuous monitoring, security assessments and audits, incident response, compliance, hardening and forensics readiness. Includes CIS, NIST 800, NIST CSF, CISA, FedRAMP, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, Well-Architected Security, ENS and more.

## Architecture

The Prowler App consists of three main components:

- **Prowler UI**: A user-friendly web interface for running Prowler and viewing results, powered by Next.js.
- **Prowler API**: The backend API that executes Prowler scans and stores the results, built with Django REST Framework.
- **Prowler SDK**: A Python SDK that integrates with the Prowler CLI for advanced functionality.

The app leverages the following supporting infrastructure:

- **PostgreSQL**: Used for persistent storage of scan results.
- **Celery Workers**: Facilitate asynchronous execution of Prowler scans.
- **Valkey**: An in-memory database serving as a message broker for the Celery workers.
- **Neo4j**: Graph Database
- **Keda**: Kubernetes Event-driven Autoscaling (Keda) automatically scales the number of Celery worker pods based on the workload, ensuring efficient resource utilization and responsiveness.

## Setup

This guide walks you through installing Prowler App using Helm. For a minimal installation example, see the [minimal installation example](./examples/minimal-installation/).

### Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3.x installed
- `kubectl` configured to access your cluster
- Access to the Prowler Helm chart repository (or local chart)

### Step 1: Create Required Secrets

Before installing the Helm chart, you must create a Kubernetes Secret containing the required authentication keys and secrets.

1. **Generate the required keys and secrets:**

   ```bash
   # Generate Django token signing key (private key)
   openssl genrsa -out private.pem 2048

   # Generate Django token verifying key (public key)
   openssl rsa -in private.pem -pubout -out public.pem

   # Generate Django secrets encryption key
   openssl rand -base64 32

   # Generate Auth secret
   openssl rand -base64 32
   ```

2. **Create the secret file:**

   Create a file named `secrets.yaml` with the following structure:

   ```yaml
   apiVersion: v1
   kind: Secret
   type: Opaque
   metadata:
     name: prowler-secret
   stringData:
     DJANGO_TOKEN_SIGNING_KEY: |
       -----BEGIN PRIVATE KEY-----
       [paste your private key here]
       -----END PRIVATE KEY-----

     DJANGO_TOKEN_VERIFYING_KEY: |
       -----BEGIN PUBLIC KEY-----
       [paste your public key here]
       -----END PUBLIC KEY-----

     DJANGO_SECRETS_ENCRYPTION_KEY: "[paste your encryption key here]"

     AUTH_SECRET: "[paste your auth secret here]"

     NEO4J_PASSWORD: "[prowler-password]"
     NEO4J_AUTH: "neo4j/[prowler-password]"
   ```

   > **Note:** You can use the [example secrets file](./examples/minimal-installation/secrets.yaml) as a template, but **always replace the placeholder values with your own secure keys** before applying.

3. **Apply the secret to your cluster:**

   ```bash
   kubectl apply -f secrets.yaml
   ```

### Step 2: Configure Values

Create a `values.yaml` file to customize your installation. At minimum, you need to configure the UI access method.

**Option A: Using Ingress (Recommended for production)**

```yaml
ui:
  ingress:
    enabled: true
    hosts:
      - host: prowler.example.com
        paths:
          - path: /
            pathType: ImplementationSpecific
```

**Option B: Using authUrl (For proxy setups)**

```yaml
ui:
  authUrl: prowler.example.com
```

> **Note:** See the [minimal installation example](./examples/minimal-installation/values.yaml) for a complete reference.

### Step 3: Install the Chart

Install Prowler App using Helm:

```bash
helm dependency update
helm install prowler prowler/prowler-app -f values.yaml
```

### Using Existing PostgreSQL and Valkey Instances

By default, this Chart uses Bitnami's Charts to deploy [PostgreSQL](https://artifacthub.io/packages/helm/bitnami/postgresql), [Neo4j](https://helm.neo4j.com/neo4j) and [Valkey official helm chart](https://valkey.io/valkey-helm/). **Note:** This default setup is not production-ready.

To connect to existing PostgreSQL, Neo4j and Valkey instances:

1. Create a `Secret` containing the correct database and message broker credentials
2. Reference the secret in the [values.yaml](values.yaml) file api->secrets list

## Contributing

Feel free to contact the maintainer of this repository for any questions or concerns. Contributions are encouraged and appreciated.
