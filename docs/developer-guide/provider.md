# Prowler Providers

## Introduction

Providers form the backbone of Prowler, enabling security assessments across various cloud environments.

A provider is any platform or service that offers resources, data, or functionality that can be audited for security and compliance. This includes:

- Cloud Infrastructure Providers (like Amazon Web Services, Microsoft Azure, and Google Cloud)
- Software as a Service (SaaS) Platforms (like Microsoft 365)
- Development Platforms (like GitHub)
- Container Orchestration Platforms (like Kubernetes)

For providers supported by Prowler, refer to [Prowler Hub](https://hub.prowler.com/).

???+ important
    There are some custom providers added by the community, like [NHN Cloud](https://www.nhncloud.com/), that are not maintained by the Prowler team, but can be used in the Prowler CLI. They can be checked directly at the [Prowler GitHub repository](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers).

---

## Provider Types in Prowler

Prowler supports several types of providers, each with its own implementation pattern and use case. Understanding the differences is key to designing your provider correctly.

### 1. SDK Providers

**Definition:**
- Use the official SDK of the provider to interact with its resources and APIs.
- Examples: AWS (boto3), Azure (azure-identity), GCP (google-auth), Kubernetes (kubernetes), M365 (msal/msgraph).

**Typical Use Cases:**
- Cloud platforms and services with mature Python SDKs.
- Need to support multiple authentication methods (profiles, service principals, etc).

**Key Characteristics:**
- Authentication and session management handled by the SDK.
- Arguments: `profile`, `region`, `tenant_id`, `client_id`, `client_secret`, etc.
- Outputs: Standardized via SDK models and responses.

**Example Skeleton:**
```python
from prowler.providers.common.provider import Provider
import boto3  # Example for AWS

class AwsProvider(Provider):
    _type: str = "aws"
    _session: boto3.Session
    # ...
    def __init__(self, profile=None, region=None, ...):
        self._session = boto3.Session(profile_name=profile, region_name=region)
        # ...
```

---

### 2. API Providers

**Definition:**
- Interact directly with the provider's REST API using HTTP requests (e.g., via `requests`).
- Examples: NHN Cloud, GitHub (partially).

**Typical Use Cases:**
- Providers without a mature or official Python SDK.
- Custom or community providers.

**Key Characteristics:**
- Manual management of authentication (tokens, username/password, etc).
- Arguments: `username`, `password`, `tenant_id`, `token`, etc.
- Outputs: Dicts or custom models based on API responses.

**Example Skeleton:**
```python
from prowler.providers.common.provider import Provider
import requests

class NhnProvider(Provider):
    _type: str = "nhn"
    _session: requests.Session
    # ...
    def __init__(self, username, password, tenant_id, ...):
        self._session = requests.Session()
        token = self.get_token(username, password, tenant_id)
        self._session.headers.update({"Authorization": f"Bearer {token}"})
        # ...
```

---

### 3. Tool/Wrapper Providers

**Definition:**
- Integrate a third-party tool as a library and map its arguments/outputs to Prowler's interface.
- Example: IAC (Checkov).

**Typical Use Cases:**
- Infrastructure as Code (IaC) scanning, or when the provider is a CLI tool or external binary/library.

**Key Characteristics:**
- No session or identity management; the tool handles scanning and output.
- Arguments: `scan_path`, `frameworks`, `exclude_path`, etc.
- Outputs: Adapted from the tool's output format.

**Example Skeleton:**
```python
from prowler.providers.common.provider import Provider
from checkov.runner_filter import RunnerFilter

class IacProvider(Provider):
    _type: str = "iac"
    def __init__(self, scan_path, frameworks, ...):
        self.scan_path = scan_path
        self.frameworks = frameworks
        # ...
    def run_scan(self):
        # Call Checkov or similar tool
        ...
```

---

## Adding a New Provider (End-to-End)

To integrate a new provider and make it available in the CLI, API, and UI, follow these steps:

### 1. Create the Provider in the Backend

#### 1.1. Folder Structure

Create a new folder in [`prowler/providers/<new_provider_name>/`](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers):

- `lib/` – Utility functions and core files (see below).
- `services/` – All services to be audited by Prowler checks.
- `__init__.py` – Empty, marks the folder as a Python package.
- `<new_provider_name>_provider.py` – Main provider class (authentication, config, etc).
- `models.py` – Data models for the provider.

**lib/ folder should include:**
- `service/service.py` – Generic service class for all services.
- `arguments/arguments.py` – Argument parsing for the provider.
- `mutelist/mutelist.py` – Mutelist logic for the provider.

???+ important
    If your new provider requires a Python library (such as an official SDK or API client) to connect to its services, add it as a dependency in `pyproject.toml`.

#### 1.2. Implement the Provider Class

All providers inherit from [`prowler/providers/common/provider.py`](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/common/provider.py).

- For **SDK providers**, use the official SDK for authentication and resource access.
- For **API providers**, use `requests` or similar to manage tokens and API calls.
- For **Tool providers**, integrate the tool as a library and map its arguments/outputs.

#### 1.3. Map Arguments and Outputs

- **SDK**: `profile`, `region`, `tenant_id`, `client_id`, `client_secret`, etc.
- **API**: `username`, `password`, `tenant_id`, `token`, etc.
- **Tool**: `scan_path`, `frameworks`, `exclude_path`, etc.

---

### 2. Register the Provider in the CLI

- Ensure your provider is discoverable by the CLI. The CLI dynamically loads providers from the `prowler/providers/` directory.
- Add argument parsing logic in `lib/cli/parser.py` if you need custom CLI flags.

---

### 3. Integrate the Provider in the API

- Register the provider in the backend API (see `api/src/backend/api/models.py` and `api/src/backend/api/v1/views.py`).
- Add your provider to the `ProviderChoices` enum and validation logic if needed.
- Ensure the API can create, update, and manage your provider (see `ProviderViewSet`).

---

### 4. Integrate the Provider in the UI

- Add your provider to the supported list in the UI (see `ui/types/formSchemas.ts`, `ui/components/providers/radio-group-provider.tsx`, and related files).
- Implement the provider's credential form and validation.
- Ensure the provider appears in the provider selection, creation, and management flows.

---

## Implementation Guidance and Examples

Use existing providers as templates:

- [AWS (SDK)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/aws_provider.py)
- [Azure (SDK)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/azure/azure_provider.py)
- [GCP (SDK)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/gcp/gcp_provider.py)
- [Kubernetes (SDK)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/kubernetes/kubernetes_provider.py)
- [M365 (SDK/API)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/m365/m365_provider.py)
- [GitHub (API)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/github/github_provider.py)
- [NHN (API)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/nhn/nhn_provider.py)
- [IAC (Tool)](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/iac/iac_provider.py)

---

## Checklist for New Providers

- [ ] Folder and files created in `prowler/providers/<name>`
- [ ] Provider class implemented and inherits from `Provider`
- [ ] Authentication/session logic implemented
- [ ] Arguments/flags mapped and documented
- [ ] Outputs and metadata standardized
- [ ] Registered in the CLI
- [ ] Registered in the API (models, serializers, views)
- [ ] Registered in the UI (types, forms, selection)
- [ ] Minimal usage example provided

---

## Next Steps

- [How to add a new Service](./services.md)
- [How to add new Checks](./checks.md)
- [How to contribute](../contributing.md)
