# AWS Organizations Bulk Account Connection - Frontend Implementation Guide

## Overview

This document provides all the backend context a frontend developer needs to implement the AWS Organizations bulk account connection feature in the Prowler UI. This feature allows SaaS users to connect all their AWS accounts at once using AWS Organizations, instead of adding them one by one.

**OSS vs SaaS behavior:** In the open-source version, the "Add Multiple Accounts With AWS Organizations" option is **disabled** with a "Get Prowler Cloud" CTA badge. In the SaaS version, this option is fully functional.

---

## Table of Contents

1. [User Workflow (from Figma)](#1-user-workflow)
2. [Backend API Endpoints](#2-backend-api-endpoints)
3. [Data Models & Resource Types](#3-data-models--resource-types)
4. [Step-by-Step API Flow](#4-step-by-step-api-flow)
5. [Discovery Result Schema](#5-discovery-result-schema)
6. [Apply Endpoint Details](#6-apply-endpoint-details)
7. [Error Handling](#7-error-handling)
8. [Existing Frontend Architecture](#8-existing-frontend-architecture)
9. [Testing Strategy](#9-testing-strategy)
10. [PR References](#10-pr-references)

---

## 1. User Workflow

Based on the Figma designs, the workflow adds a **method selection** step at the beginning of the existing provider form (Step 1), when the user selects AWS:

### Step 1: Choose Connection Method (NEW - AWS only)

After selecting AWS as the provider type, the user sees two radio options:

1. **"Add A Single AWS Cloud Account"** - Existing flow (continues to current UID input)
2. **"Add Multiple Accounts With AWS Organizations"** - New flow (described below)
   - **OSS:** Disabled, shows a gradient "Get Prowler Cloud" CTA badge (see Figma node `10248:3258`)
   - **SaaS:** Enabled, enters the Organizations workflow

### Step 2: Organization Setup (NEW)

When "Add Multiple Accounts" is selected, the user:

1. Enters an **Organization Name** (free text, min 3 chars)
2. Enters the **AWS Organization ID** (e.g., `o-abc123def4`)
3. Enters **Role ARN** for the management account role (e.g., `arn:aws:iam::123456789012:role/ProwlerOrgRole`)
4. Enters **External ID** for secure role assumption
5. Clicks "Next" to create the Organization + Secret and trigger discovery

### Step 3: Review Discovered Accounts (NEW)

After discovery completes, the user sees:

- A tree/list of all discovered **Organizational Units (OUs)**
- A list of all discovered **AWS accounts** with their status:
  - Which accounts are new vs. already connected
  - Which accounts have conflicts (already linked to another org)
  - Which accounts will get auto-generated credentials
- The user can **select/deselect** individual accounts and OUs to apply
- Each account shows its `registration` status (ready/blocked)

### Step 4: Apply & Connect

The user clicks "Apply" to bulk-create all providers, link them to the organization and OUs, and auto-generate per-account role-based credentials.

### Step 5: Validate Connection & Launch Scan

Same as the existing Step 3 (test connection), but now applied to the newly created providers.

---

## 2. Backend API Endpoints

All endpoints use **JSON:API** format (`Content-Type: application/vnd.api+json`). Base URL: `/api/v1/`.

### 2.1 Organizations CRUD

| Method   | URL                          | Description                    | Response Code |
|----------|------------------------------|--------------------------------|---------------|
| `GET`    | `/organizations`             | List organizations             | 200           |
| `POST`   | `/organizations`             | Create organization            | 201           |
| `GET`    | `/organizations/{id}`        | Retrieve organization          | 200           |
| `PATCH`  | `/organizations/{id}`        | Update organization            | 200           |
| `DELETE` | `/organizations/{id}`        | Soft-delete org (async)        | 202 (Task)    |

> **DELETE behavior:** Returns `202 Accepted` with a `tasks` resource body and a `content-location` header pointing to the task URL (same pattern as `DELETE /providers`). The soft-delete takes effect immediately in the UI (resources disappear from listings), while the async task handles background cleanup (unlinking providers, cascading to OUs, etc.).

**Filters:** `org_type` (exact), `external_id` (exact)

### 2.2 Organization Secrets CRUD

| Method   | URL                            | Description            | Response Code |
|----------|--------------------------------|------------------------|---------------|
| `GET`    | `/organization-secrets`        | List secrets           | 200           |
| `POST`   | `/organization-secrets`        | Create secret          | 201           |
| `GET`    | `/organization-secrets/{id}`   | Retrieve secret        | 200           |
| `PATCH`  | `/organization-secrets/{id}`   | Update secret          | 200           |
| `DELETE` | `/organization-secrets/{id}`   | Hard delete secret     | 204           |

**Filters:** `organization_id` (UUID)

### 2.3 Discovery Endpoints

| Method | URL                                                  | Description               | Response Code |
|--------|------------------------------------------------------|---------------------------|---------------|
| `POST` | `/organizations/{id}/discover`                       | Trigger async discovery   | 202           |
| `GET`  | `/organizations/{id}/discoveries`                    | List discoveries          | 200           |
| `GET`  | `/organizations/{org_id}/discoveries/{id}`           | Retrieve discovery result | 200           |
| `POST` | `/organizations/{org_id}/discoveries/{id}/apply`     | Apply discovery results   | 200           |

### 2.4 Organizational Units CRUD

| Method   | URL                              | Description          | Response Code |
|----------|----------------------------------|----------------------|---------------|
| `GET`    | `/organizational-units`          | List OUs             | 200           |
| `POST`   | `/organizational-units`          | Create OU            | 201           |
| `GET`    | `/organizational-units/{id}`     | Retrieve OU          | 200           |
| `PATCH`  | `/organizational-units/{id}`     | Update OU            | 200           |
| `DELETE` | `/organizational-units/{id}`     | Soft-delete OU       | 202 (Task)    |

> **DELETE behavior:** Same as Organizations DELETE - returns `202 Accepted` with a `tasks` resource body and `content-location` header. Soft-delete is immediate in the UI; background task handles cleanup.

**Filters:** `organization_id` (UUID), `parent_id` (UUID), `external_id` (exact)

### 2.5 Relationship Endpoints (Provider Linkage)

| Method   | URL                                                        | Description                    | Response Code |
|----------|------------------------------------------------------------|--------------------------------|---------------|
| `POST`   | `/organizations/{id}/relationships/providers`              | Add providers to org           | 204           |
| `PATCH`  | `/organizations/{id}/relationships/providers`              | Replace org providers          | 204           |
| `DELETE` | `/organizations/{id}/relationships/providers`              | Remove all org providers       | 204           |
| `POST`   | `/organizational-units/{id}/relationships/providers`       | Add providers to OU            | 204           |
| `PATCH`  | `/organizational-units/{id}/relationships/providers`       | Replace OU providers           | 204           |
| `DELETE` | `/organizational-units/{id}/relationships/providers`       | Remove all OU providers        | 204           |

---

## 3. Data Models & Resource Types

### 3.1 JSON:API Resource Types

| Resource Type                            | Description                               |
|------------------------------------------|-------------------------------------------|
| `organizations`                          | AWS/Azure/GCP organization                |
| `organizational-units`                   | OU within an organization                 |
| `organization-secrets`                   | Encrypted role-assumption credentials     |
| `organization-discoveries`               | Async discovery job record                |
| `organization-discovery-apply-results`   | Response from applying a discovery        |
| `organization-provider-relationships`    | Org-to-provider linkage                   |
| `organizational-unit-provider-relationships` | OU-to-provider linkage               |
| `tasks`                                  | Async task (returned on DELETE 202)       |

### 3.2 Organization Model

```typescript
interface Organization {
  id: string;                          // UUID
  type: "organizations";
  attributes: {
    name: string;                      // min 3 chars
    org_type: "aws" | "azure" | "gcp";
    external_id: string;               // e.g., "o-abc123def4"
    metadata: Record<string, any>;
    root_external_id: string | null;   // Set after discovery (e.g., "r-abc1")
    inserted_at: string;               // ISO datetime
    updated_at: string;                // ISO datetime
  };
  relationships: {
    providers: { data: Array<{ type: "providers"; id: string }> };
    organizational_units: { data: Array<{ type: "organizational-units"; id: string }> };
  };
}
```

### 3.3 Organization Secret Model

```typescript
interface OrganizationSecret {
  id: string;
  type: "organization-secrets";
  attributes: {
    secret_type: "role";               // Only "role" supported currently
    // NOTE: `secret` field is WRITE-ONLY - never returned in GET responses
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    organization: { data: { type: "organizations"; id: string } };
  };
}

// Write-only secret payload (for POST/PATCH)
interface OrganizationSecretPayload {
  role_arn: string;                    // e.g., "arn:aws:iam::123456789012:role/ProwlerOrgRole"
  external_id: string;                 // Required for secure cross-account access
  role_session_name?: string;          // Optional, defaults to "ProwlerSession"
  session_duration?: number;           // Optional, in seconds
}
```

### 3.4 Organization Discovery Model

```typescript
interface OrganizationDiscovery {
  id: string;
  type: "organization-discoveries";
  attributes: {
    status: "pending" | "running" | "succeeded" | "failed";
    result: DiscoveryResult | {};      // Populated when status === "succeeded"
    error: string | null;              // Populated when status === "failed"
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    organization: { data: { type: "organizations"; id: string } };
  };
}
```

### 3.5 Organizational Unit Model

```typescript
interface OrganizationalUnit {
  id: string;                          // UUID (internal Prowler ID)
  type: "organizational-units";
  attributes: {
    name: string;                      // min 3 chars
    external_id: string;               // AWS OU ID (e.g., "ou-abc1-12345678")
    metadata: Record<string, any>;     // May contain { arn: "..." }
    inserted_at: string;
    updated_at: string;
  };
  relationships: {
    organization: { data: { type: "organizations"; id: string } };
    parent: { data: { type: "organizational-units"; id: string } | null };
    providers: { data: Array<{ type: "providers"; id: string }> };
  };
}
```

---

## 4. Step-by-Step API Flow

### Flow 1: Create Organization + Secret + Trigger Discovery

```
Frontend                                              Backend
   |                                                     |
   |-- POST /organizations ---------------------------->|  (1) Create org
   |<-- 201 { org.id } --------------------------------|
   |                                                     |
   |-- POST /organization-secrets --------------------->|  (2) Create secret
   |<-- 201 { secret.id } -----------------------------|
   |                                                     |
   |-- POST /organizations/{org.id}/discover ---------->|  (3) Trigger discovery
   |<-- 202 { discovery.id, status: "pending" } -------|
   |                                                     |
   |-- GET /organizations/{org.id}/discoveries/{id} --->|  (4) Poll for status
   |<-- 200 { status: "running" } ---------------------|     (repeat until done)
   |                                                     |
   |-- GET /organizations/{org.id}/discoveries/{id} --->|  (5) Discovery complete
   |<-- 200 { status: "succeeded", result: {...} } ----|
   |                                                     |
```

### Flow 2: Review & Apply Discovery

```
Frontend                                              Backend
   |                                                     |
   |  (User reviews discovered accounts in the UI)       |
   |  (User selects which accounts/OUs to apply)         |
   |                                                     |
   |-- POST /.../discoveries/{id}/apply --------------->|  (6) Apply selections
   |<-- 200 { providers_created_count, ... } -----------|
   |                                                     |
   |  (Redirect to test-connection for created providers)|
   |                                                     |
```

### Detailed Request/Response Examples (Verified from Bruno API Client)

#### (1) Create Organization

```http
POST /api/v1/organizations
Content-Type: application/vnd.api+json

{
  "data": {
    "type": "organizations",
    "attributes": {
      "name": "Prowler org",
      "org_type": "aws",
      "external_id": "o-az6b84scgf"
    }
  }
}
```

**Response (201 Created, 251ms):**
```json
{
  "data": {
    "type": "organizations",
    "id": "ac6271ef-dede-425d-aee7-0109a9a402ba",
    "attributes": {
      "name": "Prowler org",
      "org_type": "aws",
      "external_id": "o-az6b84scgf",
      "metadata": {},
      "root_external_id": null
    }
  },
  "meta": {
    "version": "v1"
  }
}
```

#### (2) Create Organization Secret

```http
POST /api/v1/organization-secrets
Content-Type: application/vnd.api+json

{
  "data": {
    "type": "organization-secrets",
    "attributes": {
      "secret_type": "role",
      "secret": {
        "role_arn": "arn:aws:iam::741399645537:role/ProwlerScan",
        "external_id": "a3b26b14-cbfe-40e8-b54c-dd6e2bfa8780"
      }
    },
    "relationships": {
      "organization": {
        "data": { "type": "organizations", "id": "ac6271ef-dede-425d-aee7-0109a9a402ba" }
      }
    }
  }
}
```

**Response (201):**
```json
{
  "data": {
    "type": "organization-secrets",
    "id": "dfd50cf3-dcb1-4e56-9239-c57b78734778",
    "attributes": {
      "secret_type": "role",
      "inserted_at": "2026-02-10T11:39:48.135685Z",
      "updated_at": "2026-02-10T11:39:48.135700Z"
    },
    "relationships": {
      "organization": {
        "data": {
          "type": "organizations",
          "id": "776bd4af-2e77-47ce-8784-eb76616fb9f5"
        }
      }
    }
  },
  "meta": {
    "version": "v1"
  }
}
```

> **Note:** The `secret` field is write-only and never returned in responses.

#### (3) Trigger Discovery

```http
POST /api/v1/organizations/ac6271ef-dede-425d-aee7-0109a9a402ba/discover
```

No request body required.

**Response (202 Accepted, 288ms):**
```json
{
  "data": {
    "type": "organization-discoveries",
    "id": "42883eee-5a67-4426-8872-a638d66ba169",
    "attributes": {
      "status": "pending",
      "result": {},
      "error": null,
      "inserted_at": "2026-02-10T11:59:43.152443Z",
      "updated_at": "2026-02-10T11:59:43.152456Z"
    },
    "relationships": {
      "organization": {
        "data": {
          "type": "organizations",
          "id": "ac6271ef-dede-425d-aee7-0109a9a402ba"
        }
      }
    }
  },
  "meta": {
    "version": "v1"
  }
}
```

**Response Headers include:**
```
content-location: /api/v1/organizations/ac6271ef-dede-425d-aee7-0109a9a402ba/discoveries/42883eee-5a67-4426-8872-a638d66ba169
content-type: application/vnd.api+json
```

> Use the `content-location` header value to poll for discovery status.

#### (4) Poll Discovery Status (GET until `succeeded` or `failed`)

```http
GET /api/v1/organizations/ac6271ef-dede-425d-aee7-0109a9a402ba/discoveries/42883eee-5a67-4426-8872-a638d66ba169
```

Poll every 2-5 seconds. Status transitions: `pending` -> `running` -> `succeeded` | `failed`

**Response when `succeeded` (200):**
```json
{
  "data": {
    "type": "organization-discoveries",
    "id": "42883eee-5a67-4426-8872-a638d66ba169",
    "attributes": {
      "status": "succeeded",
      "result": {
        "roots": [
          {
            "id": "r-3iiw",
            "arn": "arn:aws:organizations::741399645537:root/o-az6b84scgf/r-3iiw",
            "name": "Root",
            "policy_types": [
              { "Type": "AISERVICES_OPT_OUT_POLICY", "Status": "ENABLED" },
              { "Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED" },
              { "Type": "TAG_POLICY", "Status": "ENABLED" }
            ]
          }
        ],
        "accounts": [
          {
            "id": "106908755756",
            "arn": "arn:aws:organizations::741399645537:account/o-az6b84scgf/106908755756",
            "name": "prowler-dev",
            "email": "ops+106908755756@prowler.com",
            "status": "ACTIVE",
            "parent_id": "ou-3iiw-4gs9ihzb",
            "joined_method": "CREATED",
            "joined_timestamp": "2022-02-17T14:59:38.887000+00:00",
            "registration": {
              "provider_exists": true,
              "provider_id": "ea6cba06-14c2-4e18-9848-6fb5969e4e9e",
              "organization_relation": "link_required",
              "organizational_unit_relation": "link_required",
              "provider_secret_state": "already_exists",
              "apply_status": "ready",
              "blocked_reasons": []
            }
          },
          {
            "id": "489604170099",
            "arn": "arn:aws:organizations::741399645537:account/o-az6b84scgf/489604170099",
            "name": "prowler-demo",
            "email": "ops+489604170099@prowler.com",
            "status": "ACTIVE"
          }
        ],
        "organizational_units": [
          {
            "id": "ou-3iiw-4gs9ihzb",
            "name": "...",
            "arn": "...",
            "parent_id": "r-3iiw"
          }
        ]
      },
      "error": null
    }
  }
}
```

> The `registration` object on each account tells the frontend exactly what will happen when applied (see Section 5 for full schema).

---

## 5. Discovery Result Schema

When a discovery succeeds, the `result` attribute contains the full AWS Organization structure, enriched with `registration` state for each account:

```typescript
interface DiscoveryResult {
  organization: {
    id: string;                        // AWS org ID (e.g., "o-abc123def4")
    arn: string;
    feature_set: string;               // e.g., "ALL"
    management_account_id: string;     // e.g., "123456789012"
    management_account_arn: string;
    management_account_email: string;
  };
  roots: Array<{
    id: string;                        // e.g., "r-abc1"
    arn: string;
    name: string;                      // e.g., "Root"
    policy_types: any[];
  }>;
  organizational_units: Array<{
    id: string;                        // AWS OU ID (e.g., "ou-abc1-12345678")
    name: string;                      // e.g., "Production"
    arn: string;
    parent_id: string;                 // Parent OU ID or Root ID
  }>;
  accounts: Array<DiscoveredAccount>;
}

interface DiscoveredAccount {
  id: string;                          // AWS Account ID (e.g., "123456789012")
  name: string;                        // Account name
  arn: string;
  email: string;
  status: "ACTIVE" | "SUSPENDED" | "PENDING_CLOSURE" | "CLOSED";
  joined_method: "INVITED" | "CREATED";
  joined_timestamp: string;            // ISO datetime
  parent_id: string;                   // Parent OU ID or Root ID

  // Enriched by backend when retrieving discovery
  registration: {
    provider_exists: boolean;          // Account already registered as a Prowler provider
    provider_id: string | null;        // Existing provider UUID if exists

    organization_relation:
      | "already_linked"               // Provider already linked to THIS org
      | "link_required"                // Provider exists but not linked (or doesn't exist yet)
      | "linked_to_other_organization"; // CONFLICT: linked to a different org

    organizational_unit_relation:
      | "not_applicable"               // Account's parent is a root (not an OU)
      | "already_linked"               // Already linked to the correct OU
      | "link_required"                // Needs to be linked to an OU
      | "linked_to_other_ou"           // CONFLICT: linked to a different OU
      | "unchanged";                   // Provider in an OU but parent isn't a discovered OU

    provider_secret_state:
      | "already_exists"               // Provider already has credentials
      | "will_create"                  // Credentials will be auto-generated from org role
      | "manual_required";             // No org role pattern - user must add manually

    apply_status: "ready" | "blocked"; // Whether this account can be applied
    blocked_reasons: string[];         // e.g., ["organization_conflict", "organizational_unit_conflict"]
  };
}
```

### Registration State Decision Logic

| Condition | `organization_relation` | `apply_status` |
|-----------|------------------------|----------------|
| Provider doesn't exist | `link_required` | `ready` |
| Provider exists, not linked to any org | `link_required` | `ready` |
| Provider exists, linked to THIS org | `already_linked` | `ready` |
| Provider exists, linked to ANOTHER org | `linked_to_other_organization` | `blocked` |

### Secret Auto-Generation Logic

The backend derives per-account role ARNs from the org-level role ARN:
- **Org role ARN:** `arn:aws:iam::123456789012:role/ProwlerOrgRole`
- **Derived account role ARN:** `arn:aws:iam::{account_id}:role/ProwlerOrgRole`

This only happens when:
1. The org secret has a `role_arn` containing `:role/`
2. The org secret has an `external_id`
3. The provider doesn't already have a secret

---

## 6. Apply Endpoint Details

### Request (Verified from Bruno)

```http
POST /api/v1/organizations/ac6271ef-dede-425d-aee7-0109a9a402ba/discoveries/42883eee-5a67-4426-8872-a638d66ba169/apply
Content-Type: application/vnd.api+json

{
  "data": {
    "type": "organization-discoveries",
    "attributes": {
      "accounts": [
        { "id": "998057895221", "alias": "public-ecr" }
      ],
      "organizational_units": [
        { "id": "ou-3iiw-4gs9ihzb" }
      ]
    }
  }
}
```

**Notes:**
- An **empty body** (`{}`), empty arrays (`[]`), or **omitted** `accounts`/`organizational_units` fields will apply **ALL** discovered accounts and OUs.
- If you **don't want to register any** providers or OUs, simply **don't call this endpoint**.
- To apply a **subset**, explicitly list only the desired account IDs and OU IDs.
- `alias` is optional per account (falls back to the AWS account name).
- The backend automatically includes ancestor OUs even if not explicitly selected.

### Response (200 OK)

> Derived from `OrganizationDiscoveryApplyResultSerializer` in `cloud/v1/serializers.py` (prowler-cloud).

```json
{
  "data": {
    "type": "organization-discovery-apply-results",
    "id": "42883eee-5a67-4426-8872-a638d66ba169",
    "attributes": {
      "providers_created_count": 1,
      "providers_linked_count": 0,
      "providers_applied_count": 1,
      "organizational_units_created_count": 1
    },
    "relationships": {
      "providers": {
        "data": [
          {
            "type": "providers",
            "id": "a1983865-cb1d-4d63-a81b-e9737566a1f7"
          }
        ],
        "meta": {
          "count": 1
        }
      },
      "organizational_units": {
        "data": [
          {
            "type": "organizational-units",
            "id": "af2d994b-c42e-4ed3-bc1b-b2a7b20140f0"
          }
        ],
        "meta": {
          "count": 1
        }
      }
    }
  },
  "meta": {
    "version": "v1"
  }
}
```

**Relationship semantics:**
- `providers` contains **all applied providers** (newly created + existing ones that were linked), sourced from `providers_applied` IDs.
- `organizational_units` contains only **newly created OUs**, sourced from `organizational_units_created` IDs.
- Counts break down the providers: `providers_created_count` (new), `providers_linked_count` (existing, newly linked to org/OU), `providers_applied_count` (total = created + linked).

### What Apply Does (Atomically)

1. Creates/updates OUs in depth-first order (ancestors before children)
2. For each selected account:
   - `get_or_create` Provider (with `provider=aws`, `uid=account_id`)
   - Links provider to the Organization (`OrganizationProvider`)
   - Links provider to its parent OU if applicable (`OrganizationalUnitProvider`)
   - Auto-creates a `ProviderSecret` with derived role ARN (if org secret has a valid role pattern and provider doesn't already have a secret)
3. Sets the organization's `root_external_id` from the discovery result
4. Returns counts and IDs of all created/linked resources

---

## 7. Error Handling

### Validation Errors (400)

```json
{
  "errors": [{
    "detail": "Organization with this type and external ID already exists.",
    "source": { "pointer": "/data/attributes/external_id" }
  }]
}
```

### Conflict Errors (409)

```json
{
  "detail": "One or more providers already belong to another organization."
}
```

### Discovery Prerequisite Error (400)

```json
{
  "errors": [{
    "detail": "Organization secret is required to run discovery."
  }]
}
```

### Apply Prerequisite Error (400)

```json
{
  "errors": [{
    "detail": "Discovery must be in SUCCEEDED status to apply."
  }]
}
```

### Apply Conflict Errors (400)

```json
{
  "errors": [{
    "detail": "One or more providers already belong to another organization.",
    "source": { "pointer": "/data/attributes/accounts" }
  }]
}
```

### Provider Unavailable (400) - from PR #2836

When the backend detects an AWS account has been closed/suspended:
```json
{
  "detail": "Provider aws is unavailable.",
  "status": "400",
  "code": "provider_unavailable"
}
```

---

## 8. Existing Frontend Architecture

### Current Provider Form Structure

```
ui/
├── app/(prowler)/providers/(set-up-provider)/
│   ├── layout.tsx                          # Sidebar stepper + content area
│   ├── connect-account/page.tsx            # Step 1 page
│   ├── add-credentials/page.tsx            # Step 2 page
│   ├── test-connection/page.tsx            # Step 3 page
│   └── update-credentials/page.tsx
├── components/providers/
│   ├── add-provider-button.tsx             # Entry point button
│   ├── radio-group-provider.tsx            # Provider type radio selector
│   ├── workflow/
│   │   ├── workflow-add-provider.tsx        # Main stepper display (3 steps)
│   │   ├── vertical-steps.tsx              # Custom stepper with Framer Motion
│   │   └── forms/
│   │       ├── connect-account-form.tsx     # Step 1: Choose provider + enter UID
│   │       ├── test-connection-form.tsx     # Step 3: Test & scan
│   │       ├── add-via-role-form.tsx        # AWS role-based credentials
│   │       └── add-via-credentials-form.tsx # AWS static credentials
├── actions/providers/
│   └── providers.ts                        # Server actions (addProvider, etc.)
├── hooks/
│   └── use-credentials-form.ts             # Form schema + state management
└── types/
    └── providers.ts                        # TypeScript interfaces
```

### Tech Stack

- **Next.js 16** (App Router)
- **React 19**
- **shadcn/ui** - Component system (all new components)
- **Tailwind CSS 4** - Styling
- **React Hook Form + Zod** - Form management + validation
- **Framer Motion** - Animations (stepper progress)
- **Lucide React** - Icons

> **IMPORTANT - Component Library:** HeroUI (`components/ui/`) is **legacy**. All new components for this feature **MUST** use **shadcn** (`components/shadcn/`) with the new Figma styling tokens. If any existing components in the provider workflow (e.g., radio groups, inputs, buttons, steppers) are currently HeroUI-based, they should be rebuilt in shadcn as part of this work. Do not import from `@heroui/*` for new code.

### Key Integration Points

1. **`connect-account-form.tsx`**: This is where the connection method radio buttons need to be added (Single vs. Organizations) after AWS is selected.
2. **`workflow-add-provider.tsx` / `vertical-steps.tsx`**: The stepper may need additional steps for the organizations flow.
3. **`actions/providers/providers.ts`**: New server actions needed for organization API calls.
4. **`types/providers.ts`**: New TypeScript interfaces needed for organization types.

### SaaS vs OSS Detection

The frontend needs to detect whether the user is on SaaS or OSS to enable/disable the Organizations option. Check existing patterns in the codebase for how this distinction is made (likely via environment variable or feature flag).

---

## 9. Testing Strategy

### Local Testing Limitations

This feature **cannot be fully tested locally**. The Organizations API relies on AWS IAM role assumption (STS `AssumeRole`) to discover accounts and OUs, which requires real AWS credentials and cross-account trust relationships that don't exist in a local dev environment.

**What CAN be tested locally:**
- UI component rendering, form validation, and stepper navigation
- Mock API responses to verify UI state transitions (pending/running/succeeded/failed)
- Error handling UI (validation errors, conflict states, blocked accounts)
- Select/deselect behavior on the discovered accounts review screen

**What CANNOT be tested locally:**
- End-to-end flow from organization creation through discovery to apply
- Real discovery results with actual AWS account data
- Role assumption and secret auto-generation
- Provider connection testing after apply

### E2E Testing in Cloud DEV (Required Before Merge)

Due to the multi-step flow and multiple chained API requests, this feature **must be E2E tested in the cloud DEV environment** before merging. This is non-negotiable — the full flow (create org -> create secret -> discover -> review -> apply -> test connection) must be validated against real AWS Organizations data.

**Deploying UI to cloud DEV:**
- Same process as deploying the API, but the deployment file starts with `ui-` (instead of `api-`).
- Ask the team for the exact deployment steps if unfamiliar.

**E2E test scenarios to cover:**

1. **Happy path:** Create org -> add secret -> trigger discovery -> review accounts -> select subset -> apply -> verify providers created
2. **Apply all:** Trigger apply with empty body -> verify all discovered accounts get registered
3. **Blocked accounts:** Verify accounts with `organization_relation: "linked_to_other_organization"` show as blocked and cannot be selected
4. **Already linked accounts:** Verify accounts with `already_linked` status show correctly (no duplicate creation)
5. **Discovery failure:** Verify UI handles `status: "failed"` gracefully (e.g., invalid role ARN, missing permissions)
6. **Secret auto-generation:** After apply, verify that providers have auto-generated credentials derived from the org role ARN
7. **Delete organization:** Verify soft-delete returns 202, resources disappear from UI immediately
8. **OSS gate:** Verify the "Add Multiple Accounts" option is disabled in OSS with the "Get Prowler Cloud" CTA badge

---

## 10. PR References

### PR #2826 - `feat(api): add organization support` (MERGED)
- **What:** Full Organizations API - CRUD for organizations, OUs, secrets, discovery, and apply
- **Files:** 29 changed, +5,063 / -91
- **Key files:**
  - `api/src/backend/cloud/models.py` - All new models
  - `api/src/backend/cloud/v1/views.py` - All views/endpoints
  - `api/src/backend/cloud/v1/serializers.py` - All serializers
  - `api/src/backend/cloud/v1/urls.py` - URL routing
  - `api/src/backend/cloud/services/organization_discovery.py` - Discovery + apply logic
  - `api/src/backend/cloud/services/organizations.py` - OU hierarchy validation
  - `api/src/backend/tasks/cloud_tasks.py` - Celery task definitions
  - `api/src/backend/tasks/jobs/cloud/organizations/discovery.py` - Async discovery job
  - `api/src/backend/tasks/jobs/cloud/organizations/deletion.py` - Async deletion with rollback

### PR #2836 - `feat(api): handle provider available field logic` (OPEN)
- **What:** Auto-detects closed/suspended AWS accounts and marks providers as `available=false`
- **Frontend impact:** The `provider.available` field may now change automatically. Providers marked as unavailable will not run scheduled scans. Error code `provider_unavailable` (HTTP 400) should be handled.
- **Key files:**
  - `api/src/backend/tasks/jobs/cloud/provider/available.py` - Availability check using AWS Organizations DescribeAccount
  - `api/src/backend/tasks/jobs/scan.py` - Raises `ProviderNotAvailableError` during scan
  - `api/src/backend/cloud/exceptions.py` - `ProviderNotAvailableError` exception (HTTP 400)

---

## Appendix: Quick API Reference Card

```
# 1. Create Organization
POST /api/v1/organizations
Body: { data: { type: "organizations", attributes: { name, org_type: "aws", external_id } } }
=> 201 { data.id = org_id }

# 2. Create Secret (linked to org via relationship)
POST /api/v1/organization-secrets
Body: { data: { type: "organization-secrets", attributes: { secret_type: "role", secret: { role_arn, external_id } }, relationships: { organization: { data: { type: "organizations", id: org_id } } } } }
=> 201 { data.id = secret_id }

# 3. Trigger Discovery (no body)
POST /api/v1/organizations/{org_id}/discover
=> 202 { data.id = discovery_id }
   Headers: content-location = /api/v1/organizations/{org_id}/discoveries/{discovery_id}

# 4. Poll Discovery (repeat until status != "pending" && status != "running")
GET /api/v1/organizations/{org_id}/discoveries/{discovery_id}
=> 200 { data.attributes.status, data.attributes.result }

# 5. Apply Discovery (select accounts + OUs, or empty body/[] for all)
#    If you don't want to register anything, DON'T call this endpoint.
POST /api/v1/organizations/{org_id}/discoveries/{discovery_id}/apply
Body: { data: { type: "organization-discoveries", attributes: { accounts: [{ id, alias? }], organizational_units: [{ id }] } } }
=> 200 { type: "organization-discovery-apply-results", attributes: { counts }, relationships: { providers, organizational_units } }

# Extras:
GET /api/v1/organizational-units?filter[organization_id]={org_id}
DELETE /api/v1/organizations/{org_id}  => 202 + Task resource + content-location header (soft-delete, instant in UI)
```
