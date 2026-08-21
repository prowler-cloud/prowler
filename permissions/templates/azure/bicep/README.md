# Prowler Azure Bicep Template

This directory contains the Bicep source and compiled Azure Resource Manager
(ARM) JSON template documented in the [Azure authentication
guide](../../../../docs/user-guide/providers/azure/authentication.mdx).

Deploying `prowler-scan.bicep` at subscription scope grants a **pre-existing**
App Registration the subscription permissions Prowler needs:

1. A subscription-scoped assignment of the built-in `Reader` role.
2. A subscription-scoped custom role (`ProwlerRole`) with the two extra
   read/list actions the built-in Reader is missing, and its role assignment.

The template is idempotent: role definitions and role assignments use
deterministic GUIDs derived from `subscription().id` and the deployment
label, so redeploying updates the existing resources instead of creating
duplicates.

## Why the template doesn't create the App Registration itself

Microsoft.Graph Bicep resources (`Microsoft.Graph/applications`,
`Microsoft.Graph/servicePrincipals`, etc.) are **not supported by the
Azure Portal "Deploy to Azure" URL flow**. This is a documented Microsoft
limitation, not a permission or configuration problem — see
[microsoftgraph/msgraph-bicep-types#294](https://github.com/microsoftgraph/msgraph-bicep-types/issues/294)
(closed as documented limitation) and Microsoft's own
[permissions and privileges docs](https://learn.microsoft.com/en-us/graph/templates/bicep/concept-permissions-and-privileges),
which list only Azure CLI and Azure PowerShell as supported deployment paths
for templates containing `Microsoft.Graph/*` resources.

A template that includes those resources fails at Portal deploy time with
`Authorization_RequestDenied: Insufficient privileges to complete the
operation` from Microsoft Graph, regardless of the deploying user's Entra
ID role — a **Global Administrator** hits the same wall. Create the App
Registration and upload the certificate separately, then use this template to
grant the existing Service Principal the RBAC roles Prowler needs.

## Required permissions to run the deployment

The account that deploys the template needs `Owner` on the target subscription.
That is enough
to create the custom role definition and assign both roles. `Contributor`
is not sufficient because it cannot create role assignments.

Creating and managing the App Registration requires the relevant Microsoft
Entra ID permission. App Registration creation is available without an
administrator when the tenant setting _Users can register applications_ is
enabled. An administrator authorized to grant tenant-wide consent must approve
the Microsoft Graph application permissions.

## Files

- `prowler-scan.bicep` — Bicep source (source of truth). Vanilla ARM only —
  no `Microsoft.Graph` extension, so it deploys cleanly through the Portal.
- `prowler-scan.json` — compiled ARM JSON. Azure Portal's
  `#create/Microsoft.Template/uri/<url>` deep link only accepts ARM JSON,
  not raw Bicep source. Keep it committed and in sync with the `.bicep`.
- `sync_docs_template.py` — copies the canonical JSON bytes to the public docs
  asset and generates the MDX code snippet shown in the authentication guide.
- `Makefile` — `make build` regenerates the JSON and synchronizes both docs
  outputs; `make check` fails when the Bicep build or either docs output drifts.

Prowler documentation serves the compiled JSON at:

```text
https://docs.prowler.com/assets/templates/azure/prowler-scan.json
```

The **Deploy to Azure** link in the authentication guide opens
`https://portal.azure.com/#create/Microsoft.Template/uri/<encoded-json-url>`,
which loads the documentation-hosted ARM JSON into Azure Portal. The Bicep
source remains in this directory and is not served as a public asset.

## Regenerating the ARM JSON

The Makefile uses the standalone Bicep CLI by default. After editing
`prowler-scan.bicep`, run:

```bash
make build
make check
```

Download the standalone binary from
<https://github.com/Azure/bicep/releases>. To use the Azure CLI wrapper
instead, install it and pass the wrapper command explicitly:

```bash
az bicep install
make build BICEP='az bicep'
make check BICEP='az bicep'
```

The Makefile adds Azure CLI's required `--file` option when
`BICEP='az bicep'` is set.

## Manual App Registration and Certificate Steps

1. **Create the App Registration** in Portal → **Microsoft Entra ID** →
   **App registrations** → **New registration**. Give it any name, keep
   the default _single tenant_ audience, no redirect URI.
2. **Upload the certificate** on the same App Registration → **Certificates
   and secrets** → **Certificates** tab → **Upload certificate**. Upload
   the public `.cer` file. Prowler's **Generate certificate** button downloads
   `prowler-cert.cer` directly and fills the private bundle field.
3. **Grant Microsoft Graph permissions** on the App Registration. Add the
   `AuditLog.Read.All`, `Directory.Read.All` (or `Domain.Read.All`), and
   `Policy.Read.All` application permissions, then grant admin consent.
4. **Copy the Service Principal Object ID**: Portal → **Microsoft Entra
   ID** → **Enterprise applications** → search for the app you just
   created → click it → **Object ID** on the Overview page. That is the
   value the Bicep template asks for as `servicePrincipalObjectId`. It is
   NOT the same as the App Registration's Object ID (Enterprise
   applications and App registrations are two separate objects with
   separate Object IDs — same App ID / Client ID, different Object IDs).
5. **Copy the Application (client) ID** from the App Registration overview
   — provide this value in Prowler's _Client ID_ field.

### Certificate generation cheatsheet

**Generate certificate** in Prowler is the easiest option — it
generates a keypair in your browser, auto-fills the base64-encoded
certificate and private key bundle into the wizard, and downloads the raw
DER public certificate as `prowler-cert.cer` for upload to the App
Registration.

If you prefer the command line:

#### macOS / Linux (OpenSSL)

```bash
# 1. Generate a 4096-bit RSA private key and matching self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout prowler.key -out prowler.crt \
    -days 365 -nodes -subj "/CN=Prowler"

# 2. Upload prowler.crt to the App Registration (Portal, step 2 above).

# 3. Bundle certificate + private key into a single PEM and base64-encode
#    it. `azure.identity.CertificateCredential` needs BOTH parts — a
#    key-only file fails with "No certificate found". Keep this value
#    secret; it is what Prowler uses to authenticate.
cat prowler.crt prowler.key > prowler-bundle.pem
CERT_BUNDLE_BASE64=$(base64 < prowler-bundle.pem | tr -d '\n')

echo "Certificate and Private Key Bundle for Prowler: $CERT_BUNDLE_BASE64"
```

#### Windows (PowerShell)

```powershell
$cert = New-SelfSignedCertificate -Subject "CN=Prowler" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable -KeySpec Signature `
    -KeyLength 4096 -HashAlgorithm SHA256

# Save the .cer to upload in the Portal
Export-Certificate -Cert $cert -FilePath prowler.cer

# Certificate and private key bundle (PKCS#12), base64-encoded — paste into
# Prowler. Keep secret.
$pfxBytes = $cert.Export('Pfx', '')
$keyBase64 = [Convert]::ToBase64String($pfxBytes)

Write-Host "Certificate and Private Key Bundle for Prowler: $keyBase64"
```

## Deploying manually (CLI, when the button is not an option)

Deploy the compiled ARM JSON (recommended, matches what the Portal loads):

```bash
az deployment sub create \
    --location westeurope \
    --template-file prowler-scan.json \
    --parameters servicePrincipalObjectId=<sp-object-id>
```

Or deploy the Bicep source directly (Azure CLI compiles it on the fly):

```bash
az deployment sub create \
    --location westeurope \
    --template-file prowler-scan.bicep \
    --parameters servicePrincipalObjectId=<sp-object-id>
```

## After the Deployment

Paste the following into Prowler's Certificate Authentication form:

- **Tenant ID** — the `tenantId` output (also visible in Portal → Entra ID
  → Overview).
- **Client ID** — the Application (client) ID of the App Registration you
  created manually in step 1 of the manual flow above.
- **Certificate and Private Key Bundle** — the base64-encoded PEM bundle
  (certificate + private key) or PKCS#12 export from the generation step.
  This bundle is submitted to Prowler and never touches Azure.

The manual fallback described in the Azure authentication docs (client
secrets, sovereign clouds, personal accounts) remains supported for
environments where the Bicep template cannot be deployed.
