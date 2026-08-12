# Prowler Azure Bicep quick-start

This directory hosts the Bicep template that powers the **Deploy to Azure**
button in the Prowler UI (`add-provider` wizard → Azure → Certificate
authentication). It is the Azure equivalent of the CloudFormation quick-create
stack under `../../cloudformation/`.

Deploying `prowler-scan.bicep` at subscription scope grants a **pre-existing**
App Registration the read-only permissions Prowler needs:

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
ID role — a **Global Administrator** hits the same wall. The wizard
therefore splits the flow: the user creates the App Registration and
uploads the certificate manually in the Portal (both operations *are*
supported through the Portal UI), then this template only grants that
existing service principal the RBAC roles Prowler needs.

## Required permissions to run the deployment

The account that clicks **Deploy to Azure** (or runs `az deployment sub
create` locally) needs `Owner` on the target subscription. That is enough
to create the custom role definition and assign both roles. `Contributor`
is not sufficient because it cannot create role assignments.

Creating the App Registration and uploading its certificate (the manual
Portal steps *before* the Deploy to Azure click) require either the tenant
setting *Users can register applications* to be enabled, or one of
`Application Administrator`, `Cloud Application Administrator`, or
`Global Administrator` in Entra ID. The wizard surfaces these prerequisites
on the Certificate Authentication step.

## Files

- `prowler-scan.bicep` — Bicep source (source of truth). Vanilla ARM only —
  no `Microsoft.Graph` extension, so it deploys cleanly through the Portal.
- `prowler-scan.json` — compiled ARM JSON. **This is the artifact the
  Deploy to Azure button loads** — Azure Portal's
  `#create/Microsoft.Template/uri/<url>` deep link only accepts ARM JSON,
  not raw Bicep source. Keep it committed and in sync with the `.bicep`.
- `bicepconfig.json` — kept for the `az bicep build` invocation; no
  extensions are required now that Microsoft.Graph resources have moved
  to the manual Portal step, but the config file lets us re-add the
  extension if a future Microsoft update supports Portal deployments.
- `Makefile` — `make build` regenerates the JSON; `make check` fails when
  the JSON is stale relative to the Bicep source (used by CI).

Both files are hosted at:

```text
https://prowler-cloud-public.s3.eu-west-1.amazonaws.com/permissions/templates/azure/bicep/prowler-scan.json
https://prowler-cloud-public.s3.eu-west-1.amazonaws.com/permissions/templates/azure/bicep/prowler-scan.bicep
```

The Deploy to Azure button opens
`https://portal.azure.com/#create/Microsoft.Template/uri/<encoded-json-url>`,
which loads the ARM JSON into the Portal deployment wizard.

## Regenerating the ARM JSON

After editing `prowler-scan.bicep`, run:

```bash
make build
```

Requires the Bicep CLI. Install with `az bicep install` or grab the
standalone binary from <https://github.com/Azure/bicep/releases>.

## Manual App Registration + certificate steps (what the wizard guides)

1. **Create the App Registration** in Portal → **Microsoft Entra ID** →
   **App registrations** → **New registration**. Give it any name, keep
   the default *single tenant* audience, no redirect URI.
2. **Upload the certificate** on the same App Registration → **Certificates
   and secrets** → **Certificates** tab → **Upload certificate**. Upload
   the `.cer` (public) file you generated. Prowler's *Generate certificate
   for me* button in the wizard produces a base64 file that decodes back to
   the required `.cer` (see the wizard for the exact one-liner).
3. **Copy the Service Principal Object ID**: Portal → **Microsoft Entra
   ID** → **Enterprise applications** → search for the app you just
   created → click it → **Object ID** on the Overview page. That is the
   value the Bicep template asks for as `servicePrincipalObjectId`. It is
   NOT the same as the App Registration's Object ID (Enterprise
   applications and App registrations are two separate objects with
   separate Object IDs — same App ID / Client ID, different Object IDs).
4. **Copy the Application (client) ID** from the App Registration overview
   — you paste this in the Prowler wizard's *Client ID* field.

### Certificate generation cheatsheet

`Generate certificate for me` in the wizard is the easiest option — it
generates a keypair in your browser, auto-fills the private key into the
wizard, and downloads a text file with the base64-encoded public
certificate you upload to the App Registration.

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

echo "Certificate Private Key for Prowler wizard: $CERT_BUNDLE_BASE64"
```

#### Windows (PowerShell)

```powershell
$cert = New-SelfSignedCertificate -Subject "CN=Prowler" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable -KeySpec Signature `
    -KeyLength 4096 -HashAlgorithm SHA256

# Save the .cer to upload in the Portal
Export-Certificate -Cert $cert -FilePath prowler.cer

# Private key (PKCS#12), base64-encoded — paste into the Prowler wizard as
# Certificate Private Key. Keep secret.
$pfxBytes = $cert.Export('Pfx', '')
$keyBase64 = [Convert]::ToBase64String($pfxBytes)

Write-Host "Certificate Private Key for Prowler wizard: $keyBase64"
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

## After the deployment

Paste the following into the Prowler wizard's Certificate Authentication form:

- **Tenant ID** — the `tenantId` output (also visible in Portal → Entra ID
  → Overview).
- **Client ID** — the Application (client) ID of the App Registration you
  created manually in step 1 of the manual flow above.
- **Certificate Private Key** — the base64-encoded PEM bundle (certificate
  + private key) or PKCS#12 export from the generation step. This is
  Prowler's copy of the private half of the keypair; it never leaves the
  wizard and never touches Azure.

The manual fallback described in the Azure authentication docs (client
secrets, sovereign clouds, personal accounts) remains supported for
environments where the Bicep template cannot be deployed.
