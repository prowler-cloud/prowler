# Prowler Azure Bicep quick-start

This directory hosts the Bicep template that powers the **Deploy to Azure**
button in the Prowler UI (`add-provider` wizard → Azure → Certificate
authentication). It is the Azure equivalent of the CloudFormation quick-create
stack under `../../cloudformation/`.

Deploying `prowler-scan.bicep` at subscription scope provisions everything
Prowler needs to authenticate against the subscription and enumerate resources:

1. An Entra ID App Registration with an X.509 `keyCredentials` entry
   (certificate authentication — no client secrets).
2. A Service Principal for that application.
3. A subscription-scoped assignment of the built-in `Reader` role.
4. A subscription-scoped custom role (`ProwlerRole`) with the two extra
   read/list actions the built-in Reader is missing, and its role assignment.

The template is idempotent: role definitions and role assignments use
deterministic GUIDs derived from `subscription().id` and `applicationName`,
so redeploying updates the existing resources instead of creating duplicates.

## Files

- `prowler-scan.bicep` — Bicep source (source of truth). Uses the
  `Microsoft.Graph` extension registered in `bicepconfig.json`.
- `prowler-scan.json` — compiled ARM JSON. **This is the artifact the
  Deploy to Azure button loads** — Azure Portal's
  `#create/Microsoft.Template/uri/<url>` deep link only accepts ARM JSON,
  not raw Bicep source. Keep it committed and in sync with the `.bicep`.
- `bicepconfig.json` — registers the Microsoft.Graph Bicep extension against
  the public Microsoft Container Registry.
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

Requires the Bicep CLI (`>= 0.30`, for the Microsoft.Graph extension).
Install with `az bicep install` or grab the standalone binary from
<https://github.com/Azure/bicep/releases>.

## Generating the certificate

The user supplies the certificate — the template only receives the
base64-encoded DER of the public certificate. Prowler never sees the private
key during deployment; Microsoft Graph computes and stores the SHA-1
thumbprint from the certificate bytes and returns it as a template output.

### macOS / Linux (OpenSSL)

```bash
# 1. Generate a 4096-bit RSA private key and a matching self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout prowler.key -out prowler.crt \
    -days 365 -nodes -subj "/CN=Prowler"

# 2. Base64-encode the DER form of the public certificate. Feeds
#    `certificateBase64`. IMPORTANT: use `-outform DER` — piping a PEM
#    file through base64 double-encodes it and the deployment will fail.
CERT_BASE64=$(openssl x509 -in prowler.crt -outform DER | base64 | tr -d '\n')

# 3. Base64-encode the private key so you can paste it into Prowler as the
#    Certificate Private Key field. Keep this value secret. Using `< file`
#    (not `-i`) works identically on macOS (BSD) and Linux (GNU).
CERT_KEY_BASE64=$(base64 < prowler.key | tr -d '\n')

echo "certificateBase64 (paste into the Bicep parameter):     $CERT_BASE64"
echo "private key (paste into Prowler UI, keep secret):       $CERT_KEY_BASE64"
```

### Windows (PowerShell)

```powershell
$cert = New-SelfSignedCertificate -Subject "CN=Prowler" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable -KeySpec Signature `
    -KeyLength 4096 -HashAlgorithm SHA256

# certificateBase64: DER of the public certificate, base64-encoded
$certBase64 = [Convert]::ToBase64String($cert.RawData)

# Private key (PKCS#12), base64-encoded — paste into Prowler as
# "Certificate Content", keep secret
$pfxBytes = $cert.Export('Pfx', '')
$keyBase64 = [Convert]::ToBase64String($pfxBytes)

Write-Host "certificateBase64 (paste into the Bicep parameter): $certBase64"
Write-Host "private key (paste into Prowler UI, keep secret): $keyBase64"
```

## Deploying manually (CLI, when the button is not an option)

Deploy the compiled ARM JSON (recommended, matches what the Portal loads):

```bash
az deployment sub create \
    --location westeurope \
    --template-file prowler-scan.json \
    --parameters certificateBase64="$CERT_BASE64"
```

Or deploy the Bicep source directly (Azure CLI compiles it on the fly):

```bash
az deployment sub create \
    --location westeurope \
    --template-file prowler-scan.bicep \
    --parameters certificateBase64="$CERT_BASE64"
```

## After the deployment

Paste the following into the Prowler wizard's Certificate Authentication form:

- **Tenant ID** — `tenantId` output.
- **Client ID** — `applicationId` output.
- **Certificate Content** — the base64-encoded **private key** you generated
  above. This is *not* the certificate you fed into the Bicep template — the
  public cert is already stored inside Entra ID.

The `certificateThumbprint` output is informational; use it to verify the
deployed keyCredential matches the certificate you generated locally.

The manual fallback described in the Azure authentication docs (client
secrets, sovereign clouds, personal accounts) remains supported for
environments where the Bicep template cannot be deployed.
