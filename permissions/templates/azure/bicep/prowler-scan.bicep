// -----------------------------------------------------------------------------
// Prowler quick-start deployment
//
// One-shot Bicep template that stands up everything Prowler needs to scan an
// Azure subscription with certificate-based authentication:
//   1. An Entra ID App Registration with an X.509 certificate credential
//      (`keyCredentials`) — no client secrets, no deploymentScripts.
//   2. A Service Principal for that App Registration.
//   3. A role assignment granting the built-in `Reader` role at subscription
//      scope so Prowler can inventory resources.
//   4. A subscription-scoped custom "ProwlerRole" that grants the two extra
//      read/list actions the built-in Reader is missing
//      (`Microsoft.Web/sites/host/listkeys/action` and
//      `Microsoft.Web/sites/config/list/Action`), plus its role assignment.
//
// This mirrors the AWS CloudFormation quick-create flow shipped in
// `permissions/templates/cloudformation/prowler-scan-role.yml`, and matches
// the "manual" instructions in
// `docs/user-guide/providers/azure/authentication.mdx`. Keep them in sync
// when adding or removing permissions here.
//
// After the deployment succeeds, copy the outputs (tenantId, clientId, and
// certificateThumbprint) into Prowler along with the private key that pairs
// with `certificateBase64`.
// -----------------------------------------------------------------------------

targetScope = 'subscription'

@description('Name for the App Registration Prowler will use. Keep the default unless you need a custom name.')
param applicationName string = 'ProwlerApp'

@description('Paste the PUBLIC certificate from the Prowler wizard (prowler-cert-base64.txt) or your own openssl output. Prowler never receives the matching private key.')
@secure()
param certificateBase64 string

@description('Label for the certificate inside the App Registration. Cosmetic — keep the default if unsure.')
param certificateDisplayName string = 'Prowler Certificate'

@description('When the certificate becomes valid. Defaults to now.')
param certificateStartDateTime string = utcNow()

@description('When the certificate expires. Defaults to 1 year from now. Rotate before this date.')
param certificateEndDateTime string = dateTimeAdd(utcNow(), 'P1Y')

@description('Name of the extra role Prowler creates. Keep the default unless your org already uses this name.')
param customRoleName string = 'ProwlerRole'

// Deterministic GUIDs derived from `subscription().id` and the params so
// re-deploying the same template into the same subscription is idempotent —
// the role definition and the two role assignments are found and updated
// instead of duplicated. `guid()` is safe to call at subscription scope.
// The role-assignment names cannot reference `servicePrincipal.id`
// because ARM needs those names calculable before the deployment starts;
// pinning to `applicationName` gives a stable identity per app.
var customRoleDefinitionName = guid(subscription().id, customRoleName)
var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7' // built-in Reader
)

// Microsoft Graph resources are provisioned through the `Microsoft.Graph`
// Bicep extension. `apiVersion: v1.0` is the stable channel; the resource
// names below are the type names Graph exposes for Bicep, not ARM.

extension microsoftGraphV1

// `uniqueName` on Microsoft.Graph/applications is tenant-scoped (an existing
// value UPSERTs the resource), so two subscriptions in the same tenant
// deploying with the default `applicationName` would otherwise overwrite
// each other's keyCredentials and silently break the previous scan. Suffix
// with the subscription id to keep each deployment isolated. The visible
// display name stays as the user-provided `applicationName`.
resource application 'Microsoft.Graph/applications@v1.0' = {
  uniqueName: '${applicationName}-${subscription().subscriptionId}'
  displayName: applicationName
  description: 'Deployed by Prowler quick-start Bicep template for read-only security scanning.'
  signInAudience: 'AzureADMyOrg'
  keyCredentials: [
    {
      displayName: certificateDisplayName
      type: 'AsymmetricX509Cert'
      usage: 'Verify'
      // Microsoft Graph computes `customKeyIdentifier` (the base64-encoded
      // SHA-1 thumbprint) from the certificate bytes automatically, so we
      // deliberately omit it. Passing the hex thumbprint here would fail the
      // keyCredentials contract, which expects base64-encoded bytes.
      key: certificateBase64
      startDateTime: certificateStartDateTime
      endDateTime: certificateEndDateTime
    }
  ]
}

resource servicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: application.appId
  displayName: applicationName
}

// Custom role: only the two read/list actions the built-in Reader is missing.
// Keep this list in sync with `permissions/prowler-azure-custom-role.json`.
resource prowlerRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' = {
  name: customRoleDefinitionName
  properties: {
    roleName: customRoleName
    description: 'Role used by Prowler for checks that require read-only access to Azure resources beyond the built-in Reader role.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Web/sites/host/listkeys/action'
          'Microsoft.Web/sites/config/list/Action'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource readerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, applicationName, 'Reader')
  properties: {
    principalId: servicePrincipal.id
    principalType: 'ServicePrincipal'
    roleDefinitionId: readerRoleDefinitionId
  }
}

resource prowlerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, applicationName, customRoleName)
  properties: {
    principalId: servicePrincipal.id
    principalType: 'ServicePrincipal'
    roleDefinitionId: prowlerRole.id
  }
}

output tenantId string = subscription().tenantId
output subscriptionId string = subscription().subscriptionId
output applicationId string = application.appId
output servicePrincipalObjectId string = servicePrincipal.id
// Microsoft Graph populates `customKeyIdentifier` (the base64-encoded SHA-1
// thumbprint) on the created keyCredential; expose it as an output so users
// can reconcile the deployed cert against the fingerprint they generated
// locally.
output certificateThumbprint string = application.keyCredentials[0].customKeyIdentifier
output prowlerRoleDefinitionId string = prowlerRole.id
