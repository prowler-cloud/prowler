// -----------------------------------------------------------------------------
// Prowler quick-start deployment (RBAC only)
//
// Subscription-scoped template that grants a pre-existing App Registration
// / Service Principal the permissions Prowler needs to scan an
// Azure subscription:
//
//   1. Assignment of the built-in `Reader` role at subscription scope so
//      Prowler can inventory resources.
//   2. A subscription-scoped custom "ProwlerRole" that grants the two extra
//      read/list actions the built-in Reader is missing
//      (`Microsoft.Web/sites/host/listkeys/action` and
//      `Microsoft.Web/sites/config/list/Action`), plus its role assignment.
//
// The template does NOT create the App Registration itself. Microsoft.Graph
// Bicep resources are not supported by the Azure Portal "Deploy to Azure"
// flow (Microsoft docs: `msgraph-bicep-types` issue #294, closed as a
// documented limitation), so any template that includes them fails at
// deploy time with `Authorization_RequestDenied` regardless of the user's
// Entra ID role. The wizard therefore guides the user to create the App
// Registration and upload the certificate manually in the Portal first,
// then deploys this template with the resulting service principal's
// Object ID.
//
// This mirrors the AWS CloudFormation quick-create flow shipped in
// `permissions/templates/cloudformation/prowler-scan-role.yml`, and matches
// the "manual" instructions in
// `docs/user-guide/providers/azure/authentication.mdx`. Keep them in sync
// when adding or removing permissions here.
//
// After the deployment succeeds, copy the outputs (tenantId, subscriptionId)
// into Prowler along with the App Registration's Client ID and the private
// key that pairs with the certificate uploaded to Entra ID manually.
// -----------------------------------------------------------------------------

targetScope = 'subscription'

@description('Object ID of the Service Principal for the App Registration Prowler will use. Find it in Azure Portal → Microsoft Entra ID → Enterprise applications → your app → Overview → Object ID. This is NOT the same as the App Registration\'s Object ID; the Service Principal has its own separate Object ID.')
param servicePrincipalObjectId string

@description('Cosmetic label included in the custom role description. Free text; keep the default unless you need to distinguish multiple Prowler deployments.')
param deploymentLabel string = 'Prowler'

@description('Name of the extra role Prowler creates. Keep the default unless your org already uses this name.')
param customRoleName string = 'ProwlerRole'

// Deterministic GUIDs derived from `subscription().id` and the params so
// re-deploying the same template into the same subscription is idempotent —
// the role definition and the two role assignments are found and updated
// instead of duplicated. `guid()` is safe to call at subscription scope.
var customRoleDefinitionName = guid(subscription().id, customRoleName)
var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7' // built-in Reader
)

// Custom role: only the two read/list actions the built-in Reader is missing.
// Keep this list in sync with `permissions/prowler-azure-custom-role.json`.
resource prowlerRole 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' = {
  name: customRoleDefinitionName
  properties: {
    roleName: customRoleName
    description: 'Role used by ${deploymentLabel} for Prowler checks that require Azure actions beyond the built-in Reader role.'
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
  name: guid(subscription().id, servicePrincipalObjectId, readerRoleDefinitionId)
  properties: {
    principalId: servicePrincipalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: readerRoleDefinitionId
  }
}

resource prowlerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, servicePrincipalObjectId, prowlerRole.id)
  properties: {
    principalId: servicePrincipalObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: prowlerRole.id
  }
}

output tenantId string = subscription().tenantId
output subscriptionId string = subscription().subscriptionId
output prowlerRoleDefinitionId string = prowlerRole.id
