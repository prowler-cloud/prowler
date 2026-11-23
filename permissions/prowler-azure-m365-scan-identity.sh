#!/usr/bin/env bash
# Creates the identity Prowler scans Azure and/or Microsoft 365 with, in the cloud and tenant the
# Azure CLI is signed in to. Dry run unless --apply; every change goes through run(). See --help.
set -euo pipefail

# Well-known application IDs. These are the same in every Microsoft cloud.
# Permission IDs are NOT the same in every cloud, so they are looked up by name.
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"    # Microsoft Graph
EXCHANGE_APP_ID="00000002-0000-0ff1-ce00-000000000000" # Office 365 Exchange Online

# Microsoft Graph application permissions (all read-only), as documented in
# docs/user-guide/providers/{azure,microsoft365}/authentication.mdx. Delete one to leave it out.
AZURE_GRAPH_PERMISSIONS=(AuditLog.Read.All Directory.Read.All Policy.Read.All)
M365_GRAPH_PERMISSIONS=(
  AccessReview.Read.All AuditLog.Read.All Directory.Read.All
  OnPremDirectorySynchronization.Read.All Policy.Read.All RoleManagementPolicy.Read.Directory
  SecurityIdentitiesHealth.Read.All SecurityIdentitiesSensors.Read.All
  SharePointTenantSettings.Read.All ThreatHunting.Read.All
  DeviceManagementServiceConfig.Read.All DeviceManagementConfiguration.Read.All
  DeviceManagementManagedDevices.Read.All
)

# Needed only by the Microsoft 365 checks that run through PowerShell. Exchange.ManageAsApp only
# lets the app sign in to Exchange Online; the directory role, Global Reader, bounds what it can do.
EXCHANGE_PERMISSION="Exchange.ManageAsApp"
DIRECTORY_ROLE="Global Reader"

# Azure RBAC roles. The custom role matches permissions/prowler-azure-custom-role.json.
BUILTIN_ROLE="Reader"
CUSTOM_ROLE="ProwlerRole"
CUSTOM_ROLE_DESCRIPTION="Role used for checks that require read-only access to Azure resources and are not covered by the Reader role."
CUSTOM_ROLE_ACTIONS=(Microsoft.Web/sites/host/listkeys/action Microsoft.Web/sites/config/list/Action)

CREDENTIAL_NAME="prowler-scan"
SECRET_DAYS=180

# Options
APPLY=0
DO_AZURE=0
DO_M365=0
GRAPH_ONLY=0
SKIP_CUSTOM_ROLE=0
CLIENT_SECRET=0
USE_EXISTING_APP=0
CERTIFICATE=""
CERTIFICATE_END_DATE=""
APP_NAME="Prowler Scan"
SUBSCRIPTIONS=()
MANAGEMENT_GROUP=""

# State
APP_ID="<appId>"
APP_IS_NEW=0
SP_ID="<servicePrincipalObjectId>"
SP_IS_NEW=1
ROLE_IS_NEW=0
EXISTING_GRANTS="" # "resourceId appRoleId" lines the service principal already holds
WANTED_GRANTS=""   # the same, for the permissions this run asks for
COMMANDS=0
WARNINGS=()
OUT=""
NEEDS=""

usage() {
  cat <<'EOF'
Usage: prowler-azure-m365-scan-identity.sh [--azure] [--m365] [options] [--apply]

Creates the app registration Prowler scans with, in the tenant and cloud your
Azure CLI is signed in to. Every role and permission it gets is read-only.
With ProwlerRole (Azure) it can also read Function App keys and App Service
app settings: these may contain secrets that allow changes to those apps. Use
--skip-custom-role to leave that out.
Without --apply nothing is changed: the commands are only printed (dry run).

What to set up (at least one, both allowed):
  --azure                  Azure: Reader and ProwlerRole on the given scope, plus
                           3 Microsoft Graph read permissions for the Entra ID checks.
  --m365                   Microsoft 365: 13 Microsoft Graph read permissions, plus
                           Exchange.ManageAsApp and Global Reader (privileged role:
                           reads every setting in Microsoft Entra ID and Microsoft
                           365; cannot change anything) for the PowerShell checks.

Azure scope (required with --azure; subscriptions or one management group):
  --subscription ID        Subscription to scan. Repeat for several.
  --management-group ID    Management group whose subscriptions will be scanned.
  --skip-custom-role       Do not create or assign ProwlerRole (4 App Service
                           function checks will not run).

Microsoft 365:
  --graph-only             Skip Exchange.ManageAsApp and Global Reader (the
                           checks that run through PowerShell will not run).

Identity:
  --app-name NAME          App registration display name. Default: "Prowler Scan".
  --use-existing-app       Allow adding these permissions to an app registration
                           that already has this name, for example one created
                           by an earlier run of this script.
  --certificate FILE       Add this PUBLIC certificate (PEM, .cer/.pem) as a
                           credential. The private key never leaves your machine.
  --client-secret          Create a client secret, valid for 180 days, and print
                           it ONCE on the terminal.

  --apply                  Run the commands. Without it this is a dry run.
  -h, --help               Show this help.

Roles the person running it needs:
  Microsoft Entra ID       Privileged Role Administrator (or Global Administrator),
                           to grant application permissions and assign Global Reader.
                           Also Application Developer (or Cloud Application
                           Administrator) if users cannot register applications.
  Azure (--azure)          Owner or User Access Administrator on each scope.
EOF
}

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
warn() {
  printf 'WARNING: %s\n' "$*" >&2
  WARNINGS+=("$*")
}

# True when the list $1 (one item per line) contains the line $2, ignoring case.
has() { printf '%s\n' "$1" | grep -qixF -- "$2"; }

# Prints a command, then runs it only with --apply. Output is kept in $OUT.
# This is the only place where the script changes anything.
run() {
  local arg line=""
  for arg in "$@"; do
    case "$arg" in
      *[!A-Za-z0-9_./:=@,+-]* | "") line="$line '$arg'" ;;
      *) line="$line $arg" ;;
    esac
  done
  printf '    $%s\n' "$line"
  COMMANDS=$((COMMANDS + 1))
  OUT=""
  [ "$APPLY" -eq 1 ] || return 0
  OUT=$("$@") || die "The command above failed. $NEEDS If it refers to something created a moment ago, wait a minute and run the script again: it is safe to re-run."
}

# ---------------------------------------------------------------- arguments
need_value() { [ "$#" -ge 2 ] && [ -n "$2" ] || die "$1 needs a value. See --help."; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --azure) DO_AZURE=1 ;;
    --m365) DO_M365=1 ;;
    --graph-only) GRAPH_ONLY=1 ;;
    --skip-custom-role) SKIP_CUSTOM_ROLE=1 ;;
    --client-secret) CLIENT_SECRET=1 ;;
    --use-existing-app) USE_EXISTING_APP=1 ;;
    --apply) APPLY=1 ;;
    --subscription)
      need_value "$@"
      has "$(printf '%s\n' ${SUBSCRIPTIONS[@]+"${SUBSCRIPTIONS[@]}"})" "$2" || SUBSCRIPTIONS+=("$2")
      shift
      ;;
    --management-group) need_value "$@"; MANAGEMENT_GROUP="$2"; shift ;;
    --app-name) need_value "$@"; APP_NAME="$2"; shift ;;
    --certificate) need_value "$@"; CERTIFICATE="$2"; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "Unknown option: $1. See --help." ;;
  esac
  shift
done

[ "$DO_AZURE" -eq 1 ] || [ "$DO_M365" -eq 1 ] || die "Choose --azure, --m365 or both. See --help."
case "$APP_NAME" in
  *[!A-Za-z0-9\ ._-]*) die "--app-name may only contain letters, digits, spaces, dots, dashes and underscores." ;;
  *[A-Za-z0-9]*) ;;
  *) die "--app-name needs at least one letter or digit." ;;
esac
[ "$CLIENT_SECRET" -eq 0 ] || [ -z "$CERTIFICATE" ] || die "Use --client-secret or --certificate, not both."
[ "$GRAPH_ONLY" -eq 0 ] || [ "$DO_M365" -eq 1 ] || die "--graph-only only applies with --m365."
if [ -n "$CERTIFICATE" ]; then
  [ -r "$CERTIFICATE" ] || die "Cannot read the certificate file: $CERTIFICATE"
  grep -q -e "BEGIN CERTIFICATE" "$CERTIFICATE" || die "$CERTIFICATE is not a PEM certificate."
  ! grep -q -e "PRIVATE KEY" "$CERTIFICATE" || die "$CERTIFICATE contains a private key. Pass the public certificate only."
  command -v openssl >/dev/null 2>&1 || die "--certificate needs openssl, to read the certificate's expiry date."
  # Without --end-date the Azure CLI caps the credential at one year, whatever the certificate says.
  cert_end=$(openssl x509 -in "$CERTIFICATE" -noout -enddate | cut -d= -f2) && [ -n "$cert_end" ] ||
    die "Could not read the expiry date of $CERTIFICATE. Is it a PEM certificate?"
  # BSD date (macOS) first, GNU date (Linux, Cloud Shell) second.
  CERTIFICATE_END_DATE=$(date -u -j -f "%b %e %T %Y %Z" "$cert_end" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "$cert_end" +%Y-%m-%dT%H:%M:%SZ)
fi

SCOPES=()
GUID='^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
if [ "$DO_AZURE" -eq 1 ]; then
  if [ -n "$MANAGEMENT_GROUP" ]; then
    [ "${#SUBSCRIPTIONS[@]}" -eq 0 ] || die "Use --subscription or --management-group, not both."
    # Azure allows letters, digits, - _ . ( ) in a management group ID, up to 90 characters.
    case "$MANAGEMENT_GROUP" in
      *[!A-Za-z0-9_.\(\)-]* | *..* | *.) die "Not a valid management group ID: $MANAGEMENT_GROUP" ;;
    esac
    [ "${#MANAGEMENT_GROUP}" -le 90 ] || die "Not a valid management group ID: $MANAGEMENT_GROUP"
    SCOPES=("/providers/Microsoft.Management/managementGroups/$MANAGEMENT_GROUP")
  else
    [ "${#SUBSCRIPTIONS[@]}" -gt 0 ] || die "--azure needs --subscription ID (repeatable) or --management-group ID."
    for sub in "${SUBSCRIPTIONS[@]}"; do
      [[ "$sub" =~ $GUID ]] || die "Not a valid subscription ID: $sub"
      SCOPES+=("/subscriptions/$sub")
    done
  fi
elif [ "${#SUBSCRIPTIONS[@]}" -gt 0 ] || [ -n "$MANAGEMENT_GROUP" ] || [ "$SKIP_CUSTOM_ROLE" -eq 1 ]; then
  die "--subscription, --management-group and --skip-custom-role only apply with --azure."
fi

# ---------------------------------------------------------------- sign-in (read-only)
command -v az >/dev/null 2>&1 || die "The Azure CLI (az) is not installed or not in PATH."
account=$(az account show --query "[tenantId, user.name]" -o tsv) ||
  die "The Azure CLI could not read the signed-in account (its own error is above). Run 'az login', or 'az login --allow-no-subscriptions' for a tenant without Azure subscriptions. For a cloud other than Azure commercial, run 'az cloud set' first."
cloud=$(az cloud show --query "[name, endpoints.microsoftGraphResourceId]" -o tsv)
TENANT_ID=$(printf '%s\n' "$account" | sed -n 1p)
SIGNED_IN_AS=$(printf '%s\n' "$account" | sed -n 2p)
CLOUD=$(printf '%s\n' "$cloud" | sed -n 1p)
GRAPH_URL=$(printf '%s\n' "$cloud" | sed -n 2p)
GRAPH_URL="${GRAPH_URL%/}"
case "$GRAPH_URL" in
  https://*) ;;
  *) die "The cloud '$CLOUD' has no Microsoft Graph endpoint registered in the Azure CLI (see 'az cloud show')." ;;
esac

say "Cloud:            $CLOUD"
say "Microsoft Graph:  $GRAPH_URL"
say "Tenant:           $TENANT_ID"
say "Signed in as:     $SIGNED_IN_AS"
if [ "$APPLY" -eq 1 ]; then
  say "Mode:             APPLY (the commands marked with \$ are run)"
else
  say "Mode:             DRY RUN (nothing is changed; pass --apply to run the commands)"
fi

# ---------------------------------------------------------------- Azure scopes (read-only)
# Checked before anything is created, so a wrong ID stops the script early.
if [ -n "$MANAGEMENT_GROUP" ]; then
  az account management-group show --name "$MANAGEMENT_GROUP" -o none ||
    die "Management group $MANAGEMENT_GROUP does not exist in this tenant, or the signed-in account cannot read it (the Azure CLI error is above)."
elif [ "$DO_AZURE" -eq 1 ]; then
  for sub in "${SUBSCRIPTIONS[@]}"; do
    sub_tenant=$(az account show --subscription "$sub" --query tenantId -o tsv) ||
      die "Subscription $sub was not found for the signed-in account (the Azure CLI error is above)."
    [ "$sub_tenant" = "$TENANT_ID" ] || die "Subscription $sub belongs to tenant $sub_tenant, not to the signed-in tenant $TENANT_ID."
  done
fi

# ---------------------------------------------------------------- app registration
say ""
say "== App registration \"$APP_NAME\""
NEEDS="Creating an app registration needs the Application Developer role, or a tenant that lets users register applications."
found=$(az ad app list --filter "displayName eq '$APP_NAME'" --query "[].appId" -o tsv)
case "$(printf '%s' "$found" | grep -c . || true)" in
  0)
    say "  [create] App registration, single tenant, no redirect URI, no permissions yet."
    # A plain Graph POST always creates; "az ad app create" would update an app that took the name meanwhile.
    run az rest --method post --url "$GRAPH_URL/v1.0/applications" \
      --body "{\"displayName\":\"$APP_NAME\",\"signInAudience\":\"AzureADMyOrg\"}" --query appId -o tsv
    [ -z "$OUT" ] || APP_ID="$OUT"
    APP_IS_NEW=1
    ;;
  1)
    # An existing app: whoever owns it or holds one of its credentials gains what is granted below.
    APP_ID="$found"
    say "  [exists] App registration $APP_ID"
    app=$(az ad app show --id "$APP_ID" --query "[signInAudience, length(passwordCredentials), length(keyCredentials)]" -o tsv)
    audience=$(printf '%s\n' "$app" | sed -n 1p)
    credentials=$(($(printf '%s\n' "$app" | sed -n 2p) + $(printf '%s\n' "$app" | sed -n 3p)))
    owners=$(az ad app owner list --id "$APP_ID" --query "length(@)" -o tsv)
    [ "$audience" = "AzureADMyOrg" ] || die "The app registration \"$APP_NAME\" accepts sign-ins from outside this tenant (signInAudience: $audience). Use a single-tenant app: pick another --app-name."
    warn "The app registration \"$APP_NAME\" already exists: $owners owner(s) and $credentials existing credential(s) will also gain this access."
    [ "$USE_EXISTING_APP" -eq 1 ] || die "Stopped before changing an app registration this run did not create. If it is the one an earlier run of this script created, or you reviewed it, run again with --use-existing-app. Otherwise pick a unique --app-name."
    ;;
  *) die "More than one app registration is named \"$APP_NAME\". Remove the duplicates or pick another --app-name." ;;
esac

if [ "$APP_ID" != "<appId>" ]; then
  found=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv)
  if [ -n "$found" ]; then
    SP_ID="$found"
    SP_IS_NEW=0
    say "  [exists] Service principal $SP_ID"
    EXISTING_GRANTS=$(az rest --method get --url "$GRAPH_URL/v1.0/servicePrincipals/$SP_ID/appRoleAssignments?\$top=999" --query "value[].[resourceId, appRoleId]" -o tsv | tr '\t' ' ')
  fi
fi
if [ "$SP_IS_NEW" -eq 1 ]; then
  say "  [create] Service principal (the app's identity in this tenant)."
  run az ad sp create --id "$APP_ID" --query id -o tsv
  [ -z "$OUT" ] || SP_ID="$OUT"
fi

# ---------------------------------------------------------------- application permissions
# grant_app_roles API_APP_ID API_LABEL PERMISSION_NAME...
# Lists each permission on the app registration and grants it (admin consent).
grant_app_roles() {
  local api="$1" label="$2" api_sp roles declared="" name id
  local to_declare=() to_grant=()
  shift 2

  api_sp=$(az ad sp list --filter "appId eq '$api'" --query "[0].id" -o tsv)
  if [ -z "$api_sp" ]; then
    warn "$label is not available in this tenant, so this was skipped: $*"
    return 0
  fi
  roles=$(az ad sp show --id "$api_sp" --query "appRoles[?contains(allowedMemberTypes,'Application')].[value,id]" -o tsv)
  # A new app may not be readable yet (Entra replication) and declares nothing anyway.
  if [ "$APP_ID" != "<appId>" ] && [ "$APP_IS_NEW" -eq 0 ]; then
    declared=$(az ad app show --id "$APP_ID" --query "requiredResourceAccess[?resourceAppId=='$api'].resourceAccess[].id" -o tsv)
  fi

  for name in "$@"; do
    id=$(printf '%s\n' "$roles" | awk -v name="$name" '$1 == name { print $2 }')
    if [ -z "$id" ]; then
      warn "$label has no application permission named $name in this cloud, so it was skipped."
      continue
    fi
    WANTED_GRANTS="$WANTED_GRANTS$api_sp $id
"
    has "$declared" "$id" || to_declare+=("$id=Role")
    if has "$EXISTING_GRANTS" "$api_sp $id"; then
      say "  [exists] $label: $name"
    else
      say "  [grant]  $label: $name ($id)"
      to_grant+=("$id")
    fi
  done

  if [ "${#to_declare[@]}" -gt 0 ]; then
    say "  List the permissions above on the app registration (\"API permissions\" page):"
    run az ad app permission add --id "$APP_ID" --api "$api" --api-permissions "${to_declare[@]}" --only-show-errors
  fi
  if [ "${#to_grant[@]}" -gt 0 ]; then
    say "  Grant them to the service principal (this is the admin consent):"
    for id in "${to_grant[@]}"; do
      run az rest --method post --url "$GRAPH_URL/v1.0/servicePrincipals/$SP_ID/appRoleAssignments" \
        --body "{\"principalId\":\"$SP_ID\",\"resourceId\":\"$api_sp\",\"appRoleId\":\"$id\"}" -o none
    done
  fi
}

say ""
say "== Microsoft Graph application permissions (read-only)"
NEEDS="Granting application permissions needs the Privileged Role Administrator or Global Administrator role in Microsoft Entra ID."
if [ "$DO_M365" -eq 1 ]; then
  # The Microsoft 365 list already contains the three Azure permissions.
  grant_app_roles "$GRAPH_APP_ID" "Microsoft Graph" "${M365_GRAPH_PERMISSIONS[@]}"
else
  grant_app_roles "$GRAPH_APP_ID" "Microsoft Graph" "${AZURE_GRAPH_PERMISSIONS[@]}"
fi

if [ "$DO_M365" -eq 1 ] && [ "$GRAPH_ONLY" -eq 0 ]; then
  say ""
  say "== Microsoft 365 checks that run through PowerShell"
  grant_app_roles "$EXCHANGE_APP_ID" "Office 365 Exchange Online" "$EXCHANGE_PERMISSION"

  NEEDS="Assigning a directory role needs the Privileged Role Administrator or Global Administrator role in Microsoft Entra ID."
  # Built-in role only, never a custom role that happens to have the same name.
  role_id=$(az rest --method get --url "$GRAPH_URL/v1.0/roleManagement/directory/roleDefinitions?\$filter=displayName eq '$DIRECTORY_ROLE'" --query "value[?isBuiltIn].id | [0]" -o tsv)
  [ -n "$role_id" ] || die "This tenant has no built-in directory role named \"$DIRECTORY_ROLE\"."
  assigned=0
  if [ "$SP_IS_NEW" -eq 0 ]; then
    assigned=$(az rest --method get --url "$GRAPH_URL/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$SP_ID' and roleDefinitionId eq '$role_id'" --query "length(value)" -o tsv)
  fi
  if [ "$assigned" -gt 0 ]; then
    say "  [exists] Directory role: $DIRECTORY_ROLE"
  else
    say "  [assign] Directory role: $DIRECTORY_ROLE (privileged role: reads every setting in Microsoft Entra ID and Microsoft 365; cannot change anything)"
    run az rest --method post --url "$GRAPH_URL/v1.0/roleManagement/directory/roleAssignments" \
      --body "{\"principalId\":\"$SP_ID\",\"roleDefinitionId\":\"$role_id\",\"directoryScopeId\":\"/\"}" -o none
  fi
fi

# Anything the service principal already holds beyond what this run asks for.
extra=$(printf '%s\n' "$EXISTING_GRANTS" | grep -vixF -e "$WANTED_GRANTS" | grep . || true)
if [ -n "$extra" ]; then
  warn "The service principal already holds $(printf '%s\n' "$extra" | grep -c .) application permission(s) that this run did not ask for (resource ID, permission ID): $(printf '%s' "$extra" | tr '\n' ';'). Review them."
fi

# ---------------------------------------------------------------- Azure roles
# assign_role ROLE_NAME ROLE_NAME_OR_ID SCOPE
assign_role() {
  local assigned=0
  # A role or service principal created by this run cannot have assignments yet.
  if [ "$SP_IS_NEW" -eq 0 ] && { [ "$1" != "$CUSTOM_ROLE" ] || [ "$ROLE_IS_NEW" -eq 0 ]; }; then
    assigned=$(az role assignment list --assignee-object-id "$SP_ID" --role "$2" --scope "$3" --query "length(@)" -o tsv)
  fi
  if [ "$assigned" -gt 0 ]; then
    say "  [exists] $1 on $3"
  else
    say "  [assign] $1 on $3"
    run az role assignment create --role "$2" --assignee-object-id "$SP_ID" \
      --assignee-principal-type ServicePrincipal --scope "$3" -o none
  fi
}

# One action per line, lower case, sorted: to compare two lists of actions.
normalize() { tr -s '[:space:]' '\n' | tr '[:upper:]' '[:lower:]' | grep . | sort; }

if [ "$DO_AZURE" -eq 1 ]; then
  say ""
  say "== Azure roles"
  NEEDS="Assigning roles needs Owner or User Access Administrator on the scope."

  custom_role_id=""
  if [ "$SKIP_CUSTOM_ROLE" -eq 0 ]; then
    expected=$(printf '%s\n' "${CUSTOM_ROLE_ACTIONS[@]}" | normalize)
    missing=""
    for scope in "${SCOPES[@]}"; do
      # Line 1: the role's ID. Line 2: every action it grants. Line 3: every action it excludes.
      role=$(az role definition list --name "$CUSTOM_ROLE" --custom-role-only true --scope "$scope" \
        --query "[0].[name, join(' ', permissions[].[actions, dataActions][][]), join(' ', permissions[].[notActions, notDataActions][][])]" -o tsv)
      if [ -z "$role" ]; then
        missing="$missing $scope"
        continue
      fi
      custom_role_id=$(printf '%s\n' "$role" | sed -n 1p)
      # Never assign a role called ProwlerRole that grants something else.
      [ "$(printf '%s\n' "$role" | sed -n 2p | normalize)" = "$expected" ] &&
        [ -z "$(printf '%s\n' "$role" | sed -n 3p | tr -d '[:space:]')" ] ||
        die "A custom role named $CUSTOM_ROLE exists on $scope but its permissions are not the ones in permissions/prowler-azure-custom-role.json. Review it before continuing."
      say "  [exists] Custom role $CUSTOM_ROLE, assignable on $scope"
    done
    if [ -n "$missing" ] && [ -n "$custom_role_id" ]; then
      die "The custom role $CUSTOM_ROLE exists but cannot be assigned on:$missing. Add those scopes to its assignable scopes (az role definition update) and run the script again."
    fi
    if [ -z "$custom_role_id" ]; then
      scopes_json=$(printf '"%s",' "${SCOPES[@]}")
      actions_json=$(printf '"%s",' "${CUSTOM_ROLE_ACTIONS[@]}")
      say "  [create] Custom role $CUSTOM_ROLE: reads Function App host keys and App Service app settings and connection strings (may contain secrets that allow changes to those apps)."
      NEEDS="Creating a custom role needs Owner or User Access Administrator on the scope. It also fails when a role named $CUSTOM_ROLE already exists elsewhere in the tenant: add this scope to that role's assignable scopes instead."
      run az role definition create --query name -o tsv --role-definition \
        "{\"Name\":\"$CUSTOM_ROLE\",\"IsCustom\":true,\"Description\":\"$CUSTOM_ROLE_DESCRIPTION\",\"AssignableScopes\":[${scopes_json%,}],\"Actions\":[${actions_json%,}]}"
      custom_role_id="${OUT:-$CUSTOM_ROLE}"
      ROLE_IS_NEW=1
      NEEDS="Assigning roles needs Owner or User Access Administrator on the scope."
    fi
  fi

  for scope in "${SCOPES[@]}"; do
    assign_role "$BUILTIN_ROLE" "$BUILTIN_ROLE" "$scope"
    # The Azure CLI resolves a bare role ID against the default subscription: qualify it for a
    # subscription scope, and pass the name for a management group, which it resolves at that scope.
    role_ref="$CUSTOM_ROLE"
    case "$scope" in
      /subscriptions/*)
        [ "$custom_role_id" = "$CUSTOM_ROLE" ] ||
          role_ref="$scope/providers/Microsoft.Authorization/roleDefinitions/$custom_role_id"
        ;;
    esac
    [ "$SKIP_CUSTOM_ROLE" -eq 1 ] || assign_role "$CUSTOM_ROLE" "$role_ref" "$scope"
  done
fi

# ---------------------------------------------------------------- credential
if [ -n "$CERTIFICATE" ] || [ "$CLIENT_SECRET" -eq 1 ]; then
  say ""
  say "== Credential"
  NEEDS="Adding a credential needs ownership of the app registration or the Cloud Application Administrator role."
  expires=""
  if [ "$APP_ID" != "<appId>" ] && [ "$APP_IS_NEW" -eq 0 ]; then
    expires=$(az ad app show --id "$APP_ID" --query "[passwordCredentials, keyCredentials][] | [?displayName=='$CREDENTIAL_NAME'].endDateTime | [0]" -o tsv)
  fi
  if [ -n "$expires" ]; then
    if [ "$expires" \< "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ]; then
      say "  [exists] A credential named \"$CREDENTIAL_NAME\" that EXPIRED on $expires. Nothing was added."
    else
      say "  [exists] A credential named \"$CREDENTIAL_NAME\", valid until $expires. Nothing was added."
    fi
    say "           A client secret cannot be shown again. To replace the credential,"
    say "           delete it (az ad app credential delete) and run the script again."
  elif [ -n "$CERTIFICATE" ]; then
    say "  [add]    Public certificate $CERTIFICATE, valid until $CERTIFICATE_END_DATE (existing credentials are kept)."
    run az ad app credential reset --id "$APP_ID" --append --display-name "$CREDENTIAL_NAME" --cert "@$CERTIFICATE" --end-date "$CERTIFICATE_END_DATE" -o none
  else
    # BSD date (macOS) first, GNU date (Linux, Cloud Shell) second.
    end_date=$(date -u -v+"$SECRET_DAYS"d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "+$SECRET_DAYS days" +%Y-%m-%dT%H:%M:%SZ)
    say "  [add]    Client secret valid for $SECRET_DAYS days, until $end_date (existing credentials are kept)."
    run az ad app credential reset --id "$APP_ID" --append --display-name "$CREDENTIAL_NAME" --end-date "$end_date" --query password -o tsv
    if [ -n "$OUT" ]; then
      say ""
      say "  Client secret (shown only this once and stored nowhere; copy it now):"
      say "    $OUT"
      OUT=""
    fi
  fi
fi

# ---------------------------------------------------------------- summary
say ""
say "Values to enter in Prowler:"
say "  Tenant ID:  $TENANT_ID"
if [ "$APP_ID" = "<appId>" ]; then
  say "  Client ID:  (assigned when the app registration is created)"
else
  say "  Client ID:  $APP_ID"
fi
if [ -z "$CERTIFICATE" ] && [ "$CLIENT_SECRET" -eq 0 ]; then
  say "  Credential: not changed. If the app has none, run again with --certificate FILE or --client-secret."
fi

say ""
if [ "${#WARNINGS[@]}" -gt 0 ]; then
  say "Warnings (read them: something was skipped or needs a review):"
  for warning in "${WARNINGS[@]}"; do
    say "  - $warning"
  done
  outcome=" ${#WARNINGS[@]} warning(s) are listed above."
else
  outcome=""
fi
if [ "$APPLY" -eq 0 ] && [ "$COMMANDS" -eq 0 ]; then
  say "Dry run: everything already exists. --apply would change nothing.$outcome"
elif [ "$APPLY" -eq 0 ]; then
  say "Dry run: nothing was changed. --apply would run the $COMMANDS command(s) marked with \$ above.$outcome"
elif [ "$COMMANDS" -eq 0 ]; then
  say "Nothing to do: everything already exists. No changes were made.$outcome"
elif [ -n "$outcome" ]; then
  say "Finished, but not everything was set up: $COMMANDS command(s) were run.$outcome"
else
  say "Done: $COMMANDS command(s) were run."
fi
