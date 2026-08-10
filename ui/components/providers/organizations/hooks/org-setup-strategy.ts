import {
  getSelectableCandidateIds,
  getSelectableCandidateIdsForTarget,
  mapAwsDiscovery,
  mapAzureDiscovery,
  mapGcpDiscovery,
} from "@/actions/organizations/organizations.adapter";
import {
  AwsDiscoveryResult,
  AzureDiscoveryResult,
  GcpDiscoveryResult,
  OrgFlowType,
  OrgHierarchy,
  ORG_SECRET_TYPE,
  ORGANIZATION_TYPE,
  OrgSecretPayload,
} from "@/types/organizations";

interface BaseOrgSetupData {
  /** Optional display name; falls back to the external id. */
  organizationName?: string;
}

export interface AwsOrgSetupData extends BaseOrgSetupData {
  orgType: typeof ORGANIZATION_TYPE.AWS;
  /** AWS organization id (`o-…`) — the external id the organization matches on. */
  awsOrgId: string;
  roleArn: string;
  // OU or root ID the StackSet was deployed to — scopes the default selection.
  organizationalUnitId?: string;
}

export interface GcpOrgSetupData extends BaseOrgSetupData {
  orgType: typeof ORGANIZATION_TYPE.GCP;
  /** Numeric Google Cloud organization id — the external id matched on. */
  gcpOrgId: string;
  /** API secret vocabulary — `service_account` (underscore) or `static`. */
  credentialMethod:
    | typeof ORG_SECRET_TYPE.SERVICE_ACCOUNT
    | typeof ORG_SECRET_TYPE.STATIC;
  /** Service-account key pasted as JSON (validated by the form before submit). */
  serviceAccountKey?: string;
  clientId?: string;
  clientSecret?: string;
  refreshToken?: string;
}

export interface AzureOrgSetupData extends BaseOrgSetupData {
  orgType: typeof ORGANIZATION_TYPE.AZURE;
  /**
   * Microsoft Entra tenant ID (UUID) — the external id matched on. Onboarding is
   * always scoped to the tenant root Management Group, which the API derives
   * from this, so there is no container to collect.
   */
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

/**
 * Values collected by an organization setup form, tagged with the organization
 * type that produced them: each form fills its own arm, and the strategy is
 * picked from the tag, so the fields and the credentials built from them cannot
 * belong to different types.
 */
export type OrgSetupSubmissionData =
  | AwsOrgSetupData
  | AzureOrgSetupData
  | GcpOrgSetupData;

export type OrgSetupErrorField =
  | "organizationName"
  | "awsOrgId"
  | "gcpOrgId"
  | "tenantId"
  | "serviceAccountKey"
  | "clientId"
  | "clientSecret"
  | "refreshToken";

/**
 * Per-organization-type pieces of the shared setup submission chain
 * (find-or-create org → create/replace secret → discover → poll → select).
 * Shared machinery (ordering, polling, cancellation) stays in the hook; only
 * these type-specific bits are dispatched on the discriminant.
 */
interface OrgSetupStrategy<D extends OrgSetupSubmissionData> {
  orgType: D["orgType"];
  /** Form field the organization external-id error attaches to. */
  externalIdField: OrgSetupErrorField;
  /** External id used to match/create the organization. */
  getExternalId: (data: D) => string;
  /** Display name to store (falls back to the external id). */
  getResolvedName: (data: D) => string;
  /**
   * Credential payload for the organization secret. `stackSetExternalId` is the
   * tenant id AWS trusts as `sts:ExternalId` — not `getExternalId`'s
   * organization external id.
   */
  buildSecretPayload: (data: D, stackSetExternalId: string) => OrgSecretPayload;
  /**
   * Maps a secret-scoped server error to the form field it belongs to, or null to
   * surface it in the banner. Matched on names rather than the pointer, which may
   * stop at `/data/attributes/secret` and leave the field as the error's own key.
   */
  mapSecretErrorField: (fieldNames: string) => OrgSetupErrorField | null;
  /**
   * Normalize the raw discovery result into the common hierarchy model and pick
   * the candidates to pre-select.
   */
  ingestDiscovery: (
    rawResult: unknown,
    data: D,
  ) => { hierarchy: OrgHierarchy; defaultSelection: string[] };
  /** Copy shown when discovery reports/looks like an auth failure. */
  authFailureMessage: (detail?: string) => string;
  /**
   * Copy for the discovery codes more than one organization type reports, in this
   * type's own hierarchy vocabulary.
   */
  sharedErrorCopy: SharedDiscoveryErrorCopy;
}

/**
 * Discovery codes the API reports for more than one organization type and whose
 * copy has to name the hierarchy the user actually has — an Azure tenant has no
 * folders. Their wording lives on each strategy (`sharedErrorCopy`) instead of in
 * the table below, so a new organization type cannot inherit another's
 * vocabulary. Codes that read correctly for everyone (`organization_discovery_failed`)
 * stay shared.
 */
const SHARED_DISCOVERY_ERROR_CODES = ["hierarchy_depth_exceeded"] as const;

type SharedDiscoveryErrorCode = (typeof SHARED_DISCOVERY_ERROR_CODES)[number];

type SharedDiscoveryErrorCopy = Record<SharedDiscoveryErrorCode, string>;

function toSharedErrorCode(code: string): SharedDiscoveryErrorCode | undefined {
  return SHARED_DISCOVERY_ERROR_CODES.find((shared) => shared === code);
}

/**
 * Human copy for the machine codes a failed discovery reports in
 * `attributes.error`. The code decides the framing too: only some of them are
 * credential problems, so "Authentication failed…" is wrong for the rest. Codes
 * whose wording differs per organization type are not here — see
 * `SHARED_DISCOVERY_ERROR_CODES`.
 */
const DISCOVERY_ERROR_COPY: Record<string, string> = {
  azure_invalid_credentials:
    "Those service principal credentials were rejected. Check the client ID and client secret, then try again.",
  azure_insufficient_permissions:
    "The service principal cannot read the complete Management Group hierarchy. Grant it the Reader role at the Management Group level, then try again.",
  azure_root_management_group_not_found:
    "The tenant root Management Group could not be found. Check the tenant ID, and that the service principal has been granted access at the tenant root.",
  azure_tenant_mismatch:
    "Those credentials belong to a different Microsoft Entra tenant. Use a service principal from the tenant you entered.",
  azure_service_unavailable:
    "Azure did not respond while reading the Management Group hierarchy. Nothing is wrong with your credentials — try again in a few minutes.",
  azure_incomplete_hierarchy:
    "Azure returned an incomplete Management Group hierarchy. This usually clears on a retry; if it does not, check that the service principal can read every Management Group in the tenant.",
  azure_rate_limited:
    "Azure rate limited the hierarchy read. Nothing is wrong with your credentials — try again in a few minutes.",
  azure_discovery_failed:
    "Azure rejected the hierarchy read. Try again, and contact support if it keeps failing.",
  organization_discovery_failed:
    "Discovery could not be completed. Try again, and contact support if it keeps failing.",
  gcp_invalid_organization_id:
    "That organization ID is not valid. Copy the numeric ID from the Google Cloud console and try again.",
  gcp_organization_not_found:
    "No organization with that ID was found. Check the ID, and that the service account has been granted access to the organization.",
  gcp_insufficient_permissions:
    "The service account cannot list this organization's folders and projects. Grant it the Folder Viewer and Project Viewer roles at the organization level, then try again.",
  gcp_service_unavailable:
    "Google Cloud did not respond while reading the organization. Nothing is wrong with your credentials — try again in a few minutes.",
};

/** Curated copy for a code: from the strategy when shared, else from the table. */
function curatedDiscoveryCopy(
  code: string,
  sharedCopy: SharedDiscoveryErrorCopy,
): string | undefined {
  const sharedCode = toSharedErrorCode(code);

  return sharedCode ? sharedCopy[sharedCode] : DISCOVERY_ERROR_COPY[code];
}

/**
 * Copy for a failed discovery, most actionable first: our curated wording for a
 * known code, then the server's own message (already display-safe) so a code
 * added after this build still says something, then the type's auth-failure copy
 * — never the raw machine code, which is a support detail.
 */
function describeDiscoveryFailure(
  code: string | undefined,
  authFailure: string,
  sharedCopy: SharedDiscoveryErrorCopy,
  serverMessage?: string | null,
): string {
  const trimmedCode = code?.trim();
  const curatedCopy = trimmedCode
    ? curatedDiscoveryCopy(trimmedCode, sharedCopy)
    : undefined;

  // `||`, not `??`: a blank server message is as good as absent.
  return curatedCopy ?? (serverMessage?.trim() || authFailure);
}

/**
 * A strategy with its submission data already applied, so the hook never holds a
 * strategy and a data object it could pair with the wrong type.
 */
export interface BoundOrgSetupStrategy {
  orgType: OrgFlowType;
  externalIdField: OrgSetupErrorField;
  /** External id used to match/create the organization. */
  externalId: string;
  resolvedName: string;
  buildSecretPayload: (stackSetExternalId: string) => OrgSecretPayload;
  mapSecretErrorField: (fieldNames: string) => OrgSetupErrorField | null;
  ingestDiscovery: (rawResult: unknown) => {
    hierarchy: OrgHierarchy;
    defaultSelection: string[];
  };
  authFailureMessage: (detail?: string) => string;
  /**
   * Copy for a discovery that failed, from its machine error code and the
   * server's human message.
   */
  discoveryFailureMessage: (
    code?: string,
    serverMessage?: string | null,
  ) => string;
}

const AWS_AUTH_FAILURE =
  "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.";

const awsOrgSetupStrategy: OrgSetupStrategy<AwsOrgSetupData> = {
  orgType: ORGANIZATION_TYPE.AWS,
  externalIdField: "awsOrgId",
  getExternalId: (data) => data.awsOrgId,
  getResolvedName: (data) => data.organizationName?.trim() || data.awsOrgId,
  buildSecretPayload: (data, stackSetExternalId) => ({
    orgType: ORGANIZATION_TYPE.AWS,
    secretType: ORG_SECRET_TYPE.ROLE,
    secret: {
      role_arn: data.roleArn,
      external_id: stackSetExternalId,
    },
  }),
  // AWS role-secret field errors surface in the banner (no dedicated fields).
  mapSecretErrorField: () => null,
  ingestDiscovery: (rawResult, data) => {
    const hierarchy = mapAwsDiscovery(rawResult as AwsDiscoveryResult);
    // The deployment (management/delegated admin) account is where the local
    // role is created; its ID is the one embedded in the Role ARN.
    const deploymentCandidateId = data.roleArn.match(
      /^arn:aws:iam::(\d{12}):role\//,
    )?.[1];

    return {
      hierarchy,
      defaultSelection: getSelectableCandidateIdsForTarget(
        hierarchy,
        data.organizationalUnitId ?? "",
        deploymentCandidateId,
      ),
    };
  },
  authFailureMessage: (detail) =>
    detail ? `${AWS_AUTH_FAILURE} ${detail}` : AWS_AUTH_FAILURE,
  sharedErrorCopy: {
    hierarchy_depth_exceeded:
      "This organization's organizational unit hierarchy is deeper than Prowler can read. Contact support so we can help you onboard it.",
  },
};

const AZURE_AUTH_FAILURE =
  "Authentication failed. Please verify the service principal permissions or credentials, then try again.";

const azureOrgSetupStrategy: OrgSetupStrategy<AzureOrgSetupData> = {
  orgType: ORGANIZATION_TYPE.AZURE,
  externalIdField: "tenantId",
  // The API stores the tenant as `str(UUID(...))` — canonical lowercase — and
  // `filter[external_id]` is an exact match, so an uppercase-typed UUID would
  // miss its own organization on a second run and then collide on the POST.
  getExternalId: (data) => data.tenantId.trim().toLowerCase(),
  getResolvedName: (data) =>
    data.organizationName?.trim() || data.tenantId.trim(),
  // The tenant comes from the organization, so the secret carries the service
  // principal only.
  buildSecretPayload: (data) => ({
    orgType: ORGANIZATION_TYPE.AZURE,
    secretType: ORG_SECRET_TYPE.STATIC,
    secret: {
      client_id: data.clientId.trim(),
      client_secret: data.clientSecret.trim(),
    },
  }),
  mapSecretErrorField: (fieldNames) => {
    if (fieldNames.includes("client_id")) return "clientId";
    if (fieldNames.includes("client_secret")) return "clientSecret";
    return null;
  },
  ingestDiscovery: (rawResult) => {
    const hierarchy = mapAzureDiscovery(rawResult as AzureDiscoveryResult);

    // Like GCP, there is no StackSet-style target scoping, so the default is
    // every ready subscription; Management Group ancestors are derived
    // server-side.
    return {
      hierarchy,
      defaultSelection: getSelectableCandidateIds(hierarchy),
    };
  },
  authFailureMessage: (detail) =>
    detail ? `${AZURE_AUTH_FAILURE} ${detail}` : AZURE_AUTH_FAILURE,
  sharedErrorCopy: {
    hierarchy_depth_exceeded:
      "This tenant's Management Group hierarchy is deeper than Prowler can read. Contact support so we can help you onboard it.",
  },
};

const GCP_AUTH_FAILURE =
  "Authentication failed. Please verify the service account permissions or credentials, then try again.";

const gcpOrgSetupStrategy: OrgSetupStrategy<GcpOrgSetupData> = {
  orgType: ORGANIZATION_TYPE.GCP,
  externalIdField: "gcpOrgId",
  getExternalId: (data) => data.gcpOrgId.trim(),
  getResolvedName: (data) =>
    data.organizationName?.trim() || data.gcpOrgId.trim(),
  buildSecretPayload: (data) => {
    if (data.credentialMethod === ORG_SECRET_TYPE.STATIC) {
      return {
        orgType: ORGANIZATION_TYPE.GCP,
        secretType: ORG_SECRET_TYPE.STATIC,
        secret: {
          client_id: data.clientId?.trim() ?? "",
          client_secret: data.clientSecret?.trim() ?? "",
          refresh_token: data.refreshToken?.trim() ?? "",
        },
      };
    }
    // The form validates this JSON before submit, so the parse cannot throw here.
    return {
      orgType: ORGANIZATION_TYPE.GCP,
      secretType: ORG_SECRET_TYPE.SERVICE_ACCOUNT,
      secret: {
        service_account_key: JSON.parse(data.serviceAccountKey ?? "{}"),
      },
    };
  },
  mapSecretErrorField: (fieldNames) => {
    if (fieldNames.includes("service_account_key")) return "serviceAccountKey";
    if (fieldNames.includes("client_id")) return "clientId";
    if (fieldNames.includes("client_secret")) return "clientSecret";
    if (fieldNames.includes("refresh_token")) return "refreshToken";
    return null;
  },
  ingestDiscovery: (rawResult) => {
    const hierarchy = mapGcpDiscovery(rawResult as GcpDiscoveryResult);

    // GCP has no StackSet-style target scoping, so the default is every ready
    // project; folder ancestors are derived server-side.
    return {
      hierarchy,
      defaultSelection: getSelectableCandidateIds(hierarchy),
    };
  },
  authFailureMessage: (detail) =>
    detail ? `${GCP_AUTH_FAILURE} ${detail}` : GCP_AUTH_FAILURE,
  sharedErrorCopy: {
    hierarchy_depth_exceeded:
      "This organization's folder hierarchy is deeper than Prowler can read. Contact support so we can help you onboard it.",
  },
};

function bind<D extends OrgSetupSubmissionData>(
  strategy: OrgSetupStrategy<D>,
  data: D,
): BoundOrgSetupStrategy {
  return {
    orgType: strategy.orgType,
    externalIdField: strategy.externalIdField,
    externalId: strategy.getExternalId(data),
    resolvedName: strategy.getResolvedName(data),
    buildSecretPayload: (stackSetExternalId) =>
      strategy.buildSecretPayload(data, stackSetExternalId),
    mapSecretErrorField: strategy.mapSecretErrorField,
    ingestDiscovery: (rawResult) => strategy.ingestDiscovery(rawResult, data),
    authFailureMessage: strategy.authFailureMessage,
    discoveryFailureMessage: (code, serverMessage) =>
      describeDiscoveryFailure(
        code,
        strategy.authFailureMessage(),
        strategy.sharedErrorCopy,
        serverMessage,
      ),
  };
}

/**
 * Binds the submission data to the strategy its own tag names. The `default` arm
 * assigns the remaining data to `never`, so a new organization type without a
 * strategy fails to compile here.
 */
export function bindOrgSetupStrategy(
  data: OrgSetupSubmissionData,
): BoundOrgSetupStrategy {
  switch (data.orgType) {
    case ORGANIZATION_TYPE.AWS:
      return bind(awsOrgSetupStrategy, data);
    case ORGANIZATION_TYPE.AZURE:
      return bind(azureOrgSetupStrategy, data);
    case ORGANIZATION_TYPE.GCP:
      return bind(gcpOrgSetupStrategy, data);
    default: {
      const exhaustiveData: never = data;
      return exhaustiveData;
    }
  }
}
