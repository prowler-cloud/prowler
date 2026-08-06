import {
  getSelectableCandidateIds,
  getSelectableCandidateIdsForTarget,
  mapAwsDiscovery,
  mapGcpDiscovery,
} from "@/actions/organizations/organizations.adapter";
import {
  AwsDiscoveryResult,
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
  /** Microsoft Entra tenant ID (UUID) — the external id matched on. */
  tenantId: string;
  /**
   * Canonical resource ID of the Management Group the organization is scoped to,
   * sent as `root_external_id`. Defaults to the tenant root group
   * (`/providers/Microsoft.Management/managementGroups/{tenantId}`).
   */
  managementGroupId: string;
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
  | "managementGroupId"
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
  /**
   * Root container the organization is scoped to, when the type picks it up front
   * (`root_external_id` on the create request). AWS and GCP leave it to
   * discovery, so they return undefined.
   */
  getRootExternalId: (data: D) => string | undefined;
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
}

/**
 * Human copy for the machine codes a failed discovery reports in
 * `attributes.error`. The code decides the framing too: only some of them are
 * credential problems, so "Authentication failed…" is wrong for the rest.
 */
const DISCOVERY_ERROR_COPY: Record<string, string> = {
  gcp_invalid_organization_id:
    "That organization ID is not valid. Copy the numeric ID from the Google Cloud console and try again.",
  gcp_organization_not_found:
    "No organization with that ID was found. Check the ID, and that the service account has been granted access to the organization.",
  gcp_insufficient_permissions:
    "The service account cannot list this organization's folders and projects. Grant it the Folder Viewer and Project Viewer roles at the organization level, then try again.",
  gcp_service_unavailable:
    "Google Cloud did not respond while reading the organization. Nothing is wrong with your credentials — try again in a few minutes.",
  hierarchy_depth_exceeded:
    "This organization's folder hierarchy is deeper than Prowler can read. Contact support so we can help you onboard it.",
};

/**
 * Copy for a failed discovery. An unknown code falls back to the type's
 * auth-failure copy without the raw token, which is a support detail.
 */
function describeDiscoveryFailure(
  code: string | undefined,
  authFailure: string,
): string {
  const trimmedCode = code?.trim();
  if (!trimmedCode) {
    return authFailure;
  }

  return DISCOVERY_ERROR_COPY[trimmedCode] ?? authFailure;
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
  /** `root_external_id` for the create request; undefined when discovery sets it. */
  rootExternalId: string | undefined;
  resolvedName: string;
  buildSecretPayload: (stackSetExternalId: string) => OrgSecretPayload;
  mapSecretErrorField: (fieldNames: string) => OrgSetupErrorField | null;
  ingestDiscovery: (rawResult: unknown) => {
    hierarchy: OrgHierarchy;
    defaultSelection: string[];
  };
  authFailureMessage: (detail?: string) => string;
  /** Copy for a discovery that failed with a machine error code. */
  discoveryFailureMessage: (code?: string) => string;
}

const AWS_AUTH_FAILURE =
  "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.";

const awsOrgSetupStrategy: OrgSetupStrategy<AwsOrgSetupData> = {
  orgType: ORGANIZATION_TYPE.AWS,
  externalIdField: "awsOrgId",
  getExternalId: (data) => data.awsOrgId,
  // Discovery reports the organization root; the StackSet target only scopes the
  // default selection.
  getRootExternalId: () => undefined,
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
};

const GCP_AUTH_FAILURE =
  "Authentication failed. Please verify the service account permissions or credentials, then try again.";

const gcpOrgSetupStrategy: OrgSetupStrategy<GcpOrgSetupData> = {
  orgType: ORGANIZATION_TYPE.GCP,
  externalIdField: "gcpOrgId",
  getExternalId: (data) => data.gcpOrgId.trim(),
  // Discovery reports the organization resource name as the root.
  getRootExternalId: () => undefined,
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
};

function bind<D extends OrgSetupSubmissionData>(
  strategy: OrgSetupStrategy<D>,
  data: D,
): BoundOrgSetupStrategy {
  return {
    orgType: strategy.orgType,
    externalIdField: strategy.externalIdField,
    externalId: strategy.getExternalId(data),
    rootExternalId: strategy.getRootExternalId(data),
    resolvedName: strategy.getResolvedName(data),
    buildSecretPayload: (stackSetExternalId) =>
      strategy.buildSecretPayload(data, stackSetExternalId),
    mapSecretErrorField: strategy.mapSecretErrorField,
    ingestDiscovery: (rawResult) => strategy.ingestDiscovery(rawResult, data),
    authFailureMessage: strategy.authFailureMessage,
    discoveryFailureMessage: (code) =>
      describeDiscoveryFailure(code, strategy.authFailureMessage()),
  };
}

/**
 * Binds the submission data to the strategy its own tag names. The switch has no
 * default, so a new organization type is a compile error until it brings one.
 */
export function bindOrgSetupStrategy(
  data: OrgSetupSubmissionData,
): BoundOrgSetupStrategy {
  switch (data.orgType) {
    case ORGANIZATION_TYPE.AWS:
      return bind(awsOrgSetupStrategy, data);
    case ORGANIZATION_TYPE.GCP:
      return bind(gcpOrgSetupStrategy, data);
  }
}
