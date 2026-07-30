import {
  getSelectableCandidateIdsForTarget,
  mapAwsDiscovery,
} from "@/actions/organizations/organizations.adapter";
import {
  AwsDiscoveryResult,
  isOrgFlowType,
  OrgFlowType,
  OrgHierarchy,
  ORG_SECRET_TYPE,
  ORGANIZATION_TYPE,
  OrganizationType,
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

/**
 * Values collected by an organization setup form, tagged with the organization
 * type that produced them: each form fills its own arm, and the strategy is
 * picked from the tag, so the fields and the credentials built from them cannot
 * belong to different types. Phase 2 adds `| GcpOrgSetupData`, which makes every
 * consumer that assumes AWS fields a compile error.
 */
export type OrgSetupSubmissionData = AwsOrgSetupData;

/**
 * Per-organization-type pieces of the shared setup submission chain
 * (find-or-create org → create/replace secret → discover → poll → select).
 * Shared machinery (ordering, polling, cancellation) stays in the hook; only
 * these type-specific bits are dispatched on the discriminant.
 */
export interface OrgSetupStrategy {
  orgType: OrgFlowType;
  /** External id used to match/create the organization. */
  getExternalId: (data: OrgSetupSubmissionData) => string;
  /** Display name to store (falls back to the external id). */
  getResolvedName: (data: OrgSetupSubmissionData) => string;
  /** Credential payload for the organization secret. */
  buildSecretPayload: (
    data: OrgSetupSubmissionData,
    externalId: string,
  ) => OrgSecretPayload;
  /**
   * Normalize the raw discovery result into the common hierarchy model and pick
   * the candidates to pre-select.
   */
  ingestDiscovery: (
    rawResult: unknown,
    data: OrgSetupSubmissionData,
  ) => { hierarchy: OrgHierarchy; defaultSelection: string[] };
  /** Copy shown when discovery reports/looks like an auth failure. */
  authFailureMessage: (detail?: string) => string;
  /** Copy shown when polling times out client-side. */
  timeoutMessage: string;
}

const AWS_AUTH_FAILURE =
  "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.";

const awsOrgSetupStrategy: OrgSetupStrategy = {
  orgType: ORGANIZATION_TYPE.AWS,
  getExternalId: (data) => data.awsOrgId,
  getResolvedName: (data) => data.organizationName?.trim() || data.awsOrgId,
  buildSecretPayload: (data, externalId) => ({
    secretType: ORG_SECRET_TYPE.ROLE,
    secret: {
      role_arn: data.roleArn,
      external_id: externalId,
    },
  }),
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
  timeoutMessage:
    "Authentication timed out. Please verify the credentials and try again.",
};

const ORG_SETUP_STRATEGIES: Partial<Record<OrgFlowType, OrgSetupStrategy>> = {
  [ORGANIZATION_TYPE.AWS]: awsOrgSetupStrategy,
};

/**
 * Whether a registered strategy exists for this organization type — i.e. whether
 * the wizard can actually drive its onboarding. `OrgFlowType` says a type is
 * *planned* for onboarding; this says the implementation has landed, so surfaces
 * that re-enter the wizard stay hidden until it has.
 */
export function hasOrgSetupStrategy(
  orgType: OrganizationType,
): orgType is OrgFlowType {
  return (
    isOrgFlowType(orgType) &&
    Object.prototype.hasOwnProperty.call(ORG_SETUP_STRATEGIES, orgType)
  );
}

export function getOrgSetupStrategy(orgType: OrgFlowType): OrgSetupStrategy {
  const strategy = hasOrgSetupStrategy(orgType)
    ? ORG_SETUP_STRATEGIES[orgType]
    : undefined;

  // Falls back rather than throwing: callers invoke this outside their try, so a
  // throw would escape as an unhandled rejection instead of a form error.
  return strategy ?? awsOrgSetupStrategy;
}
