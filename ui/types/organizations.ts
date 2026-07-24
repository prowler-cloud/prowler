// ─── Const Enums ──────────────────────────────────────────────────────────────

export const DISCOVERY_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  SUCCEEDED: "succeeded",
  FAILED: "failed",
} as const;

export type DiscoveryStatus =
  (typeof DISCOVERY_STATUS)[keyof typeof DISCOVERY_STATUS];

export const APPLY_STATUS = {
  READY: "ready",
  BLOCKED: "blocked",
} as const;

export type ApplyStatus = (typeof APPLY_STATUS)[keyof typeof APPLY_STATUS];

export const ORG_RELATION = {
  ALREADY_LINKED: "already_linked",
  LINK_REQUIRED: "link_required",
  LINKED_TO_OTHER: "linked_to_other_organization",
} as const;

export type OrgRelation = (typeof ORG_RELATION)[keyof typeof ORG_RELATION];

// Canonical node-relation vocabulary (replaces the deprecated OU_RELATION /
// `linked_to_other_ou`). `unchanged` was dropped from the contract.
export const NODE_RELATION = {
  NOT_APPLICABLE: "not_applicable",
  ALREADY_LINKED: "already_linked",
  LINK_REQUIRED: "link_required",
  LINKED_TO_OTHER_NODE: "linked_to_other_node",
} as const;

export type NodeRelation = (typeof NODE_RELATION)[keyof typeof NODE_RELATION];

// Canonical provider-secret state (replaces the deprecated `already_exists` /
// `manual_required`).
export const PROVIDER_SECRET_STATE = {
  WILL_CREATE: "will_create",
  WILL_REPLACE: "will_replace",
} as const;

export type ProviderSecretState =
  (typeof PROVIDER_SECRET_STATE)[keyof typeof PROVIDER_SECRET_STATE];

// Canonical node kinds: AWS organizational units vs GCP folders.
export const NODE_KIND = {
  ORGANIZATIONAL_UNIT: "organizational-unit",
  FOLDER: "folder",
} as const;

export type NodeKind = (typeof NODE_KIND)[keyof typeof NODE_KIND];

// Organization-secret types per provider (API vocabulary — underscore form).
export const ORG_SECRET_TYPE = {
  ROLE: "role",
  SERVICE_ACCOUNT: "service_account",
  STATIC: "static",
} as const;

export type OrgSecretType =
  (typeof ORG_SECRET_TYPE)[keyof typeof ORG_SECRET_TYPE];

export const ORG_WIZARD_STEP = {
  SETUP: 0,
  VALIDATE: 1,
  LAUNCH: 2,
} as const;

export type OrgWizardStep =
  (typeof ORG_WIZARD_STEP)[keyof typeof ORG_WIZARD_STEP];

export const ORG_SETUP_PHASE = {
  DETAILS: "details",
  ACCESS: "access",
} as const;

export type OrgSetupPhase =
  (typeof ORG_SETUP_PHASE)[keyof typeof ORG_SETUP_PHASE];

export const DISCOVERED_ACCOUNT_STATUS = {
  ACTIVE: "ACTIVE",
  SUSPENDED: "SUSPENDED",
  PENDING_CLOSURE: "PENDING_CLOSURE",
  CLOSED: "CLOSED",
} as const;

export type DiscoveredAccountStatus =
  (typeof DISCOVERED_ACCOUNT_STATUS)[keyof typeof DISCOVERED_ACCOUNT_STATUS];

export const DISCOVERED_ACCOUNT_JOINED_METHOD = {
  INVITED: "INVITED",
  CREATED: "CREATED",
} as const;

export type DiscoveredAccountJoinedMethod =
  (typeof DISCOVERED_ACCOUNT_JOINED_METHOD)[keyof typeof DISCOVERED_ACCOUNT_JOINED_METHOD];

export interface OrganizationPolicyType {
  Type: string;
  Status: string;
}

export const ORGANIZATION_TYPE = {
  AWS: "aws",
  AZURE: "azure",
  GCP: "gcp",
} as const;

export type OrganizationType =
  (typeof ORGANIZATION_TYPE)[keyof typeof ORGANIZATION_TYPE];

/** Organization types with an org-level onboarding flow. */
export type OrgFlowType =
  | typeof ORGANIZATION_TYPE.AWS
  | typeof ORGANIZATION_TYPE.GCP;

// ─── Candidate Registration (shared wire shape) ───────────────────────────────

/**
 * Registration state of a discovered account/project — its candidacy to become
 * a provider. Shared by AWS accounts and GCP projects; all fields use canonical
 * names (`organization_node_relation`, `provider_secret_state`).
 */
export interface CandidateRegistration {
  provider_exists: boolean;
  provider_id: string | null;
  organization_relation: OrgRelation;
  organization_node_relation: NodeRelation;
  provider_secret_state: ProviderSecretState;
  apply_status: ApplyStatus;
  blocked_reasons: string[];
}

// ─── AWS Discovery Result (wire) ───────────────────────────────────────────────

export interface DiscoveredAccount {
  id: string;
  name: string;
  arn: string;
  email: string;
  status: DiscoveredAccountStatus;
  joined_method: DiscoveredAccountJoinedMethod;
  joined_timestamp: string;
  parent_id: string;
  registration?: CandidateRegistration;
}

export interface DiscoveredOu {
  id: string;
  name: string;
  arn: string;
  parent_id: string;
}

export interface DiscoveredRoot {
  id: string;
  arn: string;
  name: string;
  policy_types: OrganizationPolicyType[];
}

export interface AwsDiscoveryResult {
  roots: DiscoveredRoot[];
  organizational_units: DiscoveredOu[];
  accounts: DiscoveredAccount[];
}

// ─── GCP Discovery Result (wire) ───────────────────────────────────────────────

export interface GcpDiscoveredOrganization {
  id: string;
  uid: string;
  display_name: string;
}

export interface GcpDiscoveredFolder {
  id: string;
  display_name: string;
  /** Canonical name-ref of the parent: `organizations/{id}` or `folders/{id}`. */
  parent: string;
}

export interface GcpDiscoveredProject {
  project_id: string;
  name: string;
  /** Canonical name-ref of the parent: `organizations/{id}` or `folders/{id}`. */
  parent: string;
  registration?: CandidateRegistration;
}

export interface GcpDiscoveryResult {
  organization: GcpDiscoveredOrganization;
  folders: GcpDiscoveredFolder[];
  projects: GcpDiscoveredProject[];
}

/** Raw discovery `result` blob — per-provider, carries no discriminant on the wire. */
export type DiscoveryResult = AwsDiscoveryResult | GcpDiscoveryResult;

// ─── Normalized Hierarchy Model (store currency) ───────────────────────────────

export interface OrgHierarchyOrganization {
  /** External id / uid (AWS org external id, GCP numeric org id). */
  uid: string;
  /** Human label (AWS root name / GCP org display name). */
  name: string;
}

export interface OrgNode {
  id: string;
  kind: NodeKind;
  name: string;
  /**
   * Identifier of the containing node. Points at the organization root
   * (AWS root id / GCP `organizations/{id}`) for top-level nodes; such refs are
   * absent from the node set, so tree rebuild treats them as top-level.
   */
  parentId: string;
}

export interface OrgCandidate {
  /** Provider uid by contract: AWS account id, GCP `project_id`. */
  uid: string;
  label: string;
  parentId: string;
  registration?: CandidateRegistration;
}

interface BaseOrgHierarchy {
  organization: OrgHierarchyOrganization;
  nodes: OrgNode[];
  candidates: OrgCandidate[];
}

export interface AwsOrgHierarchy extends BaseOrgHierarchy {
  orgType: typeof ORGANIZATION_TYPE.AWS;
}

export interface GcpOrgHierarchy extends BaseOrgHierarchy {
  orgType: typeof ORGANIZATION_TYPE.GCP;
}

export type OrgHierarchy = AwsOrgHierarchy | GcpOrgHierarchy;

// ─── Secret + Apply Payloads (per-type) ────────────────────────────────────────

export interface AwsRoleSecret {
  role_arn: string;
  external_id: string;
}

export interface GcpServiceAccountSecret {
  service_account_key: Record<string, unknown>;
}

export interface GcpStaticSecret {
  client_id: string;
  client_secret: string;
  refresh_token: string;
}

export type OrgSecretPayload =
  | { secretType: typeof ORG_SECRET_TYPE.ROLE; secret: AwsRoleSecret }
  | {
      secretType: typeof ORG_SECRET_TYPE.SERVICE_ACCOUNT;
      secret: GcpServiceAccountSecret;
    }
  | { secretType: typeof ORG_SECRET_TYPE.STATIC; secret: GcpStaticSecret };

export type ApplyDiscoveryPayload =
  | {
      orgType: typeof ORGANIZATION_TYPE.AWS;
      accounts: Array<{ id: string; alias?: string }>;
      organizationalUnits: Array<{ id: string }>;
    }
  | {
      orgType: typeof ORGANIZATION_TYPE.GCP;
      projects: Array<{ project_id: string; alias?: string }>;
    };

// ─── JSON:API Resource Interfaces ─────────────────────────────────────────────

export interface OrganizationAttributes {
  name: string;
  org_type: OrganizationType;
  external_id: string;
  metadata: Record<string, unknown>;
  root_external_id: string | null;
  inserted_at?: string;
  updated_at?: string;
}

interface OrganizationRelationshipRef<T extends string = string> {
  data: Array<{ id: string; type: T }>;
}

interface OrganizationRelationships {
  providers?: OrganizationRelationshipRef<"providers">;
  organization_nodes?: OrganizationRelationshipRef<"organization-nodes">;
}

export interface OrganizationResource {
  id: string;
  type: "organizations";
  attributes: OrganizationAttributes;
  relationships?: OrganizationRelationships;
}

export interface OrganizationListResponse {
  data: OrganizationResource[];
  meta?: {
    version?: string;
  };
}

export interface OrganizationNodeAttributes {
  name: string;
  kind: NodeKind;
  external_id: string;
  parent_external_id: string | null;
  metadata: Record<string, unknown>;
  inserted_at?: string;
  updated_at?: string;
}

export interface OrganizationNodeRelationships {
  organization: {
    data: { id: string; type: "organizations" };
  };
  parent?: {
    data: { id: string; type: "organization-nodes" } | null;
  };
  providers?: OrganizationRelationshipRef<"providers">;
}

export interface OrganizationNodeResource {
  id: string;
  type: "organization-nodes";
  attributes: OrganizationNodeAttributes;
  relationships: OrganizationNodeRelationships;
}

export interface OrganizationNodeListResponse {
  data: OrganizationNodeResource[];
  meta?: {
    version?: string;
  };
}

export interface DiscoveryAttributes {
  status: DiscoveryStatus;
  result: DiscoveryResult | Record<string, never>;
  error: string | null;
  inserted_at: string;
  updated_at: string;
}

export interface DiscoveryResource {
  id: string;
  type: "organization-discoveries";
  attributes: DiscoveryAttributes;
}

export interface ApplyResultAttributes {
  providers_created_count: number;
  providers_linked_count: number;
  providers_applied_count: number;
  organization_nodes_created_count: number;
}

export interface ApplyResultRelationships {
  providers: {
    data: Array<{ type: "providers"; id: string }>;
    meta: { count: number };
  };
  organization_nodes: {
    data: Array<{ type: "organization-nodes"; id: string }>;
    meta: { count: number };
  };
}

export interface ApplyResultResource {
  id: string;
  type: "organization-discovery-apply-results";
  attributes: ApplyResultAttributes;
  relationships: ApplyResultRelationships;
}

// ─── Connection Test Status ───────────────────────────────────────────────────

export const CONNECTION_TEST_STATUS = {
  PENDING: "pending",
  SUCCESS: "success",
  ERROR: "error",
} as const;

export type ConnectionTestStatus =
  (typeof CONNECTION_TEST_STATUS)[keyof typeof CONNECTION_TEST_STATUS];
