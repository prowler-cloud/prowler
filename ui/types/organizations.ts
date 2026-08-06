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

export const NODE_RELATION = {
  NOT_APPLICABLE: "not_applicable",
  ALREADY_LINKED: "already_linked",
  LINK_REQUIRED: "link_required",
  LINKED_TO_OTHER_NODE: "linked_to_other_node",
} as const;

export type NodeRelation = (typeof NODE_RELATION)[keyof typeof NODE_RELATION];

export const PROVIDER_SECRET_STATE = {
  WILL_CREATE: "will_create",
  WILL_REPLACE: "will_replace",
} as const;

export type ProviderSecretState =
  (typeof PROVIDER_SECRET_STATE)[keyof typeof PROVIDER_SECRET_STATE];

export const NODE_KIND = {
  ORGANIZATIONAL_UNIT: "organizational-unit",
  FOLDER: "folder",
  MANAGEMENT_GROUP: "management-group",
} as const;

export type NodeKind = (typeof NODE_KIND)[keyof typeof NODE_KIND];

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

/**
 * Organization types with an org-level onboarding flow (wizard, credentials,
 * discovery, apply). Display surfaces cover every `OrganizationType`; only these
 * can be onboarded, so the two domains are narrowed with `isOrgFlowType`.
 */
export const ORG_FLOW_TYPES = [
  ORGANIZATION_TYPE.AWS,
  ORGANIZATION_TYPE.AZURE,
  ORGANIZATION_TYPE.GCP,
] as const;

export type OrgFlowType = (typeof ORG_FLOW_TYPES)[number];

export function isOrgFlowType(
  orgType: OrganizationType,
): orgType is OrgFlowType {
  return (ORG_FLOW_TYPES as readonly OrganizationType[]).includes(orgType);
}

/**
 * Narrows an untrusted value (form data, wire payload) to an onboarding-capable
 * type — `isOrgFlowType` narrows inside the type domain, this guards the
 * boundary, the role `toNodeKind` plays for node kinds. Every current
 * `OrganizationType` has a flow; a display-only type added later stops here.
 */
export function toOrgFlowType(orgType: unknown): OrgFlowType | undefined {
  return ORG_FLOW_TYPES.find((flowType) => flowType === orgType);
}

// ─── Candidate Registration (shared wire shape) ───────────────────────────────

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

/**
 * Identity here is the canonical resource `name` (`organizations/{id}`,
 * `folders/{id}`) — there is no `id` field, and a child's `parent` is exactly its
 * parent's `name`. `display_name` is the only human label: a project's `name` is
 * `projects/{number}`.
 */
export interface GcpDiscoveredOrganization {
  name: string;
  display_name: string;
}

export interface GcpDiscoveredFolder {
  name: string;
  display_name: string;
  parent: string;
  state?: string;
}

export interface GcpDiscoveredProject {
  project_id: string;
  name: string;
  display_name: string;
  parent: string;
  state?: string;
  labels?: Record<string, string>;
  registration?: CandidateRegistration;
}

export interface GcpDiscoveryResult {
  organization: GcpDiscoveredOrganization;
  folders: GcpDiscoveredFolder[];
  projects: GcpDiscoveredProject[];
}

// ─── Azure Discovery Result (wire) ─────────────────────────────────────────────

/**
 * Identity here is the canonical Management Group resource ID
 * (`/providers/Microsoft.Management/managementGroups/{name}`), which is what
 * `id`/`parent_id` carry; `name` is the short segment and `display_name` the
 * human label. `root` is the Management Group the organization is scoped to —
 * the tenant root group unless the user picked a narrower one.
 */
export interface AzureDiscoveredRoot {
  id: string;
  name: string;
  display_name: string;
  tenant_id: string;
}

export interface AzureDiscoveredManagementGroup {
  id: string;
  name: string;
  display_name: string;
  parent_id: string;
}

/**
 * Subscriptions are identified by their UUID, not a resource ID, and parent
 * through the Management Group's resource ID. `not_applicable` node relations
 * mark the ones hanging directly off the root.
 */
export interface AzureDiscoveredSubscription {
  subscription_id: string;
  display_name: string;
  state?: string;
  parent_id: string;
  registration?: CandidateRegistration;
}

export interface AzureDiscoveryResult {
  root: AzureDiscoveredRoot;
  management_groups: AzureDiscoveredManagementGroup[];
  subscriptions: AzureDiscoveredSubscription[];
}

/** Raw discovery `result` blob — per-provider, carries no discriminant on the wire. */
export type DiscoveryResult =
  | AwsDiscoveryResult
  | AzureDiscoveryResult
  | GcpDiscoveryResult;

// ─── Normalized Hierarchy Model (store currency) ───────────────────────────────

export interface OrgHierarchyOrganization {
  uid: string;
  name: string;
}

export interface OrgNode {
  id: string;
  kind: NodeKind;
  name: string;
  parentId: string;
}

export interface OrgCandidate {
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

export interface AzureOrgHierarchy extends BaseOrgHierarchy {
  orgType: typeof ORGANIZATION_TYPE.AZURE;
}

export interface GcpOrgHierarchy extends BaseOrgHierarchy {
  orgType: typeof ORGANIZATION_TYPE.GCP;
}

export type OrgHierarchy =
  | AwsOrgHierarchy
  | AzureOrgHierarchy
  | GcpOrgHierarchy;

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

/** Service principal; `tenant_id` must equal the organization `external_id`. */
export interface AzureStaticSecret {
  tenant_id: string;
  client_id: string;
  client_secret: string;
}

export interface AwsRoleSecretPayload {
  orgType: typeof ORGANIZATION_TYPE.AWS;
  secretType: typeof ORG_SECRET_TYPE.ROLE;
  secret: AwsRoleSecret;
}

export interface GcpServiceAccountSecretPayload {
  orgType: typeof ORGANIZATION_TYPE.GCP;
  secretType: typeof ORG_SECRET_TYPE.SERVICE_ACCOUNT;
  secret: GcpServiceAccountSecret;
}

export interface GcpStaticSecretPayload {
  orgType: typeof ORGANIZATION_TYPE.GCP;
  secretType: typeof ORG_SECRET_TYPE.STATIC;
  secret: GcpStaticSecret;
}

export interface AzureStaticSecretPayload {
  orgType: typeof ORGANIZATION_TYPE.AZURE;
  secretType: typeof ORG_SECRET_TYPE.STATIC;
  secret: AzureStaticSecret;
}

/**
 * Discriminated on `orgType` **and** `secretType`: `static` is not one shape —
 * GCP's carries a refresh token, Azure's a tenant id — so the wire
 * `secret_type` alone cannot tell the payloads apart.
 */
export type OrgSecretPayload =
  | AwsRoleSecretPayload
  | AzureStaticSecretPayload
  | GcpServiceAccountSecretPayload
  | GcpStaticSecretPayload;

/** A candidate the user chose to onboard, optionally renamed. */
export interface ApplyAccountSelection {
  id: string;
  alias?: string;
}

/** A hierarchy node the AWS apply derives client-side. */
export interface ApplyNodeSelection {
  id: string;
}

/** GCP sends projects only; folder ancestors are derived server-side. */
export interface ApplyProjectSelection {
  project_id: string;
  alias?: string;
}

/**
 * Azure sends subscriptions only; Management Group ancestors are derived
 * server-side. `subscription_id` is the Azure subscription UUID — never a
 * Prowler provider id, which the endpoint rejects.
 */
export interface ApplySubscriptionSelection {
  subscription_id: string;
  alias?: string;
}

export interface AwsApplyDiscoveryPayload {
  orgType: typeof ORGANIZATION_TYPE.AWS;
  accounts: ApplyAccountSelection[];
  organizationalUnits: ApplyNodeSelection[];
}

export interface GcpApplyDiscoveryPayload {
  orgType: typeof ORGANIZATION_TYPE.GCP;
  projects: ApplyProjectSelection[];
}

export interface AzureApplyDiscoveryPayload {
  orgType: typeof ORGANIZATION_TYPE.AZURE;
  subscriptions: ApplySubscriptionSelection[];
}

export type ApplyDiscoveryPayload =
  | AwsApplyDiscoveryPayload
  | AzureApplyDiscoveryPayload
  | GcpApplyDiscoveryPayload;

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

/** JSON:API resource identifier — the `{id, type}` every relationship points at. */
interface OrganizationResourceRef<T extends string = string> {
  id: string;
  type: T;
}

/** To-many relationship envelope. */
interface OrganizationRelationshipRef<T extends string = string> {
  data: Array<OrganizationResourceRef<T>>;
}

/** To-many relationship the API annotates with a total. */
interface CountedRelationshipRef<T extends string = string>
  extends OrganizationRelationshipRef<T> {
  meta: RelationshipCount;
}

interface RelationshipCount {
  count: number;
}

/** To-one relationship envelope. */
interface OrganizationToOneRef<T extends string = string> {
  data: OrganizationResourceRef<T>;
}

/** To-one relationship that is explicitly null at the top of the hierarchy. */
interface OrganizationNullableToOneRef<T extends string = string> {
  data: OrganizationResourceRef<T> | null;
}

interface OrganizationRelationships {
  providers?: OrganizationRelationshipRef<"providers">;
  organization_nodes?: OrganizationRelationshipRef<"organization-nodes">;
}

interface CollectionPagination {
  page?: number;
  pages?: number;
  count?: number;
}

/**
 * Collection `meta`. One interface, not one per field: the list endpoints serve
 * `version` and `pagination` in the same object, so splitting them would make
 * each response type unable to describe half of its own payload.
 */
export interface CollectionMeta {
  version?: string;
  pagination?: CollectionPagination;
}

/** One page of a JSON:API collection, as the paginated read consumes it. */
export interface CollectionPage<T> {
  data?: T[];
  meta?: CollectionMeta;
}

export interface OrganizationResource {
  id: string;
  type: "organizations";
  attributes: OrganizationAttributes;
  relationships?: OrganizationRelationships;
}

export interface OrganizationNodeAttributes {
  name: string;
  kind: NodeKind;
  external_id: string;
  /**
   * Not served by `organization-nodes`, which parents through the `parent`
   * relationship. Kept for the legacy attribute-parented grouping branch.
   */
  parent_external_id?: string | null;
  metadata: Record<string, unknown>;
  inserted_at?: string;
  updated_at?: string;
}

export interface OrganizationNodeRelationships {
  organization: OrganizationToOneRef<"organizations">;
  parent?: OrganizationNullableToOneRef<"organization-nodes">;
  providers?: OrganizationRelationshipRef<"providers">;
}

export interface OrganizationNodeResource {
  id: string;
  type: "organization-nodes";
  attributes: OrganizationNodeAttributes;
  relationships: OrganizationNodeRelationships;
}

/**
 * Result of a non-throwing ("safe") collection fetch. `data` is always present
 * (empty on failure); `error` is set only when the request failed, letting
 * callers tell a degraded fetch from a genuinely empty collection.
 */
export interface CollectionFetch<T> {
  data: T[];
  error?: boolean;
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
  providers: CountedRelationshipRef<"providers">;
  organization_nodes: CountedRelationshipRef<"organization-nodes">;
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
