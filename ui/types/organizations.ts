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

export const OU_RELATION = {
  NOT_APPLICABLE: "not_applicable",
  ALREADY_LINKED: "already_linked",
  LINK_REQUIRED: "link_required",
  LINKED_TO_OTHER_OU: "linked_to_other_ou",
  UNCHANGED: "unchanged",
} as const;

export type OuRelation = (typeof OU_RELATION)[keyof typeof OU_RELATION];

export const SECRET_STATE = {
  ALREADY_EXISTS: "already_exists",
  WILL_CREATE: "will_create",
  MANUAL_REQUIRED: "manual_required",
} as const;

export type SecretState = (typeof SECRET_STATE)[keyof typeof SECRET_STATE];

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

// ─── Discovery Result Interfaces ──────────────────────────────────────────────

export interface AccountRegistration {
  provider_exists: boolean;
  provider_id: string | null;
  organization_relation: OrgRelation;
  organizational_unit_relation: OuRelation;
  provider_secret_state: SecretState;
  apply_status: ApplyStatus;
  blocked_reasons: string[];
}

export interface DiscoveredAccount {
  id: string;
  name: string;
  arn: string;
  email: string;
  status: DiscoveredAccountStatus;
  joined_method: DiscoveredAccountJoinedMethod;
  joined_timestamp: string;
  parent_id: string;
  registration?: AccountRegistration;
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

export interface DiscoveryResult {
  roots: DiscoveredRoot[];
  organizational_units: DiscoveredOu[];
  accounts: DiscoveredAccount[];
}

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

export interface OrganizationResource {
  id: string;
  type: "organizations";
  attributes: OrganizationAttributes;
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
  organizational_units_created_count: number;
}

export interface ApplyResultRelationships {
  providers: {
    data: Array<{ type: "providers"; id: string }>;
    meta: { count: number };
  };
  organizational_units: {
    data: Array<{ type: "organizational-units"; id: string }>;
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
