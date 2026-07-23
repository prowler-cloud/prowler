/**
 * Shared fixtures for the organizations onboarding flow browser tests and the
 * no-backend dev harness.
 *
 * The wire shapes here mirror the agreed transition-window API contract and are
 * intentionally kept independent of `@/types/organizations` so the handlers and
 * fixtures stay stable while that module is reshaped to canonical during Phase 1
 * (see design decision D13 — "zero handler changes during the refactor").
 *
 * A fixture is a self-contained snapshot of the API "world" a single test
 * exercises: seeded organizations/nodes/providers for the providers-page
 * hierarchy, a discovery result to serve while polling, an apply outcome, and
 * per-provider connection outcomes. Behaviour flags toggle error branches.
 */

import { ORGANIZATION_TYPE } from "@/types/organizations";
import type { TaskState } from "@/types/tasks";

export const DISCOVERY_STATUS_VALUE = {
  PENDING: "pending",
  RUNNING: "running",
  SUCCEEDED: "succeeded",
  FAILED: "failed",
} as const;
export type DiscoveryStatusValue =
  (typeof DISCOVERY_STATUS_VALUE)[keyof typeof DISCOVERY_STATUS_VALUE];

/** Canonical node kinds (AWS organizational unit, GCP folder). */
export const NODE_KIND = {
  ORGANIZATIONAL_UNIT: "organizational-unit",
  FOLDER: "folder",
} as const;
export type NodeKind = (typeof NODE_KIND)[keyof typeof NODE_KIND];

/**
 * Registration enums use the CANONICAL values from day 0 (see D13). Current
 * code does not read `provider_secret_state`/relation fields, so emitting the
 * new values is safe; Phase 1 code will read them.
 */
export const PROVIDER_SECRET_STATE = {
  WILL_CREATE: "will_create",
  WILL_REPLACE: "will_replace",
} as const;
export type ProviderSecretState =
  (typeof PROVIDER_SECRET_STATE)[keyof typeof PROVIDER_SECRET_STATE];

export const APPLY_STATUS_VALUE = {
  READY: "ready",
  BLOCKED: "blocked",
} as const;
export type ApplyStatusValue =
  (typeof APPLY_STATUS_VALUE)[keyof typeof APPLY_STATUS_VALUE];

export interface FixtureRegistration {
  provider_exists: boolean;
  provider_id: string | null;
  organization_relation: string;
  /** Canonical relation field. */
  organization_node_relation: string;
  provider_secret_state: ProviderSecretState;
  apply_status: ApplyStatusValue;
  blocked_reasons: string[];
}

export interface FixtureProvider {
  id: string;
  provider: string;
  uid: string;
  alias: string;
  connected: boolean | null;
}

export interface FixtureNode {
  id: string;
  kind: NodeKind;
  name: string;
  externalId: string;
  parentExternalId: string | null;
  organizationId: string;
  providerIds: string[];
}

export interface FixtureOrganization {
  id: string;
  orgType: string;
  name: string;
  externalId: string;
  rootExternalId: string | null;
  /** Providers attached directly to the organization (not under a node). */
  providerIds: string[];
  nodeIds: string[];
  secretId: string | null;
}

export interface FixtureConnectionOutcome {
  connected: boolean;
  error?: string;
}

export interface FixtureApplyOutcome {
  createdProviderIds: string[];
  providersCreatedCount: number;
  providersLinkedCount: number;
  nodesCreatedCount: number;
  accountProviderMappings: Array<{ account_id: string; provider_id: string }>;
  error: { status: number; detail: string } | null;
}

export interface FixtureDiscovery {
  id: string;
  status: DiscoveryStatusValue;
  /** Raw AWS or GCP discovery result served on the discovery poll. */
  result: unknown;
  error: string | null;
}

export interface OrgFixture {
  organizations: FixtureOrganization[];
  nodes: FixtureNode[];
  providers: FixtureProvider[];
  discovery: FixtureDiscovery | null;
  apply: FixtureApplyOutcome;
  /** Connection outcomes keyed by provider uid (AWS account id / GCP project). */
  connectionByUid: Record<string, FixtureConnectionOutcome>;
  /** POST /organization-secrets returns 409 (duplicate). */
  duplicateSecret: boolean;
  /** Terminal state the deletion task settles into. */
  deletionTaskState: TaskState;
  /** Transition window: AWS bodies carry deprecated aliases alongside canonical. */
  includeAwsAliases: boolean;
  /** Tripwire (task 2.10): when false the deprecated `/organizational-units` routes are unregistered. */
  serveDeprecatedRoutes: boolean;
}

const TS = "2026-07-01T10:00:00Z";

const readyRegistration = (
  overrides: Partial<FixtureRegistration> = {},
): FixtureRegistration => ({
  provider_exists: false,
  provider_id: null,
  organization_relation: "link_required",
  organization_node_relation: "link_required",
  provider_secret_state: PROVIDER_SECRET_STATE.WILL_CREATE,
  apply_status: APPLY_STATUS_VALUE.READY,
  blocked_reasons: [],
  ...overrides,
});

const blockedRegistration = (
  reasons: string[],
  overrides: Partial<FixtureRegistration> = {},
): FixtureRegistration =>
  readyRegistration({
    apply_status: APPLY_STATUS_VALUE.BLOCKED,
    blocked_reasons: reasons,
    ...overrides,
  });

// --- AWS discovery result --------------------------------------------------

const AWS_ROOT_ID = "r-aws0";
const AWS_OU_PROD = "ou-aws0-prod1111";
const AWS_OU_SANDBOX = "ou-aws0-sand2222";

interface AwsResultOverrides {
  blockedAccountId?: string;
  replaceAccountIds?: string[];
}

const buildAwsDiscoveryResult = ({
  blockedAccountId = "333333333333",
  replaceAccountIds = [],
}: AwsResultOverrides = {}) => {
  const account = (
    id: string,
    name: string,
    parentId: string,
    registration: FixtureRegistration,
  ) => ({
    id,
    name,
    arn: `arn:aws:organizations::999999999999:account/o-aws0/${id}`,
    email: `${name}@example.com`,
    status: "ACTIVE",
    joined_method: "CREATED",
    joined_timestamp: TS,
    parent_id: parentId,
    registration,
  });

  const regFor = (id: string): FixtureRegistration => {
    if (id === blockedAccountId) {
      return blockedRegistration(["Account is suspended"]);
    }
    if (replaceAccountIds.includes(id)) {
      return readyRegistration({
        provider_exists: true,
        provider_id: `provider-existing-${id}`,
        provider_secret_state: PROVIDER_SECRET_STATE.WILL_REPLACE,
      });
    }
    return readyRegistration();
  };

  return {
    roots: [
      {
        id: AWS_ROOT_ID,
        arn: `arn:aws:organizations::999999999999:root/o-aws0/${AWS_ROOT_ID}`,
        name: "Root",
        policy_types: [],
      },
    ],
    organizational_units: [
      {
        id: AWS_OU_PROD,
        name: "Production",
        arn: `arn:aws:organizations::999999999999:ou/o-aws0/${AWS_OU_PROD}`,
        parent_id: AWS_ROOT_ID,
      },
      {
        id: AWS_OU_SANDBOX,
        name: "Sandbox",
        arn: `arn:aws:organizations::999999999999:ou/o-aws0/${AWS_OU_SANDBOX}`,
        parent_id: AWS_ROOT_ID,
      },
    ],
    accounts: [
      account("111111111111", "prod-web", AWS_OU_PROD, regFor("111111111111")),
      account("222222222222", "prod-api", AWS_OU_PROD, regFor("222222222222")),
      account(
        "333333333333",
        "sandbox-1",
        AWS_OU_SANDBOX,
        regFor("333333333333"),
      ),
    ],
  };
};

// --- GCP discovery result --------------------------------------------------

const GCP_ORG_ID = "456123789012";
const GCP_FOLDER_A = "folders/1000000001";
const GCP_FOLDER_B = "folders/1000000002";

const buildGcpDiscoveryResult = () => {
  const project = (
    projectId: string,
    name: string,
    parent: string,
    registration: FixtureRegistration,
  ) => ({
    project_id: projectId,
    name,
    parent,
    registration,
  });

  return {
    organization: {
      id: `organizations/${GCP_ORG_ID}`,
      uid: GCP_ORG_ID,
      display_name: "example.com",
    },
    folders: [
      {
        id: GCP_FOLDER_A,
        display_name: "Engineering",
        parent: `organizations/${GCP_ORG_ID}`,
      },
      {
        id: GCP_FOLDER_B,
        display_name: "Platform",
        parent: GCP_FOLDER_A,
      },
    ],
    projects: [
      project(
        "prod-analytics",
        "Prod Analytics",
        GCP_FOLDER_A,
        readyRegistration(),
      ),
      project(
        "prod-platform",
        "Prod Platform",
        GCP_FOLDER_B,
        readyRegistration(),
      ),
      project(
        "legacy-sandbox",
        "Legacy Sandbox",
        `organizations/${GCP_ORG_ID}`,
        blockedRegistration(["Project is pending deletion"]),
      ),
    ],
  };
};

// --- Fixture builders ------------------------------------------------------

const emptyApply = (): FixtureApplyOutcome => ({
  createdProviderIds: [],
  providersCreatedCount: 0,
  providersLinkedCount: 0,
  nodesCreatedCount: 0,
  accountProviderMappings: [],
  error: null,
});

const baseFixture = (): OrgFixture => ({
  organizations: [],
  nodes: [],
  providers: [],
  discovery: null,
  apply: emptyApply(),
  connectionByUid: {},
  duplicateSecret: false,
  deletionTaskState: "completed",
  includeAwsAliases: true,
  serveDeprecatedRoutes: true,
});

/**
 * A fresh AWS onboarding world: no seeded organization yet (the flow creates
 * one), a succeeded discovery with two ready accounts + one blocked account,
 * and an apply that creates two providers which then connect successfully.
 */
export const awsOnboardingFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const createdProviderIds = ["provider-aws-1", "provider-aws-2"];
  return {
    ...baseFixture(),
    discovery: {
      id: "disc-aws-1",
      status: DISCOVERY_STATUS_VALUE.SUCCEEDED,
      result: buildAwsDiscoveryResult(),
      error: null,
    },
    apply: {
      ...emptyApply(),
      createdProviderIds,
      providersCreatedCount: 2,
      nodesCreatedCount: 2,
      accountProviderMappings: [
        { account_id: "111111111111", provider_id: "provider-aws-1" },
        { account_id: "222222222222", provider_id: "provider-aws-2" },
      ],
    },
    connectionByUid: {
      "111111111111": { connected: true },
      "222222222222": { connected: true },
    },
    ...overrides,
  };
};

/** A fresh GCP organization onboarding world (folders + projects). */
export const gcpOnboardingFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const createdProviderIds = ["provider-gcp-1", "provider-gcp-2"];
  return {
    ...baseFixture(),
    discovery: {
      id: "disc-gcp-1",
      status: DISCOVERY_STATUS_VALUE.SUCCEEDED,
      result: buildGcpDiscoveryResult(),
      error: null,
    },
    apply: {
      ...emptyApply(),
      createdProviderIds,
      providersCreatedCount: 2,
      nodesCreatedCount: 2,
      accountProviderMappings: [
        { account_id: "prod-analytics", provider_id: "provider-gcp-1" },
        { account_id: "prod-platform", provider_id: "provider-gcp-2" },
      ],
    },
    connectionByUid: {
      "prod-analytics": { connected: true },
      "prod-platform": { connected: true },
    },
    ...overrides,
  };
};

/**
 * A providers-page hierarchy world with a fully onboarded AWS organization
 * (two OUs, three providers). Used for the providers-table grouping tests.
 */
export const awsHierarchyFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const orgId = "org-aws-1";
  const providers: FixtureProvider[] = [
    {
      id: "p-1",
      provider: "aws",
      uid: "111111111111",
      alias: "prod-web",
      connected: true,
    },
    {
      id: "p-2",
      provider: "aws",
      uid: "222222222222",
      alias: "prod-api",
      connected: true,
    },
    {
      id: "p-3",
      provider: "aws",
      uid: "333333333333",
      alias: "sandbox-1",
      connected: false,
    },
  ];
  const nodes: FixtureNode[] = [
    {
      id: "node-aws-prod",
      kind: NODE_KIND.ORGANIZATIONAL_UNIT,
      name: "Production",
      externalId: AWS_OU_PROD,
      parentExternalId: AWS_ROOT_ID,
      organizationId: orgId,
      providerIds: ["p-1", "p-2"],
    },
    {
      id: "node-aws-sandbox",
      kind: NODE_KIND.ORGANIZATIONAL_UNIT,
      name: "Sandbox",
      externalId: AWS_OU_SANDBOX,
      parentExternalId: AWS_ROOT_ID,
      organizationId: orgId,
      providerIds: ["p-3"],
    },
  ];
  return {
    ...baseFixture(),
    organizations: [
      {
        id: orgId,
        orgType: ORGANIZATION_TYPE.AWS,
        name: "My AWS Organization",
        externalId: "o-aws0abcdef",
        rootExternalId: AWS_ROOT_ID,
        providerIds: [],
        nodeIds: nodes.map((n) => n.id),
        secretId: "secret-aws-1",
      },
    ],
    nodes,
    providers,
    ...overrides,
  };
};

/** AWS + GCP organizations side by side (mixed-hierarchy display test). */
export const mixedHierarchyFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const aws = awsHierarchyFixture();
  const gcpOrgId = "org-gcp-1";
  const gcpProviders: FixtureProvider[] = [
    {
      id: "gp-1",
      provider: "gcp",
      uid: "prod-analytics",
      alias: "Prod Analytics",
      connected: true,
    },
    {
      id: "gp-2",
      provider: "gcp",
      uid: "prod-platform",
      alias: "Prod Platform",
      connected: true,
    },
  ];
  const gcpNodes: FixtureNode[] = [
    {
      id: "node-gcp-eng",
      kind: NODE_KIND.FOLDER,
      name: "Engineering",
      externalId: GCP_FOLDER_A,
      parentExternalId: `organizations/${GCP_ORG_ID}`,
      organizationId: gcpOrgId,
      providerIds: ["gp-1"],
    },
    {
      id: "node-gcp-platform",
      kind: NODE_KIND.FOLDER,
      name: "Platform",
      externalId: GCP_FOLDER_B,
      parentExternalId: GCP_FOLDER_A,
      organizationId: gcpOrgId,
      providerIds: ["gp-2"],
    },
  ];
  return {
    ...baseFixture(),
    organizations: [
      ...aws.organizations,
      {
        id: gcpOrgId,
        orgType: ORGANIZATION_TYPE.GCP,
        name: "My GCP Organization",
        externalId: GCP_ORG_ID,
        rootExternalId: `organizations/${GCP_ORG_ID}`,
        providerIds: [],
        nodeIds: gcpNodes.map((n) => n.id),
        secretId: "secret-gcp-1",
      },
    ],
    nodes: [...aws.nodes, ...gcpNodes],
    providers: [...aws.providers, ...gcpProviders],
    ...overrides,
  };
};

export const fixtures = {
  awsOnboarding: awsOnboardingFixture,
  gcpOnboarding: gcpOnboardingFixture,
  awsHierarchy: awsHierarchyFixture,
  mixedHierarchy: mixedHierarchyFixture,
};
