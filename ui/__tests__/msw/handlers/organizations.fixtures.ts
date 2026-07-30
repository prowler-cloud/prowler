/**
 * Shared fixtures for the organization onboarding flow, used by the onboarding
 * integration tests and the no-backend dev harness (MSW).
 *
 * The wire shapes are declared here rather than imported from
 * `@/types/organizations` so refactors to that module don't force the mock
 * handlers and fixtures to churn. The GCP discovery result is the one exception
 * (see `GcpFixtureDiscoveryResult`).
 *
 * A fixture is a self-contained snapshot of the API "world" a single test
 * exercises: seeded organizations/nodes/providers for the providers-page
 * hierarchy, a discovery result to serve while polling, an apply outcome, and
 * per-provider connection outcomes. Behaviour flags toggle error branches.
 */

import { ORGANIZATION_TYPE } from "@/types/organizations";
import type {
  GcpDiscoveredProject,
  GcpDiscoveryResult,
} from "@/types/organizations";
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
 * `provider_secret_state` and the relation fields carry the canonical values.
 * The app doesn't read them yet, so serving them from the mock is harmless;
 * they're here for the code that will consume them.
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
  /**
   * Reads that answer `executing` before the task settles. Lets a test hold one
   * account testing while another has already settled, which is the only way to
   * observe that rows resolve per provider rather than all at the end.
   */
  executingPolls?: number;
}

/**
 * Fixture-side pairing of a discovered candidate with the provider an apply
 * creates for it. Not a wire field: the API answers the mapping through the
 * created providers' own `uid` (requested with `?include=providers`).
 */
export interface FixtureCandidateProviderId {
  candidateId: string;
  providerId: string;
}

export interface FixtureApplyError {
  status: number;
  detail: string;
}

export interface FixtureApplyOutcome {
  createdProviderIds: string[];
  providersCreatedCount: number;
  providersLinkedCount: number;
  nodesCreatedCount: number;
  candidateProviderIds: FixtureCandidateProviderId[];
  error: FixtureApplyError | null;
}

export interface FixtureDiscovery {
  id: string;
  status: DiscoveryStatusValue;
  /** Raw AWS or GCP discovery result served on the discovery poll. */
  result: unknown;
  error: string | null;
}

export interface FixtureScheduleBulkOutcome {
  /** Ids reported committed; `null` echoes every requested id minus `failed`. */
  updated: string[] | null;
  failed: Array<{ id: string; error: string }>;
  /**
   * Body variant: `flat` is what the API really returns, `attributes` the
   * serializer-rendered form the client also tolerates, `bare` a body carrying
   * neither list (an empty 200/204).
   */
  shape: "flat" | "attributes" | "bare";
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
  /** How `POST /schedules/bulk` answers the launch step. */
  scheduleBulk: FixtureScheduleBulkOutcome;
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

export const GCP_ORG_ID = "456123789012";
const GCP_FOLDER_A = "folders/1000000001";
const GCP_FOLDER_B = "folders/1000000002";
/**
 * Two folders with nothing selectable in them — discovery lists every ACTIVE
 * folder, and real organizations hold both kinds: one with no projects at all
 * (Google's own `system-gsuite`) and one holding only blocked projects. Neither
 * changes the selectable count, so every `N of M projects selected` assertion
 * stays valid.
 */
export const GCP_EMPTY_FOLDER = "folders/1000000003";
export const GCP_EMPTY_FOLDER_NAME = "system-gsuite";
export const GCP_BLOCKED_FOLDER = "folders/1000000004";
export const GCP_BLOCKED_FOLDER_NAME = "Archived";
export const GCP_BLOCKED_FOLDER_PROJECT = "archived-legacy";

/** A project id long enough to fill the fixed-width id column of a tree row. */
export const GCP_LONG_PROJECT_ID = "sys-33751773248373676292";

interface GcpResultOverrides {
  /** Project ids whose registration reports `will_replace` (existing provider). */
  replaceProjectIds?: string[];
  /**
   * Adds `GCP_LONG_PROJECT_ID` as a fourth, selectable project. Opt-in: it
   * raises the selectable count every `N of M projects selected` assertion
   * pins, and it has to be selectable to have an alias input to collide with.
   */
  includeLongIdProject?: boolean;
}

/**
 * Pinned to the app's own wire interfaces — a deliberate exception to this
 * file's decoupling rule, so a change on either side has to be an edit on both.
 * These three shapes are verified against the merged API, and inventing them
 * here alongside the types is precisely what let a flattened tree ship green.
 * Registration keeps the fixture's looser value types.
 */
type GcpFixtureDiscoveryResult = Omit<GcpDiscoveryResult, "projects"> & {
  projects: (Omit<GcpDiscoveredProject, "registration"> & {
    registration: FixtureRegistration;
  })[];
};

/**
 * The GCP discovery result as the API really shapes it: identity is the
 * canonical resource `name` (there is no `id` field), a child's `parent` is
 * exactly its parent's `name`, and `display_name` is the only human label — a
 * project's `name` is `projects/{number}`. Reading `name` as a label, or
 * expecting an `id`, is what flattened the tree in production.
 */
export const buildGcpDiscoveryResult = ({
  replaceProjectIds = [],
  includeLongIdProject = false,
}: GcpResultOverrides = {}): GcpFixtureDiscoveryResult => {
  const project = (
    projectId: string,
    resourceName: string,
    displayName: string,
    parent: string,
    registration: FixtureRegistration,
  ) => ({
    project_id: projectId,
    name: resourceName,
    display_name: displayName,
    parent,
    state: "ACTIVE",
    registration,
  });

  const readyRegFor = (projectId: string): FixtureRegistration =>
    replaceProjectIds.includes(projectId)
      ? readyRegistration({
          provider_exists: true,
          provider_id: `provider-existing-${projectId}`,
          provider_secret_state: PROVIDER_SECRET_STATE.WILL_REPLACE,
        })
      : readyRegistration();

  return {
    organization: {
      name: `organizations/${GCP_ORG_ID}`,
      display_name: "example.com",
    },
    folders: [
      {
        name: GCP_FOLDER_A,
        display_name: "Engineering",
        parent: `organizations/${GCP_ORG_ID}`,
        state: "ACTIVE",
      },
      {
        name: GCP_FOLDER_B,
        display_name: "Platform",
        parent: GCP_FOLDER_A,
        state: "ACTIVE",
      },
      {
        name: GCP_EMPTY_FOLDER,
        display_name: GCP_EMPTY_FOLDER_NAME,
        parent: `organizations/${GCP_ORG_ID}`,
        state: "ACTIVE",
      },
      {
        name: GCP_BLOCKED_FOLDER,
        display_name: GCP_BLOCKED_FOLDER_NAME,
        parent: `organizations/${GCP_ORG_ID}`,
        state: "ACTIVE",
      },
    ],
    projects: [
      project(
        "prod-analytics",
        "projects/1000000010",
        "Prod Analytics",
        GCP_FOLDER_A,
        readyRegFor("prod-analytics"),
      ),
      project(
        "prod-platform",
        "projects/1000000011",
        "Prod Platform",
        GCP_FOLDER_B,
        readyRegFor("prod-platform"),
      ),
      project(
        "legacy-sandbox",
        "projects/1000000012",
        "Legacy Sandbox",
        `organizations/${GCP_ORG_ID}`,
        blockedRegistration(["Project is pending deletion"]),
      ),
      project(
        GCP_BLOCKED_FOLDER_PROJECT,
        "projects/1000000014",
        "Archived Legacy",
        GCP_BLOCKED_FOLDER,
        blockedRegistration(["Project is pending deletion"]),
      ),
      ...(includeLongIdProject
        ? [
            project(
              GCP_LONG_PROJECT_ID,
              "projects/1000000013",
              "System Generated",
              GCP_FOLDER_A,
              readyRegFor(GCP_LONG_PROJECT_ID),
            ),
          ]
        : []),
    ],
  };
};

// --- Fixture builders ------------------------------------------------------

/**
 * Ids of the providers an apply creates. They must be UUIDs: the launch step's
 * `updateSchedulesBulk` validates every id with `z.uuid()` (SSRF guard) and
 * bails before issuing `POST /schedules/bulk` if one doesn't parse.
 */
const AWS_CREATED_PROVIDER_IDS = [
  "aaaaaaa1-1111-4111-8111-111111111111",
  "aaaaaaa2-2222-4222-8222-222222222222",
];
export const GCP_CREATED_PROVIDER_IDS = [
  "bbbbbbb1-1111-4111-8111-111111111111",
  "bbbbbbb2-2222-4222-8222-222222222222",
];

const emptyApply = (): FixtureApplyOutcome => ({
  createdProviderIds: [],
  providersCreatedCount: 0,
  providersLinkedCount: 0,
  nodesCreatedCount: 0,
  candidateProviderIds: [],
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
  scheduleBulk: { updated: null, failed: [], shape: "flat" },
  // Deprecated AWS FIELDS stay in bodies (mirrors production's facade period)…
  includeAwsAliases: true,
  // …but the deprecated `/organizational-units` ROUTES are gone (Phase 1
  // tripwire, task 2.10): with `onUnhandledRequest: "error"`, any lingering
  // alias-route call becomes a hard failure, proving the UI is fully canonical.
  serveDeprecatedRoutes: false,
});

/**
 * A fresh AWS onboarding world: no seeded organization yet (the flow creates
 * one), a succeeded discovery with two ready accounts + one blocked account,
 * and an apply that creates two providers which then connect successfully.
 */
export const awsOnboardingFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const createdProviderIds = AWS_CREATED_PROVIDER_IDS;
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
      candidateProviderIds: [
        { candidateId: "111111111111", providerId: createdProviderIds[0] },
        { candidateId: "222222222222", providerId: createdProviderIds[1] },
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
  const createdProviderIds = GCP_CREATED_PROVIDER_IDS;
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
      candidateProviderIds: [
        { candidateId: "prod-analytics", providerId: createdProviderIds[0] },
        { candidateId: "prod-platform", providerId: createdProviderIds[1] },
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
        // Only the AWS apply writes `root_external_id` (the root OU); a GCP
        // organization never has one, and its top-level folders are the ones with
        // no parent node.
        rootExternalId: null,
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

/**
 * An organization of a type the wizard cannot onboard (display-only): it is still
 * grouped and labelled from its own `org_type`, but offers no wizard re-entry.
 */
export const displayOnlyOrgHierarchyFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const orgId = "org-azure-1";
  return {
    ...baseFixture(),
    organizations: [
      {
        id: orgId,
        orgType: ORGANIZATION_TYPE.AZURE,
        name: "Contoso Tenant",
        externalId: "11111111-2222-3333-4444-555555555555",
        rootExternalId: null,
        providerIds: ["ap-1"],
        nodeIds: [],
        secretId: null,
      },
    ],
    nodes: [],
    providers: [
      {
        id: "ap-1",
        provider: "azure",
        uid: "99999999-8888-7777-6666-555555555555",
        alias: "contoso-prod",
        connected: true,
      },
    ],
    ...overrides,
  };
};

export const fixtures = {
  awsOnboarding: awsOnboardingFixture,
  gcpOnboarding: gcpOnboardingFixture,
  awsHierarchy: awsHierarchyFixture,
  mixedHierarchy: mixedHierarchyFixture,
  displayOnlyOrgHierarchy: displayOnlyOrgHierarchyFixture,
};
