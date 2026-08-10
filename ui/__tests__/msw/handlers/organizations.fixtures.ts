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
  AzureDiscoveredSubscription,
  AzureDiscoveryResult,
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

/**
 * Canonical node kinds (AWS organizational unit, GCP folder, Azure management
 * group). All kebab-case: `toNodeKind` rejects any other spelling.
 */
export const NODE_KIND = {
  ORGANIZATIONAL_UNIT: "organizational-unit",
  FOLDER: "folder",
  MANAGEMENT_GROUP: "management-group",
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
   * Reads that answer `executing` before the task settles, so a test can hold one
   * account testing while another has already settled.
   */
  executingPolls?: number;
}

/**
 * Fixture-side pairing of a discovered candidate with the provider an apply creates
 * for it. Not a wire field: the API answers the mapping through the created
 * providers' own `uid`.
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
  /** Raw AWS, Azure or GCP discovery result served on the discovery poll. */
  result: unknown;
  /** Machine error code — never user copy. */
  error: string | null;
  /**
   * Sanitized human message the server sends alongside the code. Optional: it
   * only exists for codes the API decided to explain itself.
   */
  errorMessage?: string | null;
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
  /**
   * Connection outcomes keyed by provider uid (AWS account id, GCP project id,
   * Azure subscription id).
   */
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
 * The two kinds of folder with nothing selectable in them, both of which real
 * organizations hold: no projects at all (Google's own `system-gsuite`), and only
 * blocked projects. Neither changes the selectable count.
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
   * Adds `GCP_LONG_PROJECT_ID` as a fourth, selectable project. Opt-in, because it
   * raises the selectable count that `N of M projects selected` assertions pin.
   */
  includeLongIdProject?: boolean;
}

/**
 * Pinned to the app's own wire interfaces — a deliberate exception to this file's
 * decoupling rule, so a shape verified against the API cannot be re-invented here
 * and drift. Registration keeps the fixture's looser value types.
 */
type GcpFixtureDiscoveryResult = Omit<GcpDiscoveryResult, "projects"> & {
  projects: (Omit<GcpDiscoveredProject, "registration"> & {
    registration: FixtureRegistration;
  })[];
};

/**
 * The GCP discovery result as the API shapes it: identity is the resource `name`
 * (there is no `id` field), a child's `parent` is its parent's `name`, and
 * `display_name` is the only human label — a project's `name` is
 * `projects/{number}`.
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

// --- Azure discovery result ------------------------------------------------

/** Canonical Management Group resource ID, the only identity Azure parents on. */
const azureGroupId = (name: string) =>
  `/providers/Microsoft.Management/managementGroups/${name}`;

export const AZURE_TENANT_ID = "11111111-1111-4111-8111-111111111111";
/** Tenant root group — the target the setup form defaults to. */
export const AZURE_ROOT_GROUP = azureGroupId(AZURE_TENANT_ID);
export const AZURE_GROUP_ENGINEERING = azureGroupId("engineering");
export const AZURE_GROUP_PLATFORM = azureGroupId("platform");
/**
 * The two kinds of Management Group with nothing selectable in them: no
 * subscriptions at all, and only blocked ones. Neither changes the selectable
 * count, and both must still expand.
 */
export const AZURE_EMPTY_GROUP = azureGroupId("holding");
export const AZURE_EMPTY_GROUP_NAME = "Holding";
export const AZURE_BLOCKED_GROUP = azureGroupId("archived");
export const AZURE_BLOCKED_GROUP_NAME = "Archived";

export const AZURE_SUBSCRIPTION_PROD_EU =
  "22222222-2222-4222-8222-222222222222";
export const AZURE_SUBSCRIPTION_PROD_US =
  "33333333-3333-4333-8333-333333333333";
/** Blocked, and hanging directly off the root group (`not_applicable` node relation). */
export const AZURE_SUBSCRIPTION_LEGACY = "55555555-5555-4555-8555-555555555555";
export const AZURE_BLOCKED_GROUP_SUBSCRIPTION =
  "44444444-4444-4444-8444-444444444444";
/**
 * Blocked purely because it is not enabled — no provider exists and no linkage
 * conflict applies, the one blocked class Azure can raise on its own.
 */
export const AZURE_SUBSCRIPTION_DISABLED =
  "66666666-6666-4666-8666-666666666666";

/**
 * Blocked reasons Azure discovery reports. It reuses GCP's `*_conflict`
 * vocabulary for the three linkage/type conflicts and adds one of its own:
 * `subscription_not_enabled`, raised whenever `state != "Enabled"`, which is the
 * only reason that can block a subscription with no provider involved at all.
 */
export const AZURE_BLOCKED_REASON = {
  ORGANIZATION: "organization_conflict",
  ORGANIZATION_NODE: "organization_node_conflict",
  PROVIDER_TYPE: "provider_type_conflict",
  NOT_ENABLED: "subscription_not_enabled",
} as const;

interface AzureResultOverrides {
  /** Subscription ids whose registration reports `will_replace`. */
  replaceSubscriptionIds?: string[];
}

/** Pinned to the app's wire interfaces, for the reason `GcpFixtureDiscoveryResult` is. */
type AzureFixtureDiscoveryResult = Omit<
  AzureDiscoveryResult,
  "subscriptions"
> & {
  subscriptions: (Omit<AzureDiscoveredSubscription, "registration"> & {
    registration: FixtureRegistration;
  })[];
};

/**
 * The Azure discovery result as the API shapes it: management groups carry
 * canonical resource IDs in `id`/`parent_id`, subscriptions are identified by
 * their UUID and parent through their group's resource ID, and `display_name` is
 * the only human label. Subscription UUIDs are long by nature, so the id-column
 * overflow case needs no special candidate here.
 */
export const buildAzureDiscoveryResult = ({
  replaceSubscriptionIds = [],
}: AzureResultOverrides = {}): AzureFixtureDiscoveryResult => {
  const subscription = (
    subscriptionId: string,
    displayName: string,
    parentId: string,
    registration: FixtureRegistration,
    state = "Enabled",
  ) => ({
    subscription_id: subscriptionId,
    display_name: displayName,
    state,
    parent_id: parentId,
    registration,
  });

  const readyRegFor = (subscriptionId: string): FixtureRegistration =>
    replaceSubscriptionIds.includes(subscriptionId)
      ? readyRegistration({
          provider_exists: true,
          provider_id: `provider-existing-${subscriptionId}`,
          provider_secret_state: PROVIDER_SECRET_STATE.WILL_REPLACE,
        })
      : readyRegistration();

  return {
    root_management_group: {
      id: AZURE_ROOT_GROUP,
      name: AZURE_TENANT_ID,
      display_name: "Tenant Root Group",
      tenant_id: AZURE_TENANT_ID,
    },
    management_groups: [
      {
        id: AZURE_GROUP_ENGINEERING,
        name: "engineering",
        display_name: "Engineering",
        parent_id: AZURE_ROOT_GROUP,
      },
      {
        id: AZURE_GROUP_PLATFORM,
        name: "platform",
        display_name: "Platform",
        parent_id: AZURE_GROUP_ENGINEERING,
      },
      {
        id: AZURE_EMPTY_GROUP,
        name: "holding",
        display_name: AZURE_EMPTY_GROUP_NAME,
        parent_id: AZURE_ROOT_GROUP,
      },
      {
        id: AZURE_BLOCKED_GROUP,
        name: "archived",
        display_name: AZURE_BLOCKED_GROUP_NAME,
        parent_id: AZURE_ROOT_GROUP,
      },
    ],
    subscriptions: [
      subscription(
        AZURE_SUBSCRIPTION_PROD_EU,
        "Production EU",
        AZURE_GROUP_ENGINEERING,
        readyRegFor(AZURE_SUBSCRIPTION_PROD_EU),
      ),
      subscription(
        AZURE_SUBSCRIPTION_PROD_US,
        "Production US",
        AZURE_GROUP_PLATFORM,
        readyRegFor(AZURE_SUBSCRIPTION_PROD_US),
      ),
      subscription(
        AZURE_SUBSCRIPTION_LEGACY,
        "Legacy Sandbox",
        AZURE_ROOT_GROUP,
        blockedRegistration([AZURE_BLOCKED_REASON.ORGANIZATION], {
          provider_exists: true,
          provider_id: `provider-existing-${AZURE_SUBSCRIPTION_LEGACY}`,
          organization_relation: "linked_to_other_organization",
          organization_node_relation: "not_applicable",
          provider_secret_state: PROVIDER_SECRET_STATE.WILL_REPLACE,
        }),
      ),
      // Blocked with no provider and no conflict: the state check alone is
      // enough, which is the class the linkage-conflict cases cannot cover.
      subscription(
        AZURE_SUBSCRIPTION_DISABLED,
        "Dormant Sandbox",
        AZURE_ROOT_GROUP,
        blockedRegistration([AZURE_BLOCKED_REASON.NOT_ENABLED], {
          organization_node_relation: "not_applicable",
        }),
        "Disabled",
      ),
      subscription(
        AZURE_BLOCKED_GROUP_SUBSCRIPTION,
        "Archived Legacy",
        AZURE_BLOCKED_GROUP,
        blockedRegistration(
          [
            AZURE_BLOCKED_REASON.ORGANIZATION,
            AZURE_BLOCKED_REASON.ORGANIZATION_NODE,
          ],
          {
            provider_exists: true,
            provider_id: `provider-existing-${AZURE_BLOCKED_GROUP_SUBSCRIPTION}`,
            organization_relation: "linked_to_other_organization",
            organization_node_relation: "linked_to_other_node",
            provider_secret_state: PROVIDER_SECRET_STATE.WILL_REPLACE,
          },
        ),
      ),
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
export const AZURE_CREATED_PROVIDER_IDS = [
  "ccccccc1-1111-4111-8111-111111111111",
  "ccccccc2-2222-4222-8222-222222222222",
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
 * A fresh Azure organization onboarding world (management groups +
 * subscriptions). Selection defaults to the two ready subscriptions; the other
 * two are blocked, one of them inside an otherwise empty Management Group.
 */
export const azureOnboardingFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const createdProviderIds = AZURE_CREATED_PROVIDER_IDS;
  return {
    ...baseFixture(),
    discovery: {
      id: "disc-azure-1",
      status: DISCOVERY_STATUS_VALUE.SUCCEEDED,
      result: buildAzureDiscoveryResult(),
      error: null,
    },
    apply: {
      ...emptyApply(),
      createdProviderIds,
      providersCreatedCount: 2,
      nodesCreatedCount: 2,
      candidateProviderIds: [
        {
          candidateId: AZURE_SUBSCRIPTION_PROD_EU,
          providerId: createdProviderIds[0],
        },
        {
          candidateId: AZURE_SUBSCRIPTION_PROD_US,
          providerId: createdProviderIds[1],
        },
      ],
    },
    connectionByUid: {
      [AZURE_SUBSCRIPTION_PROD_EU]: { connected: true },
      [AZURE_SUBSCRIPTION_PROD_US]: { connected: true },
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

/**
 * Management Groups of an already-onboarded Azure organization. Named apart from
 * the discovery fixture's groups (and from the AWS/GCP containers) so a row
 * lookup by label can only resolve to one hierarchy.
 */
const AZURE_HIERARCHY_GROUP = azureGroupId("landing-zones");
export const AZURE_HIERARCHY_GROUP_NAME = "Landing Zones";
const AZURE_HIERARCHY_CHILD_GROUP = azureGroupId("decommissioned");
export const AZURE_HIERARCHY_CHILD_GROUP_NAME = "Decommissioned";
/** The Azure organization of `mixedHierarchyFixture`, and its Management Group node. */
export const AZURE_ORG_NAME = "My Azure Organization";
export const AZURE_GROUP_NODE_ID = "node-azure-lz";

/** AWS + Azure + GCP organizations side by side (mixed-hierarchy display test). */
export const mixedHierarchyFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const aws = awsHierarchyFixture();
  const azureOrgId = "org-azure-1";
  const azureProviders: FixtureProvider[] = [
    {
      id: "azp-1",
      provider: "azure",
      uid: AZURE_SUBSCRIPTION_PROD_EU,
      alias: "Contoso EU",
      connected: true,
    },
    {
      id: "azp-2",
      provider: "azure",
      uid: AZURE_SUBSCRIPTION_PROD_US,
      alias: "Contoso US",
      connected: true,
    },
  ];
  const azureNodes: FixtureNode[] = [
    {
      id: AZURE_GROUP_NODE_ID,
      kind: NODE_KIND.MANAGEMENT_GROUP,
      name: AZURE_HIERARCHY_GROUP_NAME,
      externalId: AZURE_HIERARCHY_GROUP,
      // The tenant-root Management Group is never persisted as a node — nodes
      // exist only for selected descendant groups and their ancestors — so it
      // appears here as a parent id that resolves to no node row.
      parentExternalId: AZURE_ROOT_GROUP,
      organizationId: azureOrgId,
      providerIds: ["azp-1"],
    },
    {
      id: "node-azure-decommissioned",
      kind: NODE_KIND.MANAGEMENT_GROUP,
      name: AZURE_HIERARCHY_CHILD_GROUP_NAME,
      externalId: AZURE_HIERARCHY_CHILD_GROUP,
      parentExternalId: AZURE_HIERARCHY_GROUP,
      organizationId: azureOrgId,
      providerIds: ["azp-2"],
    },
  ];
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
        id: azureOrgId,
        orgType: ORGANIZATION_TYPE.AZURE,
        name: AZURE_ORG_NAME,
        externalId: AZURE_TENANT_ID,
        // Azure is the one type that writes its own root: the Management Group
        // the organization is scoped to.
        rootExternalId: AZURE_ROOT_GROUP,
        providerIds: [],
        nodeIds: azureNodes.map((n) => n.id),
        secretId: "secret-azure-1",
      },
      {
        id: gcpOrgId,
        orgType: ORGANIZATION_TYPE.GCP,
        name: "My GCP Organization",
        externalId: GCP_ORG_ID,
        // `root_external_id` is the AWS root OU; a GCP organization has none, and
        // its top-level folders are the ones with no parent node.
        rootExternalId: null,
        providerIds: [],
        nodeIds: gcpNodes.map((n) => n.id),
        secretId: "secret-gcp-1",
      },
    ],
    nodes: [...aws.nodes, ...azureNodes, ...gcpNodes],
    providers: [...aws.providers, ...azureProviders, ...gcpProviders],
    ...overrides,
  };
};

/**
 * An `org_type` this build has no onboarding flow for. Every value of
 * `ORGANIZATION_TYPE` is onboardable now that Azure has a flow, so the
 * display-only behaviour has to be exercised through a type the enum itself does
 * not carry — which is also the real case: the enum mirrors a server-side one.
 * `oraclecloud` is a real provider type, so the provider rows underneath it still
 * render coherently.
 */
export const DISPLAY_ONLY_ORG_TYPE = "oraclecloud";
export const DISPLAY_ONLY_ORG_NAME = "My Oracle Cloud Tenancy";
export const DISPLAY_ONLY_PROVIDER_ALIAS = "oci-prod";

/**
 * An organization of a type the wizard cannot onboard (display-only): it is still
 * grouped and labelled from its own `org_type`, but offers no wizard re-entry.
 */
export const displayOnlyOrgHierarchyFixture = (
  overrides: Partial<OrgFixture> = {},
): OrgFixture => {
  const orgId = "org-display-only-1";
  return {
    ...baseFixture(),
    organizations: [
      {
        id: orgId,
        orgType: DISPLAY_ONLY_ORG_TYPE,
        name: DISPLAY_ONLY_ORG_NAME,
        externalId: "ocid1.tenancy.oc1..aaaa1111",
        rootExternalId: null,
        providerIds: ["op-1"],
        nodeIds: [],
        secretId: null,
      },
    ],
    nodes: [],
    providers: [
      {
        id: "op-1",
        provider: DISPLAY_ONLY_ORG_TYPE,
        uid: "ocid1.compartment.oc1..bbbb2222",
        alias: DISPLAY_ONLY_PROVIDER_ALIAS,
        connected: true,
      },
    ],
    ...overrides,
  };
};

export const fixtures = {
  awsOnboarding: awsOnboardingFixture,
  azureOnboarding: azureOnboardingFixture,
  gcpOnboarding: gcpOnboardingFixture,
  awsHierarchy: awsHierarchyFixture,
  mixedHierarchy: mixedHierarchyFixture,
  displayOnlyOrgHierarchy: displayOnlyOrgHierarchyFixture,
};
