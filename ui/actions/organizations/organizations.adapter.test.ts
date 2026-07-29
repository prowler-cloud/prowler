import { describe, expect, it } from "vitest";

import {
  APPLY_STATUS,
  ApplyStatus,
  AwsDiscoveryResult,
  AwsOrgHierarchy,
  GcpDiscoveryResult,
  GcpOrgHierarchy,
  NODE_KIND,
  ORGANIZATION_TYPE,
} from "@/types/organizations";

import {
  buildApplyPayload,
  buildCandidateLookup,
  buildOrgTreeData,
  getNodeIdsForSelectedCandidates,
  getSelectableCandidateIds,
  getSelectableCandidateIdsForTarget,
  mapAwsDiscovery,
  mapGcpDiscovery,
} from "./organizations.adapter";

const gcpDiscoveryFixture: GcpDiscoveryResult = {
  organization: {
    id: "organizations/456123789012",
    uid: "456123789012",
    display_name: "example.com",
  },
  folders: [
    {
      id: "folders/1000000001",
      display_name: "Engineering",
      parent: "organizations/456123789012",
    },
    {
      id: "folders/1000000002",
      display_name: "Platform",
      parent: "folders/1000000001",
    },
  ],
  projects: [
    {
      project_id: "prod-analytics",
      name: "Prod Analytics",
      parent: "folders/1000000001",
      registration: {
        provider_exists: false,
        provider_id: null,
        organization_relation: "link_required",
        organization_node_relation: "link_required",
        provider_secret_state: "will_create",
        apply_status: APPLY_STATUS.READY,
        blocked_reasons: [],
      },
    },
    {
      project_id: "legacy-sandbox",
      name: "Legacy Sandbox",
      parent: "organizations/456123789012",
      registration: {
        provider_exists: false,
        provider_id: null,
        organization_relation: "link_required",
        organization_node_relation: "link_required",
        provider_secret_state: "will_create",
        apply_status: APPLY_STATUS.BLOCKED,
        blocked_reasons: ["Project is pending deletion"],
      },
    },
  ],
};

const awsDiscoveryFixture: AwsDiscoveryResult = {
  roots: [
    {
      id: "r-root",
      arn: "arn:aws:organizations::123:root/o-example/r-root",
      name: "Root",
      policy_types: [],
    },
  ],
  organizational_units: [
    {
      id: "ou-parent",
      name: "Parent OU",
      arn: "arn:aws:organizations::123:ou/o-example/ou-parent",
      parent_id: "r-root",
    },
    {
      id: "ou-child",
      name: "Child OU",
      arn: "arn:aws:organizations::123:ou/o-example/ou-child",
      parent_id: "ou-parent",
    },
  ],
  accounts: [
    {
      id: "111111111111",
      arn: "arn:aws:organizations::123:account/o-example/111111111111",
      name: "App Account",
      email: "app@example.com",
      status: "ACTIVE",
      joined_method: "CREATED",
      joined_timestamp: "2024-01-01T00:00:00Z",
      parent_id: "ou-child",
      registration: {
        provider_exists: false,
        provider_id: null,
        organization_relation: "link_required",
        organization_node_relation: "link_required",
        provider_secret_state: "will_create",
        apply_status: APPLY_STATUS.READY,
        blocked_reasons: [],
      },
    },
    {
      id: "222222222222",
      arn: "arn:aws:organizations::123:account/o-example/222222222222",
      name: "Security Account",
      email: "security@example.com",
      status: "ACTIVE",
      joined_method: "CREATED",
      joined_timestamp: "2024-01-01T00:00:00Z",
      parent_id: "ou-parent",
      registration: {
        provider_exists: false,
        provider_id: null,
        organization_relation: "link_required",
        organization_node_relation: "link_required",
        provider_secret_state: "will_create",
        apply_status: APPLY_STATUS.BLOCKED,
        blocked_reasons: ["role_missing"],
      },
    },
    {
      id: "333333333333",
      arn: "arn:aws:organizations::123:account/o-example/333333333333",
      name: "Legacy Account",
      email: "legacy@example.com",
      status: "ACTIVE",
      joined_method: "INVITED",
      joined_timestamp: "2024-01-01T00:00:00Z",
      parent_id: "r-root",
    },
  ],
};

// The normalized model is the store currency; every downstream function
// consumes it. Ingestion happens once here.
const hierarchy = mapAwsDiscovery(awsDiscoveryFixture);

describe("mapAwsDiscovery", () => {
  it("normalizes the AWS wire result into the common hierarchy model", () => {
    expect(hierarchy.orgType).toBe(ORGANIZATION_TYPE.AWS);
    expect(hierarchy.organization).toEqual({ uid: "r-root", name: "Root" });

    // OUs become nodes with the organizational-unit kind, preserving parentage.
    expect(hierarchy.nodes).toEqual([
      {
        id: "ou-parent",
        kind: NODE_KIND.ORGANIZATIONAL_UNIT,
        name: "Parent OU",
        parentId: "r-root",
      },
      {
        id: "ou-child",
        kind: NODE_KIND.ORGANIZATIONAL_UNIT,
        name: "Child OU",
        parentId: "ou-parent",
      },
    ]);

    // Accounts become candidates keyed by their provider uid (account id).
    expect(hierarchy.candidates.map((candidate) => candidate.uid)).toEqual([
      "111111111111",
      "222222222222",
      "333333333333",
    ]);
    expect(hierarchy.candidates[0]).toMatchObject({
      uid: "111111111111",
      label: "App Account",
      parentId: "ou-child",
    });
  });
});

describe("mapGcpDiscovery", () => {
  it("normalizes the GCP wire result into the common hierarchy model", () => {
    // Given / When
    const gcpHierarchy = mapGcpDiscovery(gcpDiscoveryFixture);

    // Then
    expect(gcpHierarchy.orgType).toBe(ORGANIZATION_TYPE.GCP);
    expect(gcpHierarchy.organization).toEqual({
      uid: "456123789012",
      name: "example.com",
    });

    // Folders become nodes keyed by their canonical `folders/{id}` ref, keeping
    // the parent name-ref so org-level folders read as top-level and nested
    // folders match their parent folder ref.
    expect(gcpHierarchy.nodes).toEqual([
      {
        id: "folders/1000000001",
        kind: NODE_KIND.FOLDER,
        name: "Engineering",
        parentId: "organizations/456123789012",
      },
      {
        id: "folders/1000000002",
        kind: NODE_KIND.FOLDER,
        name: "Platform",
        parentId: "folders/1000000001",
      },
    ]);

    // Projects become candidates keyed by their provider uid (project_id).
    expect(gcpHierarchy.candidates.map((candidate) => candidate.uid)).toEqual([
      "prod-analytics",
      "legacy-sandbox",
    ]);
    expect(gcpHierarchy.candidates[0]).toMatchObject({
      uid: "prod-analytics",
      label: "Prod Analytics",
      parentId: "folders/1000000001",
    });
  });

  it("builds a folder/project tree with org-level projects at the top level", () => {
    // Given
    const gcpHierarchy = mapGcpDiscovery(gcpDiscoveryFixture);

    // When
    const treeData = buildOrgTreeData(gcpHierarchy);

    // Then — the org-level folder and the org-level blocked project are both
    // top-level; the nested folder sits under Engineering.
    expect(treeData.map((node) => node.id)).toEqual(
      expect.arrayContaining(["folders/1000000001", "legacy-sandbox"]),
    );
    const engineering = treeData.find(
      (node) => node.id === "folders/1000000001",
    );
    expect(engineering?.children?.map((node) => node.id)).toEqual(
      expect.arrayContaining(["folders/1000000002", "prod-analytics"]),
    );
    const blockedProject = treeData.find(
      (node) => node.id === "legacy-sandbox",
    );
    expect(blockedProject?.disabled).toBe(true);
  });

  it("treats only ready projects as selectable", () => {
    // Given
    const gcpHierarchy = mapGcpDiscovery(gcpDiscoveryFixture);

    // When / Then
    expect(getSelectableCandidateIds(gcpHierarchy)).toEqual(["prod-analytics"]);
  });
});

describe("buildOrgTreeData", () => {
  it("builds nested tree structure and marks blocked candidates as disabled", () => {
    // Given / When
    const treeData = buildOrgTreeData(hierarchy);

    // Then
    expect(treeData).toHaveLength(2);
    expect(treeData.map((node) => node.id)).toEqual(
      expect.arrayContaining(["ou-parent", "333333333333"]),
    );

    const parentOuNode = treeData.find((node) => node.id === "ou-parent");
    expect(parentOuNode).toBeDefined();
    expect(parentOuNode?.children?.map((node) => node.id)).toEqual(
      expect.arrayContaining(["ou-child", "222222222222"]),
    );

    const blockedCandidate = parentOuNode?.children?.find(
      (node) => node.id === "222222222222",
    );
    expect(blockedCandidate?.disabled).toBe(true);
  });
});

describe("getSelectableCandidateIds", () => {
  it("returns all candidates except explicitly blocked ones", () => {
    const selectableIds = getSelectableCandidateIds(hierarchy);

    expect(selectableIds).toEqual(["111111111111", "333333333333"]);
  });

  it("excludes candidates with explicit non-ready status values", () => {
    const hierarchyWithUnexpectedStatus = mapAwsDiscovery({
      ...awsDiscoveryFixture,
      accounts: [
        ...awsDiscoveryFixture.accounts,
        {
          id: "444444444444",
          arn: "arn:aws:organizations::123:account/o-example/444444444444",
          name: "Pending Account",
          email: "pending@example.com",
          status: "ACTIVE",
          joined_method: "CREATED",
          joined_timestamp: "2024-01-01T00:00:00Z",
          parent_id: "r-root",
          registration: {
            provider_exists: false,
            provider_id: null,
            organization_relation: "link_required",
            organization_node_relation: "link_required",
            provider_secret_state: "will_create",
            apply_status: "pending" as unknown as ApplyStatus,
            blocked_reasons: [],
          },
        },
      ],
    });

    const selectableIds = getSelectableCandidateIds(
      hierarchyWithUnexpectedStatus,
    );

    expect(selectableIds).toEqual(["111111111111", "333333333333"]);
  });
});

describe("buildCandidateLookup", () => {
  it("creates a lookup map for all discovered candidates", () => {
    const lookup = buildCandidateLookup(hierarchy);

    expect(lookup.get("111111111111")?.label).toBe("App Account");
    expect(lookup.get("333333333333")?.label).toBe("Legacy Account");
    expect(lookup.size).toBe(3);
  });
});

describe("getSelectableCandidateIdsForTarget", () => {
  it("scopes selection to candidates under a target node, including nested nodes", () => {
    // ou-parent contains ou-child (holds 111...) and the blocked 222...
    const scoped = getSelectableCandidateIdsForTarget(hierarchy, "ou-parent");

    // Only the selectable descendant is returned; blocked 222... is excluded,
    // and 333... (under the root, outside the node) is not included.
    expect(scoped).toEqual(["111111111111"]);
  });

  it("scopes selection to a leaf node", () => {
    const scoped = getSelectableCandidateIdsForTarget(hierarchy, "ou-child");

    expect(scoped).toEqual(["111111111111"]);
  });

  it("includes the deployment candidate even when it lives outside the target node", () => {
    // Deployment (management) account 333... sits under the root, but gets the
    // role via DeployLocalRole, so it must be pre-selected alongside the node.
    const scoped = getSelectableCandidateIdsForTarget(
      hierarchy,
      "ou-child",
      "333333333333",
    );

    expect(scoped).toEqual(["111111111111", "333333333333"]);
  });

  it("does not include a deployment candidate that is not selectable", () => {
    // 222... is blocked, so even as the deployment candidate it stays unselected.
    const scoped = getSelectableCandidateIdsForTarget(
      hierarchy,
      "ou-child",
      "222222222222",
    );

    expect(scoped).toEqual(["111111111111"]);
  });

  it("returns every selectable candidate for a root target (whole organization)", () => {
    const scoped = getSelectableCandidateIdsForTarget(hierarchy, "r-root");

    expect(scoped).toEqual(["111111111111", "333333333333"]);
  });

  it("falls back to all selectable candidates for an empty or unknown target", () => {
    expect(getSelectableCandidateIdsForTarget(hierarchy, "")).toEqual([
      "111111111111",
      "333333333333",
    ]);
    expect(
      getSelectableCandidateIdsForTarget(hierarchy, "ou-does-not-exist"),
    ).toEqual(["111111111111", "333333333333"]);
  });
});

describe("getNodeIdsForSelectedCandidates", () => {
  it("collects all ancestor nodes for selected candidates without duplicates", () => {
    const nodeIds = getNodeIdsForSelectedCandidates(hierarchy, [
      "111111111111",
      "222222222222",
    ]);

    expect(nodeIds).toEqual(expect.arrayContaining(["ou-parent", "ou-child"]));
    expect(nodeIds.length).toBe(2);
  });

  it("terminates on a cyclic parent chain instead of hanging", () => {
    // Parent ids are wire data. A cycle must not spin the ancestor walk: the
    // collected ids live in a Set, so nothing about re-adding them would ever
    // end the loop. Each node in the cycle is still reported once.
    const cyclicHierarchy: AwsOrgHierarchy = {
      orgType: ORGANIZATION_TYPE.AWS,
      organization: { uid: "o-cycle", name: "Cyclic Org" },
      nodes: [
        {
          id: "ou-a",
          kind: NODE_KIND.ORGANIZATIONAL_UNIT,
          name: "A",
          parentId: "ou-b",
        },
        {
          id: "ou-b",
          kind: NODE_KIND.ORGANIZATIONAL_UNIT,
          name: "B",
          parentId: "ou-a",
        },
        {
          id: "ou-self",
          kind: NODE_KIND.ORGANIZATIONAL_UNIT,
          name: "Self",
          parentId: "ou-self",
        },
      ],
      candidates: [
        { uid: "111111111111", label: "In cycle", parentId: "ou-a" },
        { uid: "222222222222", label: "Self-parented", parentId: "ou-self" },
      ],
    };

    const nodeIds = getNodeIdsForSelectedCandidates(cyclicHierarchy, [
      "111111111111",
      "222222222222",
    ]);

    expect([...nodeIds].sort()).toEqual(["ou-a", "ou-b", "ou-self"]);
  });
});

describe("buildApplyPayload", () => {
  it("builds the AWS payload with client-side derived organizational units", () => {
    const payload = buildApplyPayload(hierarchy, ["111111111111"], {
      "111111111111": "Renamed App",
    });

    expect(payload).toEqual({
      orgType: ORGANIZATION_TYPE.AWS,
      accounts: [{ id: "111111111111", alias: "Renamed App" }],
      organizationalUnits: [{ id: "ou-child" }, { id: "ou-parent" }],
    });
  });

  it("omits the alias when the candidate was not renamed", () => {
    const payload = buildApplyPayload(hierarchy, ["333333333333"], {});

    expect(payload).toEqual({
      orgType: ORGANIZATION_TYPE.AWS,
      accounts: [{ id: "333333333333" }],
      // 333... hangs off the root, so no node ancestors are derived.
      organizationalUnits: [],
    });
  });

  it("builds the GCP payload with projects only (folders are server-derived)", () => {
    const gcpHierarchy: GcpOrgHierarchy = {
      orgType: ORGANIZATION_TYPE.GCP,
      organization: { uid: "456123789012", name: "example.com" },
      nodes: [
        {
          id: "folders/1000000001",
          kind: NODE_KIND.FOLDER,
          name: "Engineering",
          parentId: "organizations/456123789012",
        },
      ],
      candidates: [
        {
          uid: "prod-analytics",
          label: "Prod Analytics",
          parentId: "folders/1000000001",
        },
      ],
    };

    const payload = buildApplyPayload(gcpHierarchy, ["prod-analytics"], {
      "prod-analytics": "Analytics",
    });

    expect(payload).toEqual({
      orgType: ORGANIZATION_TYPE.GCP,
      projects: [{ project_id: "prod-analytics", alias: "Analytics" }],
    });
  });
});
