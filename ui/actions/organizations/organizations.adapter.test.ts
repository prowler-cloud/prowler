import { describe, expect, it } from "vitest";

import {
  APPLY_STATUS,
  ApplyStatus,
  DiscoveryResult,
} from "@/types/organizations";

import {
  buildAccountLookup,
  buildOrgTreeData,
  getOuIdsForSelectedAccounts,
  getSelectableAccountIds,
} from "./organizations.adapter";

const discoveryFixture: DiscoveryResult = {
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
        organizational_unit_relation: "link_required",
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
        organizational_unit_relation: "link_required",
        provider_secret_state: "manual_required",
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

describe("buildOrgTreeData", () => {
  it("builds nested tree structure and marks blocked accounts as disabled", () => {
    // Given / When
    const treeData = buildOrgTreeData(discoveryFixture);

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

    const blockedAccount = parentOuNode?.children?.find(
      (node) => node.id === "222222222222",
    );
    expect(blockedAccount?.disabled).toBe(true);
  });
});

describe("getSelectableAccountIds", () => {
  it("returns all accounts except explicitly blocked ones", () => {
    const selectableIds = getSelectableAccountIds(discoveryFixture);

    expect(selectableIds).toEqual(["111111111111", "333333333333"]);
  });

  it("excludes accounts with explicit non-ready status values", () => {
    const discoveryWithUnexpectedStatus = {
      ...discoveryFixture,
      accounts: [
        ...discoveryFixture.accounts,
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
            organizational_unit_relation: "link_required",
            provider_secret_state: "will_create",
            apply_status: "pending" as unknown as ApplyStatus,
            blocked_reasons: [],
          },
        },
      ],
    } satisfies DiscoveryResult;

    const selectableIds = getSelectableAccountIds(
      discoveryWithUnexpectedStatus,
    );

    expect(selectableIds).toEqual(["111111111111", "333333333333"]);
  });
});

describe("buildAccountLookup", () => {
  it("creates a lookup map for all discovered accounts", () => {
    const lookup = buildAccountLookup(discoveryFixture);

    expect(lookup.get("111111111111")?.name).toBe("App Account");
    expect(lookup.get("333333333333")?.name).toBe("Legacy Account");
    expect(lookup.size).toBe(3);
  });
});

describe("getOuIdsForSelectedAccounts", () => {
  it("collects all ancestor OUs for selected accounts without duplicates", () => {
    const ouIds = getOuIdsForSelectedAccounts(discoveryFixture, [
      "111111111111",
      "222222222222",
    ]);

    expect(ouIds).toEqual(expect.arrayContaining(["ou-parent", "ou-child"]));
    expect(ouIds.length).toBe(2);
  });
});
