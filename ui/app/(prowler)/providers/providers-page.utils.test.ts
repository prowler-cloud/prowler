import { describe, expect, it, vi } from "vitest";

const providersActionsMock = vi.hoisted(() => ({
  getProviders: vi.fn(),
}));

const organizationsActionsMock = vi.hoisted(() => ({
  listOrganizationsSafe: vi.fn(),
  listOrganizationUnitsSafe: vi.fn(),
}));

const scansActionsMock = vi.hoisted(() => ({
  getScans: vi.fn(),
}));

vi.mock("@/actions/providers", () => providersActionsMock);
vi.mock(
  "@/actions/organizations/organizations",
  () => organizationsActionsMock,
);
vi.mock("@/actions/scans", () => scansActionsMock);

import { SearchParamsProps } from "@/types";
import { ProvidersApiResponse } from "@/types/providers";
import { ProvidersProviderRow } from "@/types/providers-table";

import {
  buildProvidersTableRows,
  loadProvidersAccountsViewData,
  PROVIDERS_ROW_TYPE,
} from "./providers-page.utils";

const providersResponse: ProvidersApiResponse = {
  links: {
    first: "",
    last: "",
    next: null,
    prev: null,
  },
  data: [
    {
      id: "provider-1",
      type: "providers",
      attributes: {
        provider: "aws",
        uid: "111111111111",
        alias: "AWS App Account",
        status: "completed",
        resources: 0,
        connection: {
          connected: true,
          last_checked_at: "2025-02-13T11:17:00Z",
        },
        scanner_args: {
          only_logs: false,
          excluded_checks: [],
          aws_retries_max_attempts: 3,
        },
        inserted_at: "2025-02-13T11:17:00Z",
        updated_at: "2025-02-13T11:17:00Z",
        created_by: {
          object: "user",
          id: "user-1",
        },
      },
      relationships: {
        secret: {
          data: {
            type: "provider-secrets",
            id: "secret-1",
          },
        },
        provider_groups: {
          meta: {
            count: 1,
          },
          data: [
            {
              type: "provider-groups",
              id: "group-1",
            },
          ],
        },
      },
    },
    {
      id: "provider-2",
      type: "providers",
      attributes: {
        provider: "aws",
        uid: "222222222222",
        alias: "Standalone Account",
        status: "completed",
        resources: 0,
        connection: {
          connected: false,
          last_checked_at: "2025-02-13T11:17:00Z",
        },
        scanner_args: {
          only_logs: false,
          excluded_checks: [],
          aws_retries_max_attempts: 3,
        },
        inserted_at: "2025-02-13T11:17:00Z",
        updated_at: "2025-02-13T11:17:00Z",
        created_by: {
          object: "user",
          id: "user-1",
        },
      },
      relationships: {
        secret: {
          data: null,
        },
        provider_groups: {
          meta: {
            count: 0,
          },
          data: [],
        },
      },
    },
  ],
  included: [
    {
      type: "provider-groups",
      id: "group-1",
      attributes: {
        name: "AWS Team",
      },
    },
  ],
  meta: {
    pagination: {
      page: 1,
      pages: 1,
      count: 2,
    },
    version: "1",
  },
};

const toProviderRow = (
  provider: (typeof providersResponse.data)[number],
  overrides?: Partial<ProvidersProviderRow>,
): ProvidersProviderRow => ({
  ...provider,
  ...overrides,
  rowType: PROVIDERS_ROW_TYPE.PROVIDER,
  groupNames: provider.id === "provider-1" ? ["AWS Team"] : [],
  hasSchedule: false,
  relationships: {
    ...provider.relationships,
    ...overrides?.relationships,
  },
});

describe("buildProvidersTableRows", () => {
  it("returns a flat providers table for OSS", () => {
    // Given
    const providers = providersResponse.data.map((provider) =>
      toProviderRow(provider),
    );

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [],
      organizationUnits: [],
      isCloud: false,
    });

    // Then
    expect(rows).toHaveLength(2);
    expect(rows[0].rowType).toBe(PROVIDERS_ROW_TYPE.PROVIDER);
    expect(rows[1].rowType).toBe(PROVIDERS_ROW_TYPE.PROVIDER);
  });

  it("nests providers under organizations and organization units in cloud", () => {
    // Given
    const providers = providersResponse.data.map((provider) =>
      toProviderRow(provider, {
        relationships: {
          ...provider.relationships,
          organization: {
            data:
              provider.id === "provider-1"
                ? { type: "organizations", id: "org-1" }
                : null,
          },
          organization_unit: {
            data:
              provider.id === "provider-1"
                ? { type: "organizational-units", id: "ou-1" }
                : null,
          },
        },
      }),
    );

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Root Organization",
            org_type: "aws",
            external_id: "o-root",
            metadata: {},
            root_external_id: "r-root",
          },
          relationships: {},
        },
      ],
      organizationUnits: [
        {
          id: "ou-1",
          type: "organizational-units",
          attributes: {
            name: "Security OU",
            external_id: "ou-security",
            parent_external_id: "r-root",
            metadata: {},
          },
          relationships: {
            organization: {
              data: {
                type: "organizations",
                id: "org-1",
              },
            },
          },
        },
      ],
      isCloud: true,
    });

    // Then
    expect(rows).toHaveLength(2);
    expect(rows[0].rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(rows[0].subRows).toHaveLength(1);
    expect(rows[0].subRows?.[0].rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(rows[0].subRows?.[0].subRows?.[0].rowType).toBe(
      PROVIDERS_ROW_TYPE.PROVIDER,
    );
    expect(rows[1].rowType).toBe(PROVIDERS_ROW_TYPE.PROVIDER);
  });

  it("nests organizational units recursively up to multiple levels", () => {
    // Given — OU hierarchy: org-1 > ou-root > ou-child > ou-grandchild
    const providers = [
      toProviderRow(providersResponse.data[0], {
        relationships: {
          ...providersResponse.data[0].relationships,
          organization: {
            data: { type: "organizations", id: "org-1" },
          },
          organization_unit: {
            data: { type: "organizational-units", id: "ou-grandchild" },
          },
        },
      }),
    ];

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Root Organization",
            org_type: "aws",
            external_id: "o-root",
            metadata: {},
            root_external_id: "r-root",
          },
          relationships: {},
        },
      ],
      organizationUnits: [
        {
          id: "ou-root",
          type: "organizational-units",
          attributes: {
            name: "Production",
            external_id: "ou-prod",
            parent_external_id: "r-root",
            metadata: {},
          },
          relationships: {
            organization: {
              data: { type: "organizations", id: "org-1" },
            },
          },
        },
        {
          id: "ou-child",
          type: "organizational-units",
          attributes: {
            name: "EMEA",
            external_id: "ou-emea",
            parent_external_id: "ou-prod",
            metadata: {},
          },
          relationships: {
            organization: {
              data: { type: "organizations", id: "org-1" },
            },
          },
        },
        {
          id: "ou-grandchild",
          type: "organizational-units",
          attributes: {
            name: "Security",
            external_id: "ou-security",
            parent_external_id: "ou-emea",
            metadata: {},
          },
          relationships: {
            organization: {
              data: { type: "organizations", id: "org-1" },
            },
          },
        },
      ],
      isCloud: true,
    });

    // Then — org > ou-root > ou-child > ou-grandchild > provider
    expect(rows).toHaveLength(1);
    const orgRow = rows[0];
    expect(orgRow.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(orgRow.subRows).toHaveLength(1);

    const ouRoot = orgRow.subRows![0];
    expect(ouRoot.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(ouRoot.subRows).toHaveLength(1);

    const ouChild = ouRoot.subRows![0];
    expect(ouChild.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(ouChild.subRows).toHaveLength(1);

    const ouGrandchild = ouChild.subRows![0];
    expect(ouGrandchild.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(ouGrandchild.subRows).toHaveLength(1);
    expect(ouGrandchild.subRows![0].rowType).toBe(PROVIDERS_ROW_TYPE.PROVIDER);
  });

  it("nests providers under OUs using relationship-based parent IDs", () => {
    // Given — providers have no org/OU linkage; tree is built from OU relationships
    const providers = [toProviderRow(providersResponse.data[0])];

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Root Organization",
            org_type: "aws",
            external_id: "o-root",
            metadata: {},
            root_external_id: "r-root",
          },
          relationships: {},
        },
      ],
      organizationUnits: [
        {
          id: "ou-parent",
          type: "organizational-units",
          attributes: {
            name: "Workloads",
            external_id: "ou-workloads",
            parent_external_id: null,
            metadata: {},
          },
          relationships: {
            organization: {
              data: { type: "organizations", id: "org-1" },
            },
            parent: {
              data: null,
            },
          },
        },
        {
          id: "ou-child",
          type: "organizational-units",
          attributes: {
            name: "Team A",
            external_id: "ou-team-a",
            parent_external_id: null,
            metadata: {},
          },
          relationships: {
            organization: {
              data: { type: "organizations", id: "org-1" },
            },
            parent: {
              data: { type: "organizational-units", id: "ou-parent" },
            },
            providers: {
              data: [{ type: "providers", id: "provider-1" }],
            },
          },
        },
      ],
      isCloud: true,
    });

    // Then — org > ou-parent > ou-child > provider
    // Provider is claimed by ou-child via relationships, so org's direct
    // providers list becomes empty and the org row only contains the OU subtree.
    expect(rows).toHaveLength(1);
    const orgRow = rows[0];
    expect(orgRow.subRows).toHaveLength(1);

    const ouParent = orgRow.subRows![0];
    expect(ouParent.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(ouParent.subRows).toHaveLength(1);

    const ouChild = ouParent.subRows![0];
    expect(ouChild.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(ouChild.subRows).toHaveLength(1);
    expect(ouChild.subRows![0].rowType).toBe(PROVIDERS_ROW_TYPE.PROVIDER);
  });

  it("does not duplicate providers that appear in both org relationships and OU assignments", () => {
    // Given — provider-1 is linked to org-1 AND assigned to ou-1
    const providers = [
      toProviderRow(providersResponse.data[0], {
        relationships: {
          ...providersResponse.data[0].relationships,
          organization: {
            data: { type: "organizations", id: "org-1" },
          },
          organization_unit: {
            data: { type: "organizational-units", id: "ou-1" },
          },
        },
      }),
    ];

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Root Organization",
            org_type: "aws",
            external_id: "o-root",
            metadata: {},
            root_external_id: "r-root",
          },
          relationships: {
            providers: {
              data: [{ type: "providers", id: "provider-1" }],
            },
          },
        },
      ],
      organizationUnits: [
        {
          id: "ou-1",
          type: "organizational-units",
          attributes: {
            name: "Security OU",
            external_id: "ou-security",
            parent_external_id: "r-root",
            metadata: {},
          },
          relationships: {
            organization: {
              data: { type: "organizations", id: "org-1" },
            },
          },
        },
      ],
      isCloud: true,
    });

    // Then — provider appears only under OU, not duplicated at org level
    expect(rows).toHaveLength(1);
    const orgRow = rows[0];
    expect(orgRow.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    // Org should contain only the OU row, not the provider directly
    expect(orgRow.subRows).toHaveLength(1);
    expect(orgRow.subRows![0].rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    // The OU should contain the provider
    expect(orgRow.subRows![0].subRows).toHaveLength(1);
    expect(orgRow.subRows![0].subRows![0].rowType).toBe(
      PROVIDERS_ROW_TYPE.PROVIDER,
    );
    expect(orgRow.subRows![0].subRows![0].id).toBe("provider-1");
  });

  it("keeps org-only providers as direct org children even when org has relationship data", () => {
    // Given — provider-1 belongs to org-1 but has no OU
    const providers = [
      toProviderRow(providersResponse.data[0], {
        relationships: {
          ...providersResponse.data[0].relationships,
          organization: {
            data: { type: "organizations", id: "org-1" },
          },
          organization_unit: {
            data: null,
          },
        },
      }),
    ];

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Root Organization",
            org_type: "aws",
            external_id: "o-root",
            metadata: {},
            root_external_id: "r-root",
          },
          relationships: {
            providers: {
              data: [{ type: "providers", id: "provider-1" }],
            },
          },
        },
      ],
      organizationUnits: [],
      isCloud: true,
    });

    // Then — provider appears as a direct child of the org
    expect(rows).toHaveLength(1);
    const orgRow = rows[0];
    expect(orgRow.rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(orgRow.subRows).toHaveLength(1);
    expect(orgRow.subRows![0].rowType).toBe(PROVIDERS_ROW_TYPE.PROVIDER);
    expect(orgRow.subRows![0].id).toBe("provider-1");
  });

  it("groups providers from organization relationships when provider resources do not expose organization linkage", () => {
    // Given
    const providers = providersResponse.data.map((provider) =>
      toProviderRow(provider, {
        relationships: {
          ...provider.relationships,
          organization: {
            data: null,
          },
          organization_unit: {
            data: null,
          },
        },
      }),
    );

    // When
    const rows = buildProvidersTableRows({
      providers,
      organizations: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Shared Organization",
            org_type: "aws",
            external_id: "o-shared",
            metadata: {},
            root_external_id: "r-shared",
          },
          relationships: {
            providers: {
              data: [
                { type: "providers", id: "provider-1" },
                { type: "providers", id: "provider-2" },
              ],
            },
            organizational_units: {
              data: [],
            },
          },
        },
      ],
      organizationUnits: [],
      isCloud: true,
    });

    // Then
    expect(rows).toHaveLength(1);
    expect(rows[0].rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
    expect(rows[0].subRows).toHaveLength(2);
    expect(
      rows[0].subRows?.every(
        (row) => row.rowType === PROVIDERS_ROW_TYPE.PROVIDER,
      ),
    ).toBe(true);
  });
});

describe("loadProvidersAccountsViewData", () => {
  it("does not call organizations endpoints in OSS", async () => {
    // Given
    providersActionsMock.getProviders.mockResolvedValue(providersResponse);
    scansActionsMock.getScans.mockResolvedValue({ data: [] });

    // When
    const viewData = await loadProvidersAccountsViewData({
      searchParams: {} satisfies SearchParamsProps,
      isCloud: false,
    });

    // Then
    expect(
      organizationsActionsMock.listOrganizationsSafe,
    ).not.toHaveBeenCalled();
    expect(
      organizationsActionsMock.listOrganizationUnitsSafe,
    ).not.toHaveBeenCalled();
    expect(viewData.filters.map((filter) => filter.labelCheckboxGroup)).toEqual(
      ["Status"],
    );
  });

  it("loads organizations filters and recursive rows in cloud", async () => {
    // Given
    providersActionsMock.getProviders.mockResolvedValue({
      ...providersResponse,
      data: providersResponse.data.map((provider) => ({
        ...provider,
        relationships: {
          ...provider.relationships,
          organization: {
            data:
              provider.id === "provider-1"
                ? { type: "organizations", id: "org-1" }
                : null,
          },
          organization_unit: {
            data:
              provider.id === "provider-1"
                ? { type: "organizational-units", id: "ou-1" }
                : null,
          },
        },
      })),
    });
    organizationsActionsMock.listOrganizationsSafe.mockResolvedValue({
      data: [
        {
          id: "org-1",
          type: "organizations",
          attributes: {
            name: "Root Organization",
            org_type: "aws",
            external_id: "o-root",
            metadata: {},
            root_external_id: "r-root",
          },
          relationships: {},
        },
      ],
    });
    organizationsActionsMock.listOrganizationUnitsSafe.mockResolvedValue({
      data: [
        {
          id: "ou-1",
          type: "organizational-units",
          attributes: {
            name: "Security OU",
            external_id: "ou-security",
            parent_external_id: "r-root",
            metadata: {},
          },
          relationships: {
            organization: {
              data: {
                type: "organizations",
                id: "org-1",
              },
            },
          },
        },
      ],
    });
    scansActionsMock.getScans.mockResolvedValue({ data: [] });

    // When
    const viewData = await loadProvidersAccountsViewData({
      searchParams: {} satisfies SearchParamsProps,
      isCloud: true,
    });

    // Then
    expect(
      organizationsActionsMock.listOrganizationsSafe,
    ).toHaveBeenCalledTimes(1);
    expect(
      organizationsActionsMock.listOrganizationUnitsSafe,
    ).toHaveBeenCalledTimes(1);
    expect(viewData.filters.map((filter) => filter.labelCheckboxGroup)).toEqual(
      ["Status"],
    );
    expect(viewData.rows[0].rowType).toBe(PROVIDERS_ROW_TYPE.ORGANIZATION);
  });

  it("falls back to empty cloud grouping data when organizations endpoints fail", async () => {
    // Given
    providersActionsMock.getProviders.mockResolvedValue(providersResponse);
    organizationsActionsMock.listOrganizationsSafe.mockResolvedValue({
      data: [],
    });
    organizationsActionsMock.listOrganizationUnitsSafe.mockResolvedValue({
      data: [],
    });
    scansActionsMock.getScans.mockResolvedValue({ data: [] });

    // When
    const viewData = await loadProvidersAccountsViewData({
      searchParams: {} satisfies SearchParamsProps,
      isCloud: true,
    });

    // Then
    expect(viewData.filters.map((filter) => filter.labelCheckboxGroup)).toEqual(
      ["Status"],
    );
    expect(viewData.rows).toHaveLength(2);
    expect(
      viewData.rows.every((row) => row.rowType === PROVIDERS_ROW_TYPE.PROVIDER),
    ).toBe(true);
  });
});
