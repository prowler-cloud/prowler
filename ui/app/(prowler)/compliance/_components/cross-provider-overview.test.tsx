import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ACTION_ERROR_STATUS, USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";
import { useComplianceWatchlistViewStore } from "@/store/compliance/store";
import { makeComplianceCatalogEntry } from "@/test-utils/compliance-watchlist";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";

import { getCrossProviderComplianceOverview } from "../_actions/cross-provider";
import { loadComplianceWatchlistContext } from "../_lib/watchlist-context";
import type { CrossProviderOverviewResult } from "../_types";
import {
  CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
  CROSS_PROVIDER_OVERVIEW_TYPE,
} from "../_types";

import { CrossProviderOverview } from "./cross-provider-overview";

vi.mock("../_actions/cross-provider", () => ({
  getCrossProviderComplianceOverview: vi.fn(),
}));

vi.mock("@/actions/providers", () => ({
  getAllProviders: vi.fn().mockResolvedValue({ data: [] }),
}));

vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: vi.fn().mockResolvedValue({ data: [] }),
}));

// The watchlist server actions pull in `@/lib`, which imports next-auth and
// cannot be loaded in this environment. They have their own tests.
vi.mock("@/actions/compliance-watchlist", () => ({
  getComplianceCatalog: vi.fn(),
  addComplianceToWatchlist: vi.fn(),
  removeComplianceFromWatchlist: vi.fn(),
  bulkUpdateComplianceWatchlist: vi.fn(),
}));

// The watchlist context reads the session through next-auth, which cannot be
// imported in this environment; the watchlist behaviour has its own tests.
// It also carries the catalog the section builds its cards from.
vi.mock("../_lib/watchlist-context", () => ({
  loadComplianceWatchlistContext: vi.fn(),
}));

vi.mock("./cross-provider-filters", () => ({
  CrossProviderFilters: () => <div data-testid="cross-provider-filters" />,
}));

vi.mock("./cross-provider-framework-card", () => ({
  CrossProviderFrameworkCard: ({
    title,
    watchlist,
    canManageWatchlist,
  }: {
    title: string;
    watchlist?: { state: string };
    canManageWatchlist?: boolean;
  }) => (
    <div
      data-testid="framework-card"
      data-pin-state={watchlist?.state}
      data-can-manage={String(Boolean(canManageWatchlist))}
    >
      {title}
    </div>
  ),
}));

const DORA_ID = "dora_2022_2554";

// One card per entry, ordered by title.
const UNIVERSAL_FRAMEWORKS = [
  { complianceId: "csa_ccm_4.0", framework: "CSA-CCM" },
  { complianceId: "cis_controls_8.1", framework: "CIS-Controls" },
  { complianceId: "cmmc_2.0", framework: "CMMC" },
  { complianceId: DORA_ID, framework: "DORA" },
];

const EXPECTED_TITLES = ["CIS-Controls", "CMMC", "CSA-CCM", "DORA"];

const catalogEntries = (pinned: string[] = []): ComplianceCatalogEntry[] =>
  UNIVERSAL_FRAMEWORKS.map(({ complianceId, framework }) =>
    makeComplianceCatalogEntry({
      complianceId,
      // The catalog keys a universal framework under `*`.
      providerType: "*",
      framework,
      inWatchlist: pinned.includes(complianceId),
      watchlistEntryId: pinned.includes(complianceId)
        ? `entry-${complianceId}`
        : null,
    }),
  );

const withCatalog = (
  entries: ComplianceCatalogEntry[],
  eligibleProviderTypes: string[] = ["aws", "azure"],
  canManage = true,
  unavailable = false,
) =>
  vi.mocked(loadComplianceWatchlistContext).mockResolvedValue({
    entries,
    eligibleProviderTypes,
    canManage,
    unavailable,
  });

const successResult = (complianceId: string): CrossProviderOverviewResult => ({
  status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS,
  response: {
    data: {
      type: CROSS_PROVIDER_OVERVIEW_TYPE,
      id: complianceId,
      attributes: {
        compliance_id: complianceId,
        framework: complianceId,
        name: complianceId,
        version: "1.0",
        description: "",
        compatible_providers: ["aws"],
        requested_providers: ["aws"],
        providers: ["aws"],
        scan_ids: [],
        scan_ids_by_provider: {},
        requirements_passed: 1,
        requirements_failed: 0,
        requirements_manual: 0,
        total_requirements: 1,
        requirements: [],
      },
    },
  },
});

const loadErrorResult: CrossProviderOverviewResult = {
  status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
  message: CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
};

const renderOverview = async () =>
  render(await CrossProviderOverview({ searchParams: {} }));

describe("CrossProviderOverview", () => {
  beforeEach(() => {
    vi.mocked(getCrossProviderComplianceOverview).mockReset();
    vi.mocked(loadComplianceWatchlistContext).mockReset();
    withCatalog(catalogEntries());
  });

  it("renders one card per universal framework the catalog reports", async () => {
    // ACME is what an entry-point package would contribute.
    withCatalog([
      ...catalogEntries(),
      makeComplianceCatalogEntry({
        complianceId: "acme_1.0",
        providerType: "*",
        framework: "ACME",
      }),
    ]);
    vi.mocked(getCrossProviderComplianceOverview).mockImplementation(
      async ({ complianceId }) => successResult(complianceId),
    );

    // When
    await renderOverview();

    // Then
    const cards = screen.getAllByTestId("framework-card");
    expect(cards.map((card) => card.textContent)).toEqual([
      "ACME",
      ...EXPECTED_TITLES,
    ]);
  });

  it("renders no cards when the catalog reports no universal framework", async () => {
    withCatalog([]);

    await renderOverview();

    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
    expect(getCrossProviderComplianceOverview).not.toHaveBeenCalled();
    expect(
      screen.getByText(/No cross-provider compliance data yet/i),
    ).toBeInTheDocument();
  });

  it("reports the failure instead of claiming there is no data", async () => {
    withCatalog([], ["aws", "azure"], true, true);

    await renderOverview();

    expect(
      screen.getByText(CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/No cross-provider compliance data yet/i),
    ).not.toBeInTheDocument();
    expect(getCrossProviderComplianceOverview).not.toHaveBeenCalled();
  });

  it("degrades to a partial view when a single framework fails to load", async () => {
    // Given: DORA fails, the other frameworks load
    vi.mocked(getCrossProviderComplianceOverview).mockImplementation(
      async ({ complianceId }) =>
        complianceId === DORA_ID
          ? loadErrorResult
          : successResult(complianceId),
    );

    // When
    await renderOverview();

    // Then: loaded cards render, the failed framework is called out by name
    expect(screen.getAllByTestId("framework-card")).toHaveLength(
      UNIVERSAL_FRAMEWORKS.length - 1,
    );
    expect(screen.getByText(/Could not load DORA/)).toBeInTheDocument();
    expect(
      screen.queryByText(CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE),
    ).not.toBeInTheDocument();
  });

  it("replaces the tab with the error alert when every framework fails to load", async () => {
    // Given
    vi.mocked(getCrossProviderComplianceOverview).mockResolvedValue(
      loadErrorResult,
    );

    // When
    await renderOverview();

    // Then
    expect(
      screen.getByText(CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
  });

  it("gates the whole tab on an action error even if other frameworks loaded", async () => {
    // Given: one framework hits the usage limit (402)
    vi.mocked(getCrossProviderComplianceOverview).mockImplementation(
      async ({ complianceId }) =>
        complianceId === DORA_ID
          ? {
              status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR,
              result: { status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED },
            }
          : successResult(complianceId),
    );

    // When
    await renderOverview();

    // Then
    expect(
      screen.getByText(new RegExp(USAGE_LIMIT_MESSAGE)),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
  });
});

describe("CrossProviderOverview watchlist", () => {
  beforeEach(() => {
    localStorage.clear();
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: false });
    vi.mocked(loadComplianceWatchlistContext).mockReset();
    vi.mocked(getCrossProviderComplianceOverview).mockImplementation(
      async ({ complianceId }) => successResult(complianceId),
    );
  });

  it("keeps the catalog order when one framework is pinned", async () => {
    withCatalog(catalogEntries([DORA_ID]));

    await renderOverview();

    const cards = screen.getAllByTestId("framework-card");
    expect(cards.map((card) => card.textContent)).toEqual(EXPECTED_TITLES);
    expect(cards[EXPECTED_TITLES.indexOf("DORA")]).toHaveAttribute(
      "data-pin-state",
      "pinned",
    );
  });

  it("narrows the grid to the pinned frameworks when the filter is on", async () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });
    withCatalog(catalogEntries([DORA_ID]));

    await renderOverview();

    const cards = screen.getAllByTestId("framework-card");
    expect(cards).toHaveLength(1);
    expect(cards[0]).toHaveTextContent("DORA");
  });

  it("explains the blank grid when nothing universal is pinned", async () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });
    withCatalog(catalogEntries());

    await renderOverview();

    expect(
      screen.getByText(/no universal framework is pinned/i),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("framework-card")).not.toBeInTheDocument();
  });

  it("cannot manage the watchlist without the permission", async () => {
    withCatalog(catalogEntries([DORA_ID]), ["aws", "azure"], false);

    await renderOverview();

    for (const card of screen.getAllByTestId("framework-card")) {
      expect(card).toHaveAttribute("data-can-manage", "false");
    }
  });
});
