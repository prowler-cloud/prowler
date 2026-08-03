import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TourStepHandlers } from "@/lib/tours/tour-types";
import type { ViewComplianceTourTarget } from "@/lib/tours/view-compliance.tour";
import { VIEW_COMPLIANCE_TOUR_TARGETS } from "@/lib/tours/view-compliance.tour";
import { useComplianceWatchlistViewStore } from "@/store/compliance/store";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import {
  UNIVERSAL_PROVIDER_TYPE,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";

import { ComplianceOverviewGrid } from "./compliance-overview-grid";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/compliance",
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: () => null,
}));

type ViewComplianceStepHandlers = {
  [K in ViewComplianceTourTarget]?: TourStepHandlers<ViewComplianceTourTarget>;
};

// Captured so the tour's own step handlers can be exercised: the trigger is a
// driver.js host, and the handlers are the only part of it this grid owns.
const capturedStepHandlers = vi.hoisted(() => ({
  current: {} as ViewComplianceStepHandlers,
}));

vi.mock("@/components/onboarding", () => ({
  OnboardingTrigger: ({
    stepHandlers,
  }: {
    stepHandlers: ViewComplianceStepHandlers;
  }) => {
    capturedStepHandlers.current = stepHandlers;
    return null;
  },
  PageReady: () => null,
}));

vi.mock("@/actions/compliance-watchlist", () => ({
  addComplianceToWatchlist: vi.fn(),
  bulkUpdateComplianceWatchlist: vi.fn(),
  removeComplianceFromWatchlist: vi.fn(),
}));

vi.mock("./compliance-card", () => ({
  ComplianceCard: ({
    title,
    watchlistAction,
  }: {
    title: string;
    watchlistAction?: ReactNode;
  }) => (
    <div data-testid={`card-${title}`}>
      {title}
      {watchlistAction}
    </div>
  ),
}));

const framework = (id: string, frameworkName: string): ComplianceOverviewData =>
  ({
    id,
    type: "compliance-overviews",
    attributes: {
      framework: frameworkName,
      version: "1.0",
      requirements_passed: 5,
      requirements_failed: 5,
      total_requirements: 10,
    },
  }) as unknown as ComplianceOverviewData;

const FRAMEWORKS = [
  framework("cis_1.4_aws", "CIS"),
  framework("gdpr_aws", "GDPR"),
  framework("iso27001_aws", "ISO27001"),
];

const catalogEntry = (
  complianceId: string,
  inWatchlist: boolean,
): ComplianceCatalogEntry => ({
  id: `aws:${complianceId}`,
  scope: WATCHLIST_SCOPE.PROVIDER,
  providerTypes: ["aws"],
  complianceId,
  providerType: "aws",
  framework: complianceId,
  name: complianceId,
  version: "1.0",
  description: "",
  totalRequirements: 10,
  requirementsPassed: 5,
  requirementsFailed: 5,
  requirementsManual: 0,
  score: 50,
  hasData: true,
  inWatchlist,
  watchlistEntryId: inWatchlist ? "3fa85f64-5717-4562-b3fc-2c963f66afa6" : null,
});

beforeEach(() => {
  localStorage.clear();
  useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: false });
});

const renderGrid = (
  overrides: Partial<Parameters<typeof ComplianceOverviewGrid>[0]> = {},
) =>
  render(
    <ComplianceOverviewGrid
      frameworks={FRAMEWORKS}
      scanId="scan-1"
      {...overrides}
    />,
  );

describe("ComplianceOverviewGrid without the watchlist (OSS / no catalog)", () => {
  it("keeps the flat single-grid layout", () => {
    renderGrid();

    expect(screen.getByTestId("card-CIS")).toBeInTheDocument();
    expect(screen.queryByText(/compliance watchlist/i)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/all compliance frameworks/i),
    ).not.toBeInTheDocument();
  });

  it("renders no watchlist affordances at all", () => {
    renderGrid();

    expect(
      screen.queryByRole("button", { name: /edit watchlist/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Watchlist" }),
    ).not.toBeInTheDocument();
  });

  it("still reports the total entries counter", () => {
    renderGrid();

    expect(screen.getByText("3 Total Entries")).toBeInTheDocument();
  });
});

describe("ComplianceOverviewGrid with a curated watchlist", () => {
  const catalogEntries = [
    catalogEntry("cis_1.4_aws", true),
    catalogEntry("gdpr_aws", false),
    catalogEntry("iso27001_aws", false),
  ];

  it("shows the whole catalog while the filter is off", () => {
    renderGrid({ catalogEntries, providerType: "aws" });

    expect(screen.getByTestId("card-CIS")).toBeInTheDocument();
    expect(screen.getByTestId("card-GDPR")).toBeInTheDocument();
    expect(screen.getByTestId("card-ISO27001")).toBeInTheDocument();
    expect(screen.getByText("3 Total Entries")).toBeInTheDocument();
  });

  it("narrows the grid to the pinned frameworks when the filter is on", () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    renderGrid({ catalogEntries, providerType: "aws" });

    expect(screen.getByTestId("card-CIS")).toBeInTheDocument();
    expect(screen.queryByTestId("card-GDPR")).not.toBeInTheDocument();
    expect(screen.getByText("1 Total Entries")).toBeInTheDocument();
  });

  it("offers the pin action on every card when the user can manage the account", () => {
    renderGrid({
      catalogEntries,
      providerType: "aws",
      canManageWatchlist: true,
    });

    // One toggle per card, told apart by `aria-pressed` rather than by a
    // swapped label — which is what a screen reader actually announces.
    const toggles = screen.getAllByRole("button", { name: "Watchlist" });
    expect(toggles).toHaveLength(3);
    expect(
      toggles.some((toggle) => toggle.getAttribute("aria-pressed") === "true"),
    ).toBe(true);
    expect(
      toggles.some((toggle) => toggle.getAttribute("aria-pressed") === "false"),
    ).toBe(true);
  });

  it("hides the per-card pin without the manage account permission", () => {
    renderGrid({
      catalogEntries,
      providerType: "aws",
      canManageWatchlist: false,
    });

    expect(screen.getByTestId("card-CIS")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Watchlist" }),
    ).not.toBeInTheDocument();
  });

  it("still filters for a viewer who cannot curate the list", () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    renderGrid({
      catalogEntries,
      providerType: "aws",
      canManageWatchlist: false,
    });

    expect(screen.getByTestId("card-CIS")).toBeInTheDocument();
    expect(screen.queryByTestId("card-GDPR")).not.toBeInTheDocument();
  });
});

describe("ComplianceOverviewGrid with an empty watchlist", () => {
  const catalogEntries = [
    catalogEntry("cis_1.4_aws", false),
    catalogEntry("gdpr_aws", false),
    catalogEntry("iso27001_aws", false),
  ];

  it("explains the blank grid when the filter hides everything", () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    renderGrid({
      catalogEntries,
      providerType: "aws",
      canManageWatchlist: true,
    });

    expect(screen.getByText(/no frameworks pinned yet/i)).toBeVisible();
    expect(screen.queryByTestId("card-CIS")).not.toBeInTheDocument();
  });

  it("shows the flat grid while the filter is off", () => {
    renderGrid({
      catalogEntries,
      providerType: "aws",
      canManageWatchlist: false,
    });

    expect(
      screen.queryByText(/no frameworks pinned yet/i),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("card-CIS")).toBeInTheDocument();
  });
});

describe("ComplianceOverviewGrid with a universal framework", () => {
  // The catalog keys a universal framework under `*`, while this per-scan grid
  // only knows the scan's own provider type — the wildcard fallback is what
  // makes the two agree.
  const universalEntries = [
    {
      ...catalogEntry("cis_controls_8.1", true),
      id: `${UNIVERSAL_PROVIDER_TYPE}:cis_controls_8.1`,
      providerType: UNIVERSAL_PROVIDER_TYPE,
      scope: WATCHLIST_SCOPE.UNIVERSAL,
      providerTypes: ["aws", "azure"],
    },
    catalogEntry("gdpr_aws", false),
  ];
  const universalFrameworks = [
    framework("cis_controls_8.1", "CIS-Controls"),
    framework("gdpr_aws", "GDPR"),
  ];

  it("reads the pinned state of a universal framework from the wildcard row", () => {
    render(
      <ComplianceOverviewGrid
        frameworks={universalFrameworks}
        scanId="scan-1"
        catalogEntries={universalEntries}
        providerType="aws"
        canManageWatchlist
      />,
    );

    const toggles = screen.getAllByRole("button", { name: "Watchlist" });
    expect(toggles).toHaveLength(2);
    expect(toggles[0]).toHaveAttribute("aria-pressed", "true");
    expect(toggles[1]).toHaveAttribute("aria-pressed", "false");
  });

  it("keeps the universal framework under the filter", () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    render(
      <ComplianceOverviewGrid
        frameworks={universalFrameworks}
        scanId="scan-1"
        catalogEntries={universalEntries}
        providerType="aws"
      />,
    );

    expect(screen.getByTestId("card-CIS-Controls")).toBeInTheDocument();
    expect(screen.queryByTestId("card-GDPR")).not.toBeInTheDocument();
  });
});

describe("ComplianceOverviewGrid tour anchor", () => {
  const searchHandlers = () =>
    capturedStepHandlers.current[VIEW_COMPLIANCE_TOUR_TARGETS.SEARCH];

  it("carries the anchor on exactly one card", () => {
    // `tour:check` only greps for the attribute; that exactly one element gets
    // it — the first card the user sees — is this test's job. Anchoring the
    // whole grid lit up the viewport and scrolled the page to the bottom.
    const { container } = renderGrid();

    const anchored = container.querySelectorAll(
      '[data-tour-id="view-compliance-frameworks"]',
    );
    expect(anchored).toHaveLength(1);
    expect(anchored[0]).toHaveTextContent("CIS");
  });

  it("moves the anchor to the first pinned card, matching the render order", () => {
    renderGrid({
      catalogEntries: [
        catalogEntry("cis_1.4_aws", false),
        catalogEntry("gdpr_aws", true),
        catalogEntry("iso27001_aws", false),
      ],
      providerType: "aws",
    });

    expect(
      document.querySelector('[data-tour-id="view-compliance-frameworks"]'),
    ).toHaveTextContent("GDPR");
  });

  it("drops the anchor entirely when the filter hides every card", () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    renderGrid({
      catalogEntries: [
        catalogEntry("cis_1.4_aws", false),
        catalogEntry("gdpr_aws", false),
        catalogEntry("iso27001_aws", false),
      ],
      providerType: "aws",
    });

    expect(
      document.querySelector('[data-tour-id="view-compliance-frameworks"]'),
    ).toBeNull();
  });

  it("waits for the framework card when one will render", async () => {
    const waitForStep = vi
      .fn()
      .mockResolvedValue(document.createElement("div"));

    renderGrid();
    await searchHandlers()?.onNext?.({ waitForStep });

    expect(waitForStep).toHaveBeenCalledWith("frameworks");
  });

  it("skips the wait when the persisted filter leaves no card to anchor to", async () => {
    // The filter survives reloads, so the tour can start on a grid that renders
    // the empty state instead of a card — and waiting for an anchor that never
    // mounts would hang it there.
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });
    const waitForStep = vi
      .fn()
      .mockResolvedValue(document.createElement("div"));

    renderGrid({
      catalogEntries: [
        catalogEntry("cis_1.4_aws", false),
        catalogEntry("gdpr_aws", false),
        catalogEntry("iso27001_aws", false),
      ],
      providerType: "aws",
    });
    await searchHandlers()?.onNext?.({ waitForStep });

    expect(waitForStep).not.toHaveBeenCalled();
  });
});
