import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import { WATCHLIST_SCOPE } from "@/types/compliance-watchlist";

import { WatchlistControls } from "./watchlist-controls";

vi.mock("./watchlist-filter-toggle", () => ({
  WatchlistFilterToggle: () => <div data-testid="filter-toggle" />,
}));

vi.mock("./watchlist-multi-select", () => ({
  WatchlistMultiSelect: () => <div data-testid="multi-select" />,
}));

const ENTRY: ComplianceCatalogEntry = {
  id: "aws:cis_1.4_aws",
  scope: WATCHLIST_SCOPE.PROVIDER,
  providerTypes: ["aws"],
  complianceId: "cis_1.4_aws",
  providerType: "aws",
  framework: "CIS",
  name: "CIS",
  version: "1.4",
  description: "",
  totalRequirements: 10,
  requirementsPassed: 5,
  requirementsFailed: 5,
  requirementsManual: 0,
  score: 50,
  hasData: true,
  inWatchlist: false,
  watchlistEntryId: null,
};

describe("WatchlistControls", () => {
  it("renders nothing without a catalog, keeping the feature Cloud-only", () => {
    const { container } = render(
      <WatchlistControls entries={[]} canManageWatchlist />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("offers both the filter and the editor to a curator", () => {
    render(<WatchlistControls entries={[ENTRY]} canManageWatchlist />);

    expect(screen.getByTestId("filter-toggle")).toBeInTheDocument();
    expect(screen.getByTestId("multi-select")).toBeInTheDocument();
  });

  it("keeps the filter but drops the editor without MANAGE_SCANS", () => {
    // Rendering the editor disabled would be worse: the write 403s, so the
    // affordance is removed rather than teased.
    render(<WatchlistControls entries={[ENTRY]} canManageWatchlist={false} />);

    expect(screen.getByTestId("filter-toggle")).toBeInTheDocument();
    expect(screen.queryByTestId("multi-select")).not.toBeInTheDocument();
  });
});
