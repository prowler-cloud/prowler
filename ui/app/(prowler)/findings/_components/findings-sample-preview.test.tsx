import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SAMPLE_FAILED_CHECKS } from "@/lib/sample-preview/sample-dataset";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";
import { SAMPLE_FINDINGS } from "@/lib/sample-preview/sample-records";

import { FindingsSamplePreview } from "./findings-sample-preview";

const {
  fetchMock,
  getScanMock,
  refreshMock,
  resolveFindingIdsMock,
  searchParams,
} = vi.hoisted(() => ({
  // One instance, like Next's hook: a new one per render loops the filter bar.
  searchParams: new URLSearchParams(),
  fetchMock: vi.fn(),
  getScanMock: vi.fn(),
  refreshMock: vi.fn(),
  resolveFindingIdsMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: refreshMock, replace: vi.fn() }),
  useSearchParams: () => searchParams,
  usePathname: () => "/findings",
}));
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));
vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: null, status: "unauthenticated" }),
}));
vi.mock("@/actions/scans", () => ({ getScan: getScanMock }));
vi.mock("@/actions/findings/findings-by-resource", () => ({
  resolveFindingIdsByVisibleGroupResources: resolveFindingIdsMock,
}));

const STATE = {
  active: true as const,
  stage: SAMPLE_PREVIEW_STAGE.NO_SCAN,
  runningScan: null,
};

describe("FindingsSamplePreview", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    // jsdom has no scrollIntoView; the filter bar's command lists call it.
    Element.prototype.scrollIntoView = vi.fn();
    // jsdom has no IntersectionObserver; the drill-down's infinite scroll needs one.
    vi.stubGlobal(
      "IntersectionObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("refreshes itself while the first scan runs, so early findings can take over", () => {
    // Given
    vi.useFakeTimers();
    render(
      <FindingsSamplePreview
        state={{
          active: true,
          stage: SAMPLE_PREVIEW_STAGE.SCAN_RUNNING,
          runningScan: { id: "scan-1", progress: 38 },
        }}
      />,
    );

    // When
    vi.advanceTimersByTime(5_000);

    // Then
    expect(refreshMock).toHaveBeenCalled();
  });

  it("does not refresh itself when no scan is running", () => {
    // Given
    vi.useFakeTimers();
    render(<FindingsSamplePreview state={STATE} />);

    // When
    vi.advanceTimersByTime(30_000);

    // Then
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("renders every failed sample check without fetching", () => {
    const { container } = render(<FindingsSamplePreview state={STATE} />);

    expect(
      screen.getByText("You are exploring sample data"),
    ).toBeInTheDocument();

    const publicBucket = SAMPLE_FAILED_CHECKS.find(
      (check) => check.checkId === "s3_bucket_public_access",
    )!;
    const row = screen
      .getByText(publicBucket.title)
      .closest("tr") as HTMLElement;
    // Impacted resources: failed of failed + passed.
    expect(
      within(row).getByText(String(publicBucket.failed)),
    ).toBeInTheDocument();
    expect(
      within(row).getByText(String(publicBucket.failed + publicBucket.passed)),
    ).toBeInTheDocument();

    const table = container.querySelector("table") as HTMLElement;
    expect(within(table).getAllByRole("row", { hidden: true })).toHaveLength(
      SAMPLE_FAILED_CHECKS.length + 1,
    );
    expect(table.closest("[inert]")).toBeNull();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(getScanMock).not.toHaveBeenCalled();
    expect(resolveFindingIdsMock).not.toHaveBeenCalled();
  });

  it("expands a sample group into its resources from the sample records", async () => {
    const user = userEvent.setup();
    render(<FindingsSamplePreview state={STATE} />);

    await user.click(
      screen.getByText("Ensure S3 buckets are not publicly accessible"),
    );

    expect(
      await screen.findByText("acme-customer-exports"),
    ).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("expands a PASS group into passing resources only", async () => {
    const user = userEvent.setup();
    render(
      <FindingsSamplePreview
        state={STATE}
        searchParams={{ "filter[status__in]": "PASS" }}
      />,
    );
    await user.click(
      screen.getByText("Ensure S3 buckets are not publicly accessible"),
    );
    const passing = SAMPLE_FINDINGS.find(
      (finding) =>
        finding.check.checkId === "s3_bucket_public_access" &&
        finding.status === "PASS",
    )!;
    expect(await screen.findByText(passing.resource.name)).toBeInTheDocument();
    expect(screen.queryByText("acme-customer-exports")).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("applies the severity an Overview link carried", () => {
    render(
      <FindingsSamplePreview
        state={STATE}
        searchParams={{
          "filter[severity__in]": "critical",
          "filter[status__in]": "FAIL",
        }}
      />,
    );

    const critical = SAMPLE_FAILED_CHECKS.filter(
      (check) => check.severity === "critical",
    );
    const high = SAMPLE_FAILED_CHECKS.find(
      (check) => check.severity === "high",
    )!;
    for (const check of critical) {
      expect(screen.getByText(check.title)).toBeInTheDocument();
    }
    expect(screen.queryByText(high.title)).not.toBeInTheDocument();
  });

  it("offers the real filter bar without fetching its options", () => {
    render(<FindingsSamplePreview state={STATE} />);

    expect(
      screen.getByRole("combobox", { name: /^Filter by Provider\./ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "More Filters" }),
    ).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
