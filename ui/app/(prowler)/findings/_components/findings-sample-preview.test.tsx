import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SAMPLE_FAILED_CHECKS } from "@/lib/sample-preview/sample-dataset";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";
import { SAMPLE_FINDINGS } from "@/lib/sample-preview/sample-records";

import { FindingsSamplePreview } from "./findings-sample-preview";

const { fetchMock, getScanMock, resolveFindingIdsMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getScanMock: vi.fn(),
  resolveFindingIdsMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
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
    vi.stubGlobal("fetch", fetchMock);
    // jsdom has no IntersectionObserver; the drill-down's infinite scroll needs one.
    vi.stubGlobal(
      "IntersectionObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
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

  it("applies the severity an Overview link carried, with a way back to all", () => {
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
    expect(screen.getByRole("link", { name: "Show all" })).toHaveAttribute(
      "href",
      "/findings",
    );
  });
});
