import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SAMPLE_FAILED_CHECKS } from "@/lib/sample-preview/sample-dataset";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";

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
  });

  it("renders every failed sample check in an inert table without fetching", () => {
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
    expect(table.closest("[inert]")).not.toBeNull();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(getScanMock).not.toHaveBeenCalled();
    expect(resolveFindingIdsMock).not.toHaveBeenCalled();
  });
});
