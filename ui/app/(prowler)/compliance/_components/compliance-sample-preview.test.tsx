import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE } from "@/lib/sample-preview/sample-overview";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";

import { ComplianceSamplePreview } from "./compliance-sample-preview";

const { fetchMock, getScanMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getScanMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/compliance",
}));
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));
vi.mock("@/actions/scans", () => ({ getScan: getScanMock }));

const STATE = {
  active: true as const,
  stage: SAMPLE_PREVIEW_STAGE.NO_PROVIDER,
  runningScan: null,
};

describe("ComplianceSamplePreview", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
  });

  it("renders the Overview watchlist frameworks as inert cards without fetching", () => {
    render(<ComplianceSamplePreview state={STATE} />);

    expect(
      screen.getByText("You are exploring sample data"),
    ).toBeInTheDocument();

    const cards = screen.getAllByRole("button", {
      name: /compliance details$/,
    });
    expect(cards).toHaveLength(
      SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data.length,
    );

    const cis = SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data.find(
      (item) => item.attributes.compliance_id === "cis_5.0_aws",
    )!.attributes;
    expect(
      screen.getByRole("button", { name: "Open CIS - 5.0 compliance details" }),
    ).toHaveTextContent(
      `${cis.requirements_passed} / ${cis.total_requirements}`,
    );

    expect(cards[0].closest("[inert]")).not.toBeNull();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(getScanMock).not.toHaveBeenCalled();
  });
});
