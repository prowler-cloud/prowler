import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ProviderBreakdownEntry } from "../_types";
import { CrossProviderFrameworkCard } from "./cross-provider-framework-card";

const { pushMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  useSearchParams: () => new URLSearchParams("filter[provider_type__in]=aws"),
}));

const breakdown: ProviderBreakdownEntry[] = [
  {
    provider: "aws",
    pass: 10,
    fail: 5,
    manual: 2,
    total: 17,
    score: 67,
    unscanned: false,
  },
  {
    provider: "gcp",
    pass: 0,
    fail: 0,
    manual: 0,
    total: 0,
    score: 0,
    unscanned: true,
  },
];

const baseProps = {
  complianceId: "csa_ccm_4.0",
  title: "CSA-CCM",
  version: "4.0",
  description: "CSA Cloud Controls Matrix",
  requirementsPassed: 10,
  requirementsFailed: 5,
  requirementsManual: 2,
  totalRequirements: 17,
  providerBreakdown: breakdown,
};

describe("CrossProviderFrameworkCard", () => {
  beforeEach(() => {
    pushMock.mockClear();
  });

  it("shows the framework identity and passing summary", () => {
    render(<CrossProviderFrameworkCard {...baseProps} />);

    expect(screen.getByText("CSA CCM - 4.0")).toBeInTheDocument();
    expect(screen.getByText("10 / 17")).toBeInTheDocument();
    // Same formula as the per-scan ComplianceCard: floor(passed / total).
    expect(screen.getByText("58%")).toBeInTheDocument();
  });

  it("marks compatible-but-unscanned providers as dimmed", () => {
    render(<CrossProviderFrameworkCard {...baseProps} />);

    expect(screen.getByTestId("provider-chip-aws")).not.toHaveAttribute(
      "data-unscanned",
      "true",
    );
    expect(screen.getByTestId("provider-chip-gcp")).toHaveAttribute(
      "data-unscanned",
      "true",
    );
  });

  it("navigates to the cross-provider detail forwarding active filters", async () => {
    const user = userEvent.setup();
    render(<CrossProviderFrameworkCard {...baseProps} />);

    await user.click(screen.getByRole("button", { name: /csa ccm/i }));

    expect(pushMock).toHaveBeenCalledTimes(1);
    const href = pushMock.mock.calls[0][0] as string;
    const url = new URL(href, "https://localhost");
    expect(url.pathname).toBe("/compliance/CSA-CCM");
    expect(url.searchParams.get("mode")).toBe("cross-provider");
    expect(url.searchParams.get("complianceId")).toBe("csa_ccm_4.0");
    expect(url.searchParams.get("version")).toBe("4.0");
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws");
  });
});
