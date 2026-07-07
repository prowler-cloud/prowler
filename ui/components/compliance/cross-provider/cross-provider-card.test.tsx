import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getProwlerHubComplianceUrl } from "@/lib/compliance/prowler-hub";

import { CrossProviderCard } from "./cross-provider-card";

const { pushMock, searchParams } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  searchParams: new URLSearchParams(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  useSearchParams: () => searchParams,
}));

// ``next/image`` needs the App Router runtime; a stub is enough to assert the
// card's own wiring (the logo image itself isn't queried).
vi.mock("next/image", () => ({
  default: ({ alt }: { alt?: string }) => <span aria-label={alt} />,
}));

const baseProps = {
  complianceId: "cis_controls_8.1",
  title: "CIS-Controls",
  version: "8.1",
  description: "A universal framework",
  requirementsPassed: 5,
  totalRequirements: 10,
  contributingProviders: ["aws"],
  compatibleProviders: ["aws", "azure"],
};

describe("CrossProviderCard", () => {
  beforeEach(() => {
    pushMock.mockClear();
    searchParams.forEach((_, key) => searchParams.delete(key));
  });

  it("navigates to the universal detail page in cross-provider mode on click", () => {
    render(<CrossProviderCard {...baseProps} />);

    // The whole card is the click target — drill in from its title.
    fireEvent.click(screen.getByText("CIS Controls - 8.1"));

    expect(pushMock).toHaveBeenCalledTimes(1);
    const target = pushMock.mock.calls[0][0] as string;
    expect(target).toContain("/compliance/CIS-Controls");
    expect(target).toContain("mode=cross-provider");
    expect(target).toContain("complianceId=cis_controls_8.1");
  });

  it("is keyboard-activatable via Enter", () => {
    render(<CrossProviderCard {...baseProps} />);

    const card = screen.getAllByRole("button")[0];
    fireEvent.keyDown(card, { key: "Enter" });

    expect(pushMock).toHaveBeenCalledTimes(1);
  });

  it("preserves provider_type and region filters when drilling in", () => {
    searchParams.set("filter[region__in]", "eu-west-1");
    searchParams.set("filter[provider_type__in]", "aws");

    render(<CrossProviderCard {...baseProps} />);
    fireEvent.click(screen.getByText("CIS Controls - 8.1"));

    const target = pushMock.mock.calls[0][0] as string;
    expect(target).toContain("filter%5Bregion__in%5D=eu-west-1");
    expect(target).toContain("filter%5Bprovider_type__in%5D=aws");
  });

  it("renders one chip per provider, marking contributing vs. not-yet-scanned", () => {
    render(<CrossProviderCard {...baseProps} />);

    // aws contributed a scan; azure is compatible but has no scan yet.
    expect(screen.getByLabelText(/scan available/)).toBeInTheDocument();
    expect(screen.getByLabelText(/no scan yet/)).toBeInTheDocument();
  });

  it("links the info button to the framework's Prowler Hub page in a new tab", () => {
    render(<CrossProviderCard {...baseProps} />);

    const hubLink = screen.getByRole("link", { name: /prowler hub/i });
    expect(hubLink).toHaveAttribute(
      "href",
      getProwlerHubComplianceUrl(baseProps.complianceId),
    );
    expect(hubLink).toHaveAttribute("target", "_blank");
  });

  it("does not trigger the card's drill-down when the info button is clicked", () => {
    render(<CrossProviderCard {...baseProps} />);

    fireEvent.click(screen.getByRole("link", { name: /prowler hub/i }));

    expect(pushMock).not.toHaveBeenCalled();
  });
});
