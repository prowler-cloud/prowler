import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProviderBadgeIcon } from "./provider-badge-icon";

describe("ProviderBadgeIcon", () => {
  it("renders the registered badge component for a known provider", () => {
    const { container } = render(
      <ProviderBadgeIcon providerKey="aws" size={16} />,
    );

    // The real AWS badge is an <svg>; the initials fallback never mounts.
    expect(container.querySelector("svg")).toBeInTheDocument();
    expect(screen.queryByText("AW")).not.toBeInTheDocument();
  });

  it("falls back to an initials chip for a provider with a label but no icon", () => {
    // ``linode`` is declared by the SDK's cross-provider CIS Controls
    // template but has no dedicated badge component yet — the exact gap
    // ``ProviderBadgeIcon`` exists to paper over.
    render(<ProviderBadgeIcon providerKey="linode" size={16} />);

    expect(screen.getByText("LI")).toBeInTheDocument();
  });

  it("hides the fallback chip from assistive tech", () => {
    render(<ProviderBadgeIcon providerKey="linode" size={16} />);

    expect(screen.getByText("LI")).toHaveAttribute("aria-hidden", "true");
  });

  it("derives fallback initials from the uppercased key when the provider is entirely unknown", () => {
    // Regression guard: an unrecognized key must not throw, and should
    // still render *something* identifiable rather than a blank square.
    render(<ProviderBadgeIcon providerKey="zzznope" size={16} />);

    expect(screen.getByText("ZZ")).toBeInTheDocument();
  });

  it("sizes the fallback chip from the size prop", () => {
    render(<ProviderBadgeIcon providerKey="linode" size={20} />);

    expect(screen.getByText("LI")).toHaveStyle({
      width: "20px",
      height: "20px",
    });
  });
});
