import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ProviderTypeIcon, ProviderTypeIconStack } from "./provider-type-icon";

// Render the lazy provider badges as plain text so we can assert on them.
vi.mock("@/components/icons/providers-badge", () => ({
  AWSProviderBadge: () => <span>AWS</span>,
  AzureProviderBadge: () => <span>Azure</span>,
  GCPProviderBadge: () => <span>GCP</span>,
  KS8ProviderBadge: () => <span>Kubernetes</span>,
  M365ProviderBadge: () => <span>M365</span>,
  GitHubProviderBadge: () => <span>GitHub</span>,
  GoogleWorkspaceProviderBadge: () => <span>Google Workspace</span>,
  IacProviderBadge: () => <span>IaC</span>,
  ImageProviderBadge: () => <span>Image</span>,
  OracleCloudProviderBadge: () => <span>Oracle Cloud</span>,
  MongoDBAtlasProviderBadge: () => <span>MongoDB Atlas</span>,
  AlibabaCloudProviderBadge: () => <span>Alibaba Cloud</span>,
  CloudflareProviderBadge: () => <span>Cloudflare</span>,
  OpenStackProviderBadge: () => <span>OpenStack</span>,
  VercelProviderBadge: () => <span>Vercel</span>,
  OktaProviderBadge: () => <span>Okta</span>,
}));

// Render the tooltip pieces inline so the hover content is queryable in jsdom.
vi.mock("@/components/shadcn", () => ({
  Badge: ({ children }: { children: React.ReactNode }) => (
    <span data-testid="badge">{children}</span>
  ),
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TooltipTrigger: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
  TooltipContent: ({ children }: { children: React.ReactNode }) => (
    <span data-testid="tooltip">{children}</span>
  ),
  TooltipProvider: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));

vi.mock("@radix-ui/react-tooltip", () => ({
  Portal: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe("ProviderTypeIcon", () => {
  it("renders the badge for the given provider type", async () => {
    render(<ProviderTypeIcon type="aws" />);

    expect(await screen.findByText("AWS")).toBeInTheDocument();
  });
});

describe("ProviderTypeIconStack", () => {
  it("renders one icon per item without deduping by type", async () => {
    render(
      <ProviderTypeIconStack
        items={[
          { key: "a", type: "aws", tooltip: "111" },
          { key: "b", type: "aws", tooltip: "222" },
        ]}
      />,
    );

    // Two AWS accounts -> two AWS icons (no dedupe).
    expect(await screen.findAllByText("AWS")).toHaveLength(2);
  });

  it("shows each item's tooltip text on the icon", async () => {
    render(
      <ProviderTypeIconStack
        items={[{ key: "a", type: "aws", tooltip: "account-uid-123" }]}
      />,
    );

    expect(await screen.findByTestId("tooltip")).toHaveTextContent(
      "account-uid-123",
    );
  });

  it("collapses items beyond `max` into a +N badge", async () => {
    render(
      <ProviderTypeIconStack
        max={3}
        items={[
          { key: "a", type: "aws", tooltip: "1" },
          { key: "b", type: "azure", tooltip: "2" },
          { key: "c", type: "gcp", tooltip: "3" },
          { key: "d", type: "github", tooltip: "4" },
          { key: "e", type: "okta", tooltip: "5" },
        ]}
      />,
    );

    expect(await screen.findByTestId("badge")).toHaveTextContent("+2");
    // First icon is shown; items sliced beyond `max` never reach the DOM.
    expect(await screen.findByText("AWS")).toBeInTheDocument();
    expect(screen.queryByText("Okta")).not.toBeInTheDocument();
  });
});
