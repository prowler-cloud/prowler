import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ProviderType } from "@/types/providers";

import { ProviderIconCell } from "./provider-icon-cell";

// Render the lazy provider badges as plain text so we can assert on them. The
// real PROVIDER_TYPE_DATA map (and its `in` guard) is exercised on purpose.
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

describe("ProviderIconCell", () => {
  it("renders the shared provider-type icon for a known provider", async () => {
    render(<ProviderIconCell provider="aws" />);

    expect(await screen.findByText("AWS")).toBeInTheDocument();
  });

  it("renders a '?' placeholder for a provider type missing from the map", () => {
    render(
      <ProviderIconCell
        provider={"future-provider" as unknown as ProviderType}
      />,
    );

    expect(screen.getByText("?")).toBeInTheDocument();
  });
});
