import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ProviderTypeSelector } from "./provider-type-selector";

const multiSelectContentSpy = vi.fn();

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({
    navigateWithParams: vi.fn(),
  }),
}));

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
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({
    children,
    search,
  }: {
    children: React.ReactNode;
    search?: unknown;
  }) => {
    multiSelectContentSpy(search);
    return <div>{children}</div>;
  },
  MultiSelectItem: ({
    children,
    value,
    keywords,
  }: {
    children: React.ReactNode;
    value: string;
    keywords?: string[];
  }) => (
    <div data-value={value} data-keywords={keywords?.join("|")}>
      {children}
    </div>
  ),
}));

const providers = [
  {
    id: "provider-1",
    type: "providers" as const,
    attributes: {
      provider: "aws" as const,
      uid: "123456789012",
      alias: "Production AWS",
      status: "completed" as const,
      resources: 0,
      connection: {
        connected: true,
        last_checked_at: "2026-04-13T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-04-13T00:00:00Z",
      updated_at: "2026-04-13T00:00:00Z",
      created_by: {
        object: "user",
        id: "user-1",
      },
    },
    relationships: {
      secret: {
        data: null,
      },
      provider_groups: {
        meta: {
          count: 0,
        },
        data: [],
      },
    },
  },
];

describe("ProviderTypeSelector", () => {
  it("passes searchable dropdown defaults to MultiSelectContent", () => {
    render(<ProviderTypeSelector providers={providers} />);

    expect(multiSelectContentSpy).toHaveBeenCalledWith({
      placeholder: "Search providers...",
      emptyMessage: "No providers found.",
    });
    expect(screen.getByText("Amazon Web Services")).toBeInTheDocument();
  });

  it("allows disabling search explicitly", () => {
    render(<ProviderTypeSelector providers={providers} search={false} />);

    expect(multiSelectContentSpy).toHaveBeenLastCalledWith(false);
  });

  it("passes provider label as search keywords", () => {
    render(<ProviderTypeSelector providers={providers} />);

    expect(
      screen.getByText("Amazon Web Services").closest("[data-value]"),
    ).toHaveAttribute(
      "data-keywords",
      expect.stringContaining("Amazon Web Services"),
    );
  });
});
