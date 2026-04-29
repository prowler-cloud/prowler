import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AccountsSelector } from "./accounts-selector";

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
  CloudflareProviderBadge: () => <span>Cloudflare</span>,
  GitHubProviderBadge: () => <span>GitHub</span>,
  GoogleWorkspaceProviderBadge: () => <span>Google Workspace</span>,
  IacProviderBadge: () => <span>IaC</span>,
  ImageProviderBadge: () => <span>Image</span>,
  KS8ProviderBadge: () => <span>Kubernetes</span>,
  M365ProviderBadge: () => <span>M365</span>,
  MongoDBAtlasProviderBadge: () => <span>MongoDB Atlas</span>,
  OpenStackProviderBadge: () => <span>OpenStack</span>,
  OracleCloudProviderBadge: () => <span>Oracle Cloud</span>,
  AlibabaCloudProviderBadge: () => <span>Alibaba Cloud</span>,
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

describe("AccountsSelector", () => {
  it("passes searchable dropdown defaults to MultiSelectContent", () => {
    render(<AccountsSelector providers={providers} />);

    expect(multiSelectContentSpy).toHaveBeenCalledWith({
      placeholder: "Search accounts...",
      emptyMessage: "No accounts found.",
    });
    expect(screen.getByText("Production AWS")).toBeInTheDocument();
  });

  it("allows disabling search explicitly", () => {
    render(<AccountsSelector providers={providers} search={false} />);

    expect(multiSelectContentSpy).toHaveBeenLastCalledWith(false);
  });

  it("passes visible account labels as search keywords instead of only the internal id", () => {
    render(<AccountsSelector providers={providers} />);

    expect(
      screen.getByText("Production AWS").closest("[data-value]"),
    ).toHaveAttribute(
      "data-keywords",
      expect.stringContaining("Production AWS"),
    );
    expect(
      screen.getByText("Production AWS").closest("[data-value]"),
    ).toHaveAttribute("data-keywords", expect.stringContaining("123456789012"));
  });
});
