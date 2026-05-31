import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { AccountsSelector } from "./accounts-selector";

const multiSelectContentSpy = vi.fn();
const multiSelectSpy = vi.fn();

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
  OktaProviderBadge: () => <span>Okta</span>,
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({
    children,
    open,
    onOpenChange,
  }: {
    children: React.ReactNode;
    open?: boolean;
    onOpenChange?: (open: boolean) => void;
  }) => {
    multiSelectSpy({ open });
    return (
      <div data-open={String(open)}>
        <button type="button" onClick={() => onOpenChange?.(true)}>
          Open selector
        </button>
        {children}
      </div>
    );
  },
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
    disabled,
    value,
    keywords,
    onSelect,
  }: {
    children: React.ReactNode;
    disabled?: boolean;
    value: string;
    keywords?: string[];
    onSelect?: (value: string) => void;
  }) => (
    <button
      type="button"
      data-value={value}
      data-keywords={keywords?.join("|")}
      data-disabled={disabled ? "true" : "false"}
      onClick={() => onSelect?.(value)}
    >
      {children}
    </button>
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
      placeholder: "Search Providers...",
      emptyMessage: "No Providers found.",
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

  it("can use provider UID values for pages whose API filters by provider_uid__in", () => {
    render(
      <AccountsSelector providers={providers} filterKey="provider_uid__in" />,
    );

    expect(
      screen.getByText("Production AWS").closest("[data-value]"),
    ).toHaveAttribute("data-value", "123456789012");
  });

  it("disables select all when every account is already shown", () => {
    render(<AccountsSelector providers={providers} />);

    expect(
      screen.getByRole("option", { name: /select all Providers/i }),
    ).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("All selected")).toBeInTheDocument();
  });

  it("marks configured account values as disabled", () => {
    render(
      <AccountsSelector
        providers={providers}
        disabledValues={["provider-1"]}
      />,
    );

    expect(
      screen.getByText("Production AWS").closest("[data-value]"),
    ).toHaveAttribute("data-disabled", "true");
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("can close the dropdown after selecting a launch-scan provider", async () => {
    const user = userEvent.setup();

    render(
      <AccountsSelector
        providers={providers}
        closeOnSelect
        onBatchChange={vi.fn()}
        selectedValues={[]}
      />,
    );

    await user.click(screen.getByRole("button", { name: /open selector/i }));
    expect(multiSelectSpy).toHaveBeenLastCalledWith({ open: true });

    await user.click(screen.getByRole("button", { name: /production aws/i }));

    expect(multiSelectSpy).toHaveBeenLastCalledWith({ open: false });
  });
});
