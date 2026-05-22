import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ScansPageShell } from "./scans-page-shell";

const { pushMock, searchParamsValue } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  searchParamsValue: { current: "" },
}));

const { accountsSelectorSpy, providerTypeSelectorSpy } = vi.hoisted(() => ({
  accountsSelectorSpy: vi.fn(),
  providerTypeSelectorSpy: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/scans",
  useRouter: () => ({
    push: pushMock,
  }),
  useSearchParams: () => new URLSearchParams(searchParamsValue.current),
}));

vi.mock("@/app/(prowler)/_overview/_components/accounts-selector", () => ({
  AccountsSelector: (props: unknown) => {
    accountsSelectorSpy(props);
    return <div>Shared accounts selector</div>;
  },
}));

vi.mock("@/app/(prowler)/_overview/_components/provider-type-selector", () => ({
  ProviderTypeSelector: (props: unknown) => {
    providerTypeSelectorSpy(props);
    return <div>Shared provider type selector</div>;
  },
}));

vi.mock("./launch-scan-modal", () => ({
  LaunchScanModal: ({ open }: { open: boolean }) =>
    open ? <div role="dialog">Launch scan</div> : null,
}));

vi.mock("@/components/providers/muted-findings-config-button", () => ({
  MutedFindingsConfigButton: () => <a href="/mutelist">Configure Mutelist</a>,
}));

const providers = [
  {
    id: "provider-1",
    type: "providers" as const,
    attributes: {
      provider: "aws" as const,
      uid: "123456789012",
      alias: "Production",
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

describe("ScansPageShell", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.clearAllMocks();
    searchParamsValue.current = "";
  });

  it("does not render an imported findings tab", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(
      screen.queryByRole("tab", { name: /imported findings/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /import findings/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("uses the shared provider selectors from Findings for scan filters", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(
      screen.getByText("Shared provider type selector"),
    ).toBeInTheDocument();
    expect(screen.getByText("Shared accounts selector")).toBeInTheDocument();
    expect(providerTypeSelectorSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        providers,
        selectedValues: [],
      }),
    );
    expect(accountsSelectorSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        providers,
        filterKey: "provider_uid__in",
        selectedValues: [],
        selectedProviderTypes: [],
      }),
    );
  });

  it("clears the active sort when switching tabs", async () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    searchParamsValue.current = "tab=active&sort=trigger";
    const user = userEvent.setup();

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    await user.click(screen.getByRole("tab", { name: /completed/i }));

    expect(pushMock).toHaveBeenCalled();
    const calledUrl = pushMock.mock.calls.at(-1)?.[0] as string;
    expect(calledUrl).toContain("tab=completed");
    expect(calledUrl).not.toContain("sort=");
  });

  it("uses a generic type filter label in Cloud", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(screen.getByRole("combobox", { name: /all types/i })).toBeVisible();
  });

  it("keeps launch scan with filters and mutelist with tabs", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(
      screen.getByRole("group", { name: /scan filters/i }),
    ).toContainElement(screen.getByRole("button", { name: /launch scan/i }));
    expect(
      screen.getByRole("group", { name: /scan filters/i }),
    ).not.toContainElement(
      screen.getByRole("link", { name: /configure mutelist/i }),
    );
    expect(screen.getByRole("group", { name: /scan tabs/i })).toContainElement(
      screen.getByRole("link", { name: /configure mutelist/i }),
    );
  });

  it("shows the status filter only on the completed tab", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    searchParamsValue.current = "tab=completed";

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(
      screen.getByRole("combobox", { name: /all statuses/i }),
    ).toBeVisible();
  });

  it("hides the status filter outside of the completed tab", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(
      screen.queryByRole("combobox", { name: /all statuses/i }),
    ).not.toBeInTheDocument();
  });

  it("clears status filter when switching scan tabs", async () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    searchParamsValue.current = "tab=completed&filter%5Bstate__in%5D=failed";
    const user = userEvent.setup();

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    await user.click(screen.getByRole("tab", { name: /active/i }));

    const calledUrl = pushMock.mock.calls.at(-1)?.[0] as string;
    expect(calledUrl).toContain("tab=active");
    expect(calledUrl).not.toContain("filter%5Bstate__in%5D");
  });
});
