import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ScansPageShell } from "./scans-page-shell";

const { pushMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
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
  useSearchParams: () => new URLSearchParams(),
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

  it("uses a generic type filter label in Cloud", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(screen.getByRole("combobox", { name: /all types/i })).toBeVisible();
  });
});
