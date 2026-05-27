import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useScansStore } from "@/store";

import { ScansPageShell } from "./scans-page-shell";

const { pushMock, replaceMock, searchParamsValue } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  replaceMock: vi.fn(),
  searchParamsValue: { current: "" },
}));

const { scansFilterBarSpy } = vi.hoisted(() => ({
  scansFilterBarSpy: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/scans",
  useRouter: () => ({
    push: pushMock,
    replace: replaceMock,
  }),
  useSearchParams: () => new URLSearchParams(searchParamsValue.current),
}));

vi.mock("./scans-filter-bar", () => ({
  ScansFilterBar: (props: {
    showStatusFilter: boolean;
    onScheduleTypeChange: (value: string) => void;
    onScanStatusChange: (value: string) => void;
  }) => {
    scansFilterBarSpy(props);
    return (
      <>
        <div>Shared scan filters</div>
        <select
          aria-label="All Types"
          onChange={(event) => props.onScheduleTypeChange(event.target.value)}
        >
          <option value="all">All Types</option>
        </select>
        {props.showStatusFilter && (
          <select
            aria-label="All Statuses"
            onChange={(event) => props.onScanStatusChange(event.target.value)}
          >
            <option value="all">All Statuses</option>
          </select>
        )}
      </>
    );
  },
}));

vi.mock("./launch-scan-modal", () => ({
  LaunchScanModal: ({
    open,
    onOpenChange,
  }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
  }) =>
    open ? (
      <div role="dialog">
        Launch scan
        <button type="button" onClick={() => onOpenChange(false)}>
          Close
        </button>
      </div>
    ) : null,
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
    useScansStore.getState().closeLaunchScanModal();
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

  it("uses the shared scan filter bar for scan filters", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(screen.getByText("Shared scan filters")).toBeInTheDocument();
    expect(scansFilterBarSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        providers,
        scheduleType: "all",
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
      screen.getByRole("group", { name: /scan filters and actions/i }),
    ).toContainElement(screen.getByRole("button", { name: /launch scan/i }));
    expect(
      screen.getByRole("group", { name: /scan filters and actions/i }),
    ).not.toContainElement(
      screen.getByRole("link", { name: /configure mutelist/i }),
    );
    expect(screen.getByRole("group", { name: /scan tabs/i })).toContainElement(
      screen.getByRole("link", { name: /configure mutelist/i }),
    );
  });

  it("opens the launch scan modal from the URL", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    searchParamsValue.current = "launchScan=true";

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(screen.getByRole("dialog")).toHaveTextContent(/launch scan/i);
  });

  it("strips the launchScan URL param when closing the URL-opened modal", async () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    searchParamsValue.current = "tab=completed&launchScan=true";
    const user = userEvent.setup();

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    await user.click(screen.getByRole("button", { name: /close/i }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(replaceMock).toHaveBeenCalledWith(
      "/scans?tab=completed",
      expect.objectContaining({ scroll: false }),
    );
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("opens and closes the launch scan modal from client state without navigation", async () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    const user = userEvent.setup();
    useScansStore.getState().openLaunchScanModal();

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    expect(screen.getByRole("dialog")).toHaveTextContent(/launch scan/i);

    await user.click(screen.getByRole("button", { name: /close/i }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(pushMock).not.toHaveBeenCalled();
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
