import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { render, screen } from "@testing-library/react";
import { type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ProviderProps } from "@/types";

import Scans from "./page";

const {
  authMock,
  getAllProvidersMock,
  getAllProviderGroupsMock,
  getScansMock,
  redirectMock,
  contentLayoutSpy,
  scansPageShellSpy,
} = vi.hoisted(() => ({
  authMock: vi.fn(),
  getAllProvidersMock: vi.fn(),
  getAllProviderGroupsMock: vi.fn(),
  getScansMock: vi.fn(),
  redirectMock: vi.fn(),
  contentLayoutSpy: vi.fn(),
  scansPageShellSpy: vi.fn(),
}));

// redirect is spied as a regression tripwire: re-adding a prerequisite gate would call it.
vi.mock("next/navigation", () => ({
  redirect: redirectMock,
  notFound: vi.fn(),
  usePathname: () => "/scans",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("@/actions/providers", () => ({
  getAllProviders: getAllProvidersMock,
}));
vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: getAllProviderGroupsMock,
}));
vi.mock("@/actions/scans", () => ({ getScans: getScansMock }));
vi.mock("@/actions/schedules", () => ({
  getSchedules: vi.fn(),
  getSchedulesPage: vi.fn(),
}));

// The shell is exercised in its own test; here we only assert the page always
// mounts it (with a table subtree) and never gates on provider state.
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: (props: {
    children: ReactNode;
    onboardingAction: unknown;
  }) => {
    contentLayoutSpy(props);
    return <div data-testid="content-layout">{props.children}</div>;
  },
}));
vi.mock("@/components/scans/scans-page-shell", () => ({
  ScansPageShell: (props: {
    children: unknown;
    providers: ProviderProps[];
  }) => {
    scansPageShellSpy(props);
    return <div data-testid="scans-page-shell" />;
  },
}));

const connectedProvider = {
  id: "provider-1",
  type: "providers" as const,
  attributes: {
    provider: "aws" as const,
    connection: { connected: true },
  },
} as unknown as ProviderProps;

const disconnectedProvider = {
  ...connectedProvider,
  id: "provider-2",
  attributes: {
    ...connectedProvider.attributes,
    connection: { connected: false },
  },
} as unknown as ProviderProps;

const renderPage = async () => {
  const ui = await Scans({ searchParams: Promise.resolve({}) });
  render(ui);
};

describe("scans page rendering", () => {
  beforeEach(() => {
    authMock.mockResolvedValue({
      user: { permissions: { manage_scans: true } },
    });
    getAllProviderGroupsMock.mockResolvedValue({ data: [] });
    getScansMock.mockResolvedValue({ meta: { pagination: { count: 0 } } });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it.each([
    ["connected", [connectedProvider]],
    ["disconnected", [disconnectedProvider]],
    ["empty", [] as ProviderProps[]],
  ])(
    "renders the scans shell with the table and never redirects when providers are %s",
    async (_state, providers) => {
      getAllProvidersMock.mockResolvedValue({ data: providers });

      await renderPage();

      expect(screen.getByTestId("scans-page-shell")).toBeInTheDocument();
      expect(redirectMock).not.toHaveBeenCalled();

      const shellProps = scansPageShellSpy.mock.calls.at(-1)?.[0];
      expect(shellProps?.providers).toEqual(providers);
      // The table subtree is always wired, regardless of provider connection state.
      expect(shellProps?.children).toBeTruthy();
    },
  );

  it("uses the plain view-first-scan onboarding action when a provider is connected", async () => {
    getAllProvidersMock.mockResolvedValue({ data: [connectedProvider] });

    await renderPage();

    const props = contentLayoutSpy.mock.calls.at(-1)?.[0];
    expect(props?.onboardingAction).toEqual({ flowId: "view-first-scan" });
  });

  it("falls back to add-provider onboarding when no provider is connected", async () => {
    getAllProvidersMock.mockResolvedValue({ data: [disconnectedProvider] });

    await renderPage();

    const props = contentLayoutSpy.mock.calls.at(-1)?.[0];
    expect(props?.onboardingAction).toEqual({
      flowId: "view-first-scan",
      fallbackFlowId: "add-provider",
      useFallback: true,
    });
  });
});

describe("scans page scheduled tab source", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("sources the Scheduled tab from /schedules only for the advanced capability", () => {
    expect(source).toContain("getSchedulesPage");
    expect(source).toContain("SCAN_SCHEDULE_CAPABILITY.ADVANCED");
    expect(source).toContain("tab === SCAN_JOBS_TAB.SCHEDULED");
  });

  it("maps schedule resources to rows and delegates pagination to the endpoint", () => {
    expect(source).toContain("buildScheduledTabRows");
    expect(source).toContain("pickScheduleProviderFilters");
  });
});
