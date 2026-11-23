import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DEFAULT_REALTIME_POLICY } from "@/app/(prowler)/realtime/_lib/policy-schema";
import {
  REALTIME_DATA_STORE,
  REALTIME_FEED_SOURCE,
  REALTIME_FEED_STATUS,
  REALTIME_MODE,
  type RealtimeOverviewPayload,
  type RealtimePolicy,
} from "@/app/(prowler)/realtime/_types";

import { RealtimeAccountHeader } from "./realtime-account-header";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
}));
vi.mock("@/app/(prowler)/realtime/_actions", () => ({
  getRealtimeDemo: vi.fn(),
  getRealtimeInsight: vi.fn(),
}));

const PROVIDER = {
  id: "1f0e6c1e-6b1a-4c8f-9d55-7d6d1d8c2a10",
  uid: "123456789012",
  alias: "production",
};

const policy = (overrides: Partial<RealtimePolicy> = {}): RealtimePolicy => ({
  ...DEFAULT_REALTIME_POLICY,
  id: "policy",
  provider_id: PROVIDER.id,
  ...overrides,
});

const overview = (
  feed: RealtimeOverviewPayload["feed"],
): RealtimeOverviewPayload => ({
  provider: PROVIDER,
  policy: null,
  feed,
  data_store: REALTIME_DATA_STORE.OK,
  events_last_hour: { events: 10, changes: 2 },
  cost: { enabled: false },
  posture: {
    passed: 1,
    failed: 1,
    muted: 0,
    score: 50,
    failed_by_severity: {},
    has_scan: true,
  },
  detections: {},
  actions: {},
});

const renderHeader = (
  props: Partial<Parameters<typeof RealtimeAccountHeader>[0]> = {},
) =>
  render(
    <RealtimeAccountHeader
      providers={[PROVIDER]}
      providerId={PROVIDER.id}
      tab="overview"
      policy={policy()}
      overview={overview(null)}
      frameworkNames={[]}
      canManage
      demo={false}
      {...props}
    />,
  );

describe("RealtimeAccountHeader", () => {
  it("says an auto-fix policy is in dry run", () => {
    renderHeader({
      policy: policy({
        enabled: true,
        mode: REALTIME_MODE.AUTO,
        dry_run: true,
      }),
    });

    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Fix automatically")).toBeInTheDocument();
    expect(screen.getByText("Dry run")).toBeInTheDocument();
  });

  it("only mentions dry run for auto-fix, where it applies", () => {
    renderHeader({
      policy: policy({ enabled: false, mode: REALTIME_MODE.PR, dry_run: true }),
    });

    expect(screen.getByText("Paused")).toBeInTheDocument();
    expect(screen.queryByText("Dry run")).not.toBeInTheDocument();
  });

  it("shows a failing feed and the frameworks it enforces", () => {
    renderHeader({
      overview: overview({
        status: REALTIME_FEED_STATUS.ERROR,
        source: REALTIME_FEED_SOURCE.SQS,
        last_event_at: null,
        last_error: "AccessDenied",
      }),
      frameworkNames: ["SOC 2"],
    });

    expect(screen.getByText("Feed error")).toBeInTheDocument();
    expect(screen.getByText("SOC 2")).toBeInTheDocument();
  });

  it("marks a role without the permission as read only", () => {
    renderHeader({ canManage: false });

    expect(screen.getByText("Read only")).toBeInTheDocument();
  });

  it("hides the policy details and Configure on demo data", () => {
    renderHeader({ policy: null, demo: true });

    expect(screen.getByText("Not set up")).toBeInTheDocument();
    expect(screen.queryByText("Response")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /Configure/ }),
    ).not.toBeInTheDocument();
  });
});
