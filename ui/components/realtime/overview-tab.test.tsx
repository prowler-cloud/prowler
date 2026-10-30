import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getInsight, getFrameworks } = vi.hoisted(() => ({
  getInsight: vi.fn(),
  getFrameworks: vi.fn(),
}));

vi.mock("@/actions/realtime", () => ({
  getRealtimeInsight: getInsight,
  getRealtimeFrameworks: getFrameworks,
}));
vi.mock("@/components/realtime/posture-timeline", () => ({
  PostureTimeline: () => null,
}));

import type {
  RealtimeOverviewPayload,
  RealtimeSimulationPayload,
} from "@/types/realtime";

import { OverviewTab } from "./overview-tab";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

const overview = (
  cost: RealtimeOverviewPayload["cost"],
  policy: RealtimeOverviewPayload["policy"] = {
    enabled: true,
    mode: "pr",
    dry_run: true,
    scope_tags: {},
  },
): RealtimeOverviewPayload => ({
  provider: { id: PROVIDER, uid: "123456789012", alias: null },
  policy,
  feed: null,
  data_store: "ok",
  events_last_hour: { events: 10, changes: 2 },
  cost,
  posture: {
    passed: 8,
    failed: 2,
    muted: 0,
    score: 80,
    failed_by_severity: {},
    has_scan: true,
  },
  detections: {},
  actions: {},
});

const simulation: RealtimeSimulationPayload = {
  open: 4,
  would_fix_in_account: 0,
  would_propose_in_code: 1,
  needs_a_person: 1,
  outside_frameworks: 2,
  frameworks: ["soc2_aws"],
  dry_run: true,
  mode: "pr",
  effects: [],
  projected_open_after_auto: 4,
  automation_share: 50,
};

const respond = (cost: RealtimeOverviewPayload["cost"], policy?: never) => {
  getInsight.mockImplementation(async (kind: string) => {
    if (kind === "overview") return { ok: true, data: overview(cost, policy) };
    if (kind === "simulation") return { ok: true, data: simulation };
    return { ok: true, data: { points: [], actions: [] } };
  });
};

describe("OverviewTab cost", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getFrameworks.mockResolvedValue({
      ok: true,
      data: [{ id: "soc2_aws", name: "SOC 2", version: "2017" }],
    });
  });

  it("shows no cost card, only a hint to enable it, while cost anomalies are off", async () => {
    respond({ enabled: false });
    render(<OverviewTab providerId={PROVIDER} />);

    const hint = await screen.findByRole("link", {
      name: "enable them in Configuration",
    });
    expect(hint).toHaveAttribute(
      "href",
      `/realtime/settings/cost-anomalies?provider=${PROVIDER}`,
    );
    expect(screen.getByText(/Cost anomalies are off/)).toBeVisible();
    expect(screen.queryByText("Cost today")).not.toBeInTheDocument();
  });

  it("shows the cost card and links every anomaly to its detail", async () => {
    respond({
      enabled: true,
      available: true,
      total: 300,
      today: 42.5,
      anomaly_count: 2,
      anomalies: [
        {
          id: "Amazon Elastic Compute Cloud - Compute|eu-west-1",
          service: "Amazon Elastic Compute Cloud - Compute",
          region: "eu-west-1",
          short_service: "ec2",
          today: 120,
          base: 20,
          delta: 100,
          ratio: 6,
        },
        {
          id: "Amazon S3|us-east-1",
          service: "Amazon S3",
          region: "us-east-1",
          short_service: "s3",
          today: 30,
          base: 10,
          delta: 20,
          ratio: 3,
        },
      ],
    });
    render(<OverviewTab providerId={PROVIDER} />);

    expect(await screen.findByText("Cost today")).toBeVisible();
    expect(screen.getByText("$42.50")).toBeVisible();
    expect(screen.getByText("2 cost anomalies")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "ec2 (eu-west-1)" }),
    ).toHaveAttribute(
      "href",
      `/realtime/cost-anomalies/${encodeURIComponent(
        "Amazon Elastic Compute Cloud - Compute|eu-west-1",
      )}?provider=${PROVIDER}`,
    );
    expect(
      screen.getByRole("link", { name: "s3 (us-east-1)" }),
    ).toHaveAttribute(
      "href",
      `/realtime/cost-anomalies/Amazon%20S3%7Cus-east-1?provider=${PROVIDER}`,
    );
    expect(
      screen.queryByText(/Cost anomalies are off/),
    ).not.toBeInTheDocument();
  });

  it("says there is no cost data yet when enabled but not available", async () => {
    respond({
      enabled: true,
      available: false,
      anomaly_count: 0,
      anomalies: [],
    });
    render(<OverviewTab providerId={PROVIDER} />);

    expect(await screen.findByText(/No cost data yet/)).toBeVisible();
  });

  it("shows the enforced frameworks as badges, and links to the settings", async () => {
    respond({ enabled: false });
    render(<OverviewTab providerId={PROVIDER} />);

    const list = await screen.findByRole("list", {
      name: "Enforced frameworks",
    });
    expect(list).toHaveTextContent("SOC 2");
    expect(screen.getByRole("link", { name: "Configure" })).toHaveAttribute(
      "href",
      `/realtime/settings?provider=${PROVIDER}`,
    );
    expect(
      await screen.findByText(/outside the enforced frameworks/),
    ).toBeVisible();
  });
});
