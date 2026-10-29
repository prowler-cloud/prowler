import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getDemo: vi.fn(),
  getInsight: vi.fn(),
  getActions: vi.fn(),
  getEvents: vi.fn(),
  getDetections: vi.fn(),
  getAnomaly: vi.fn(),
  getFrameworks: vi.fn(),
  revert: vi.fn(),
}));

vi.mock("@/actions/realtime", () => ({
  getRealtimeDemo: mocks.getDemo,
  getRealtimeInsight: mocks.getInsight,
  getRealtimeActions: mocks.getActions,
  getRealtimeEvents: mocks.getEvents,
  getRealtimeDetections: mocks.getDetections,
  getRealtimeCostAnomaly: mocks.getAnomaly,
  getRealtimeFrameworks: mocks.getFrameworks,
  revertRealtimeAction: mocks.revert,
}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));
vi.mock("@/components/realtime/posture-timeline", () => ({
  PostureTimeline: () => null,
}));
vi.mock("@/components/realtime/anomaly-chart", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("@/components/realtime/anomaly-chart")
  >()),
  AnomalyChart: ({ label }: { label: string }) => <div>chart: {label}</div>,
}));

import { DEMO_ANOMALY_ID } from "@/lib/realtime/demo";
import type {
  RealtimeAction,
  RealtimeDetection,
  RealtimeEvent,
} from "@/types/realtime";

import { ActionsList } from "./actions-list";
import { AnomalyDetail } from "./anomaly-detail";
import { DemoBanner, DemoProvider } from "./demo-context";
import { DetectionsList } from "./detections-list";
import { FindingsTab } from "./findings-tab";
import { OverviewTab } from "./overview-tab";
import { RealtimeSection } from "./realtime-stat-card";
import { StatusStatementCard } from "./status-statement-card";
import { StreamTab } from "./stream-tab";

const ok = <T,>(data: T) => ({ ok: true as const, data });
const page = <T,>(items: T[]) =>
  ok({ items, page: 1, pages: 1, count: items.length });

const action: RealtimeAction = {
  id: "a1",
  provider_id: "",
  detection_id: null,
  kind: "self_fix",
  status: "fixed_verified",
  check_id: "s3_bucket_level_public_access_block",
  resource_uid: "demo-bucket",
  region: "eu-west-1",
  severity: "high",
  summary: "Enabled public access block",
  pr_url: "",
  branch: "",
  revertible: true,
  inserted_at: "2026-10-23T10:00:00Z",
};

const event = (id: string, readOnly: boolean): RealtimeEvent => ({
  id,
  event_time: "2026-10-23T10:00:00Z",
  region: "eu-west-1",
  event_source: "ec2.amazonaws.com",
  event_name: readOnly ? "DescribeInstances" : "RunInstances",
  user_type: "IAMUser",
  user_arn: "arn:aws:iam::123456789012:user/demo",
  source_ip: "203.0.113.9",
  error_code: "",
  read_only: readOnly,
  provider_id: "",
  detection_status: null,
  rule_id: null,
});

const detection = (id: string, status: RealtimeDetection["status"]) =>
  ({
    id,
    provider_id: "p",
    event_id: "e",
    event_time: "2026-10-23T10:00:00Z",
    region: "eu-west-1",
    rule_id: `rule_${id}`,
    title: `Detection ${id}`,
    severity: "high",
    actor: "demo",
    resource: "r",
    check_ids: [],
    requirements: [],
    status,
    note: "",
    verified_at: null,
  }) as RealtimeDetection;

beforeAll(() => {
  // Radix Select needs these in jsdom.
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: () => false,
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: () => {},
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: () => {},
  });
});

const REAL = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

describe("demo labelling", () => {
  it("banner has the title, the setup button and the Lighthouse AI alternative", () => {
    render(<DemoBanner providerId={REAL} />);

    expect(screen.getByRole("status", { name: "Demo data" })).toHaveTextContent(
      "DEMO DATA — a made-up account shown until you set up Prowler Realtime",
    );
    expect(
      screen.getByRole("link", { name: "Set up Prowler Realtime" }),
    ).toHaveAttribute("href", `/realtime/setup?provider=${REAL}`);
    expect(
      screen.getByRole("link", { name: "Ask Lighthouse AI to set it up" }),
    ).toHaveAttribute("href", "/lighthouse");
  });

  it("marks section headers as demo for sight and for screen readers, only in a demo", () => {
    const { rerender } = render(
      <DemoProvider demo>
        <RealtimeSection title="Actions">body</RealtimeSection>
      </DemoProvider>,
    );

    expect(screen.getByTestId("demo-badge")).toHaveTextContent(
      "DEMO data: made up, not your account",
    );

    rerender(
      <DemoProvider demo={false}>
        <RealtimeSection title="Actions">body</RealtimeSection>
      </DemoProvider>,
    );
    expect(screen.queryByTestId("demo-badge")).not.toBeInTheDocument();
  });
});

describe("dashboard tabs in demo mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getFrameworks.mockResolvedValue(ok([]));
  });

  it("loads the overview, simulation and timeline from the demo, never the account", async () => {
    mocks.getDemo.mockImplementation(async (kind: string) => {
      if (kind === "overview") {
        return ok({
          provider: { id: "demo", uid: "123456789012", alias: "demo" },
          policy: null,
          feed: null,
          data_store: "ok",
          events_last_hour: { events: 3, changes: 1 },
          cost: {
            enabled: true,
            available: true,
            total: 100,
            today: 10,
            anomaly_count: 1,
            anomalies: [
              {
                id: DEMO_ANOMALY_ID,
                service: "Amazon Elastic Compute Cloud - Compute",
                region: "us-east-1",
                short_service: "ec2",
                today: 120,
                base: 20,
                delta: 100,
                ratio: 6,
              },
            ],
          },
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
      }
      if (kind === "simulation") {
        return ok({
          open: 1,
          would_fix_in_account: 0,
          would_propose_in_code: 0,
          needs_a_person: 0,
          outside_frameworks: 0,
          frameworks: [],
          dry_run: true,
          mode: "monitor",
          effects: [],
          projected_open_after_auto: 1,
          automation_share: 0,
        });
      }
      return ok({ points: [], actions: [] });
    });

    render(
      <DemoProvider demo>
        <OverviewTab providerId="" demo />
      </DemoProvider>,
    );

    const link = await screen.findByRole("link", { name: /ec2/ });
    expect(link).toHaveAttribute("href", "/realtime/cost-anomalies/demo");
    expect(mocks.getDemo.mock.calls.map(([kind]) => kind).sort()).toEqual([
      "overview",
      "simulation",
      "timeline",
    ]);
    expect(mocks.getInsight).not.toHaveBeenCalled();
    expect(screen.getAllByTestId("demo-badge").length).toBeGreaterThan(0);
  });

  it("loads findings and cost from the demo", async () => {
    mocks.getDemo.mockImplementation(async (kind: string) =>
      kind === "findings"
        ? ok({ signals: [], findings: [] })
        : ok({ enabled: false }),
    );

    render(
      <DemoProvider demo>
        <FindingsTab providerId="" demo />
      </DemoProvider>,
    );

    await screen.findByText("No open findings");
    expect(mocks.getDemo).toHaveBeenCalledWith("findings");
    expect(mocks.getDemo).toHaveBeenCalledWith("cost");
    expect(mocks.getInsight).not.toHaveBeenCalled();
  });

  it("loads the status statement from the demo", async () => {
    mocks.getDemo.mockResolvedValue(
      ok({
        generated_on: "2026-10-23",
        mode: "monitor",
        scope: "Whole account",
        checks_passing: 9,
        checks_failing: 1,
        failing_by_severity: {},
        fixed_and_verified_last_30_days: 2,
        sha256: "abc",
      }),
    );

    render(
      <DemoProvider demo>
        <StatusStatementCard providerId="" demo />
      </DemoProvider>,
    );

    expect(await screen.findByText("Whole account")).toBeVisible();
    expect(mocks.getDemo).toHaveBeenCalledWith("status");
    expect(mocks.getInsight).not.toHaveBeenCalled();
  });

  it("streams sample events, filters changes locally and never refreshes from the account", async () => {
    const user = userEvent.setup();
    mocks.getDemo.mockResolvedValue(
      page([event("e1", false), event("e2", true)]),
    );

    render(
      <DemoProvider demo>
        <StreamTab providerId="" demo />
      </DemoProvider>,
    );

    expect(await screen.findByText("RunInstances")).toBeVisible();
    expect(screen.queryByText("DescribeInstances")).not.toBeInTheDocument();
    await user.click(screen.getByRole("switch", { name: "Changes only" }));
    expect(await screen.findByText("DescribeInstances")).toBeVisible();
    expect(mocks.getDemo).toHaveBeenCalledWith("events");
    expect(mocks.getEvents).not.toHaveBeenCalled();
  });

  it("lists sample detections and filters them by verdict locally", async () => {
    const user = userEvent.setup();
    mocks.getDemo.mockResolvedValue(
      page([detection("a", "violation"), detection("b", "compliant")]),
    );

    render(
      <DemoProvider demo>
        <DetectionsList providerId="" demo />
      </DemoProvider>,
    );

    expect(await screen.findByText("Detection a")).toBeVisible();
    expect(screen.getByText("Detection b")).toBeVisible();
    await user.click(
      screen.getByRole("combobox", { name: "Filter detections by verdict" }),
    );
    await user.click(await screen.findByRole("option", { name: "Compliant" }));
    await waitFor(() =>
      expect(screen.queryByText("Detection a")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("Detection b")).toBeVisible();
    expect(mocks.getDetections).not.toHaveBeenCalled();
  });

  it("disables Revert on sample actions, with the Demo data tooltip, and never calls the API", async () => {
    const user = userEvent.setup();
    mocks.getDemo.mockResolvedValue(page([action]));

    render(
      <DemoProvider demo>
        <ActionsList providerId="" canManage demo />
      </DemoProvider>,
    );

    const revert = await screen.findByRole("button", { name: "Revert" });
    expect(revert).toBeDisabled();
    await user.hover(revert.parentElement as HTMLElement);
    expect((await screen.findAllByText("Demo data")).length).toBeGreaterThan(0);
    expect(mocks.getActions).not.toHaveBeenCalled();
    expect(mocks.revert).not.toHaveBeenCalled();
  });
});

describe("the demo anomaly page", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows the banner and loads the demo anomaly without a provider", async () => {
    mocks.getDemo.mockResolvedValue(
      ok({
        anomaly: {
          id: DEMO_ANOMALY_ID,
          service: "Amazon Elastic Compute Cloud - Compute",
          region: "us-east-1",
          short_service: "ec2",
          today: 120,
          base: 20,
          delta: 100,
          ratio: 6,
        },
        short_service: "ec2",
        series: [{ day: "2026-10-23", amount: 120 }],
        thresholds: { min_ratio: 2, min_delta: 5 },
        events: [],
        findings: [],
      }),
    );

    render(<AnomalyDetail anomalyId={DEMO_ANOMALY_ID} providerId="" demo />);

    expect(await screen.findByText(/chart: Daily cost of/)).toBeVisible();
    expect(screen.getByText(/DEMO DATA/)).toBeVisible();
    expect(
      screen.getByRole("heading", {
        name: "Cost anomaly: Amazon Elastic Compute Cloud - Compute",
      }),
    ).toBeVisible();
    expect(mocks.getDemo).toHaveBeenCalledWith("anomaly");
    expect(mocks.getAnomaly).not.toHaveBeenCalled();
    expect(screen.getAllByTestId("demo-badge").length).toBeGreaterThan(0);
  });

  it("has no banner for a real anomaly", () => {
    mocks.getAnomaly.mockReturnValue(new Promise(() => {}));
    render(<AnomalyDetail anomalyId={DEMO_ANOMALY_ID} providerId={REAL} />);

    expect(screen.queryByText(/DEMO DATA/)).not.toBeInTheDocument();
  });
});
