import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getAnomaly } = vi.hoisted(() => ({ getAnomaly: vi.fn() }));

vi.mock("@/actions/realtime", () => ({ getRealtimeCostAnomaly: getAnomaly }));
// Recharts needs layout that jsdom does not have; the chart is covered by its helpers.
vi.mock("@/components/realtime/anomaly-chart", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("@/components/realtime/anomaly-chart")
  >()),
  AnomalyChart: ({ label }: { label: string }) => <div>chart: {label}</div>,
}));

import type { RealtimeAnomalyPayload } from "@/types/realtime";

import { AnomalyBody, AnomalyDetail } from "./anomaly-detail";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";
const ID = "Amazon Elastic Compute Cloud - Compute|eu-west-1";

const detail: RealtimeAnomalyPayload = {
  anomaly: {
    id: ID,
    service: "Amazon Elastic Compute Cloud - Compute",
    region: "eu-west-1",
    short_service: "ec2",
    today: 120,
    base: 20,
    delta: 100,
    ratio: 6,
  },
  short_service: "ec2",
  series: [
    { day: "2026-10-21", amount: 20 },
    { day: "2026-10-22", amount: 22 },
    { day: "2026-10-23", amount: 120 },
  ],
  thresholds: { min_ratio: 2, min_delta: 5 },
  events: [
    {
      event_id: "e1",
      event_time: "2026-10-23T09:00:00Z",
      region: "eu-west-1",
      event_source: "ec2.amazonaws.com",
      event_name: "RunInstances",
      user_type: "IAMUser",
      user_arn: "arn:aws:iam::123456789012:user/mallory",
      source_ip: "203.0.113.9",
      error_code: "",
    },
  ],
  findings: [
    {
      finding_id: "f1",
      check_id: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
      severity: "high",
      title: "SSH open to the internet",
      service: "ec2",
      resource_uid: "sg-1",
      region: "eu-west-1",
      status_extended: "",
      score: 90,
      reasons: [],
      route: "pr",
    },
  ],
};

describe("AnomalyBody", () => {
  it("shows today, baseline, increase and ratio against the thresholds", () => {
    render(
      <AnomalyBody
        detail={detail}
        service="Amazon Elastic Compute Cloud - Compute"
        region="eu-west-1"
      />,
    );

    expect(screen.getByText("$120.00")).toBeVisible();
    expect(screen.getByText("$20.00")).toBeVisible();
    expect(screen.getByText("+$100.00")).toBeVisible();
    expect(screen.getByText("6x")).toBeVisible();
    expect(screen.getByText(/Needs at least 2x/)).toBeVisible();
    expect(screen.getByText(/Needs at least \+\$5\.00/)).toBeVisible();
    expect(screen.getByText(/chart: Daily cost of/)).toBeVisible();
  });

  it("lists the recent changes and the related open findings", () => {
    render(
      <AnomalyBody
        detail={detail}
        service="Amazon Elastic Compute Cloud - Compute"
        region="eu-west-1"
      />,
    );

    expect(screen.getByText("RunInstances")).toBeVisible();
    expect(screen.getByText("user/mallory")).toBeVisible();
    expect(screen.getByText("SSH open to the internet")).toBeVisible();
  });

  it("says when the spend is back to normal", () => {
    render(
      <AnomalyBody
        detail={{ ...detail, anomaly: null }}
        service="Amazon Elastic Compute Cloud - Compute"
        region="eu-west-1"
      />,
    );

    expect(screen.getByText("Back to normal")).toBeVisible();
  });
});

describe("AnomalyDetail", () => {
  beforeEach(() => vi.clearAllMocks());

  it("fetches by service and region from the id and links back", async () => {
    getAnomaly.mockResolvedValue({ ok: true, data: detail });
    render(<AnomalyDetail anomalyId={ID} providerId={PROVIDER} />);

    expect(await screen.findByText("RunInstances")).toBeVisible();
    expect(getAnomaly).toHaveBeenCalledWith({
      providerId: PROVIDER,
      service: "Amazon Elastic Compute Cloud - Compute",
      region: "eu-west-1",
    });
    expect(
      screen.getByRole("link", { name: /back to realtime/i }),
    ).toHaveAttribute("href", `/realtime?provider=${PROVIDER}&tab=findings`);
  });

  it("says the anomaly is no longer active on a 404", async () => {
    getAnomaly.mockResolvedValue({
      ok: false,
      status: 404,
      error: "Not found",
    });
    render(<AnomalyDetail anomalyId={ID} providerId={PROVIDER} />);

    expect(
      await screen.findByText("This anomaly is no longer active"),
    ).toBeVisible();
    expect(
      screen.getAllByRole("link", { name: /back to realtime/i }),
    ).not.toHaveLength(0);
  });

  it("shows the data store notice on a 503", async () => {
    getAnomaly.mockResolvedValue({ ok: false, status: 503, error: "x" });
    render(<AnomalyDetail anomalyId={ID} providerId={PROVIDER} />);

    expect(
      await screen.findByText("Real-time data store not configured"),
    ).toBeVisible();
  });

  it("does not call the API for an id or provider that cannot be valid", () => {
    render(<AnomalyDetail anomalyId="nopipe" providerId={PROVIDER} />);

    expect(screen.getByText("This anomaly is no longer active")).toBeVisible();
    expect(getAnomaly).not.toHaveBeenCalled();
  });
});
