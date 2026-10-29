import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getInsight } = vi.hoisted(() => ({ getInsight: vi.fn() }));

vi.mock("@/actions/realtime", () => ({ getRealtimeInsight: getInsight }));

import { CostPanel } from "./cost-panel";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

describe("CostPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders nothing while cost anomalies are off", async () => {
    getInsight.mockResolvedValue({ ok: true, data: { enabled: false } });
    const { container } = render(<CostPanel providerId={PROVIDER} />);

    await vi.waitFor(() => expect(getInsight).toHaveBeenCalled());
    await vi.waitFor(() =>
      expect(screen.queryByRole("status")).not.toBeInTheDocument(),
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("links each anomaly to its detail page when enabled", async () => {
    getInsight.mockResolvedValue({
      ok: true,
      data: {
        enabled: true,
        total: { total: 100, today: 10 },
        series: [],
        thresholds: { min_ratio: 2, min_delta: 5 },
        anomalies: [
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
      },
    });
    render(<CostPanel providerId={PROVIDER} />);

    expect(
      await screen.findByRole("link", { name: "Amazon S3" }),
    ).toHaveAttribute(
      "href",
      `/realtime/cost-anomalies/Amazon%20S3%7Cus-east-1?provider=${PROVIDER}`,
    );
  });

  it("explains a missing data store with a notice", async () => {
    getInsight.mockResolvedValue({ ok: false, status: 503, error: "x" });
    render(<CostPanel providerId={PROVIDER} />);

    expect(
      await screen.findByText("Real-time data store not configured"),
    ).toBeVisible();
  });
});
