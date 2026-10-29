import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { saveCost, toast } = vi.hoisted(() => ({
  saveCost: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/actions/realtime", () => ({
  saveRealtimeCostSettings: saveCost,
  getRealtimePolicy: vi.fn(),
}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast }),
}));
vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_prowler_realtime: true } }),
}));

import { CostAnomalyForm } from "./cost-anomaly-settings";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

const policy = {
  id: "pol-1",
  provider_id: PROVIDER,
  enabled: false,
  mode: "pr" as const,
  dry_run: true,
  min_severity: "low" as const,
  deny_checks: [],
  allow_regions: [],
  scope_tags: {},
  iac_repo: "",
  iac_path: "",
  open_pr: false,
  use_lighthouse: true,
  frameworks: [],
  cost_anomaly_enabled: false,
  cost_anomaly_min_ratio: 2,
  cost_anomaly_min_delta: 5,
  notifications: {
    min_severity: "high" as const,
    slack: { enabled: false, channel_ids: [] },
    email: { enabled: false, recipient_ids: [] },
  },
};

describe("CostAnomalyForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    saveCost.mockResolvedValue({ ok: true, data: policy });
  });

  it("is off by default and explains the Cost Explorer billing", () => {
    render(
      <CostAnomalyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("switch", { name: /detect cost anomalies/i }),
    ).not.toBeChecked();
    expect(screen.getByLabelText("Minimum ratio")).toHaveValue(2);
    expect(screen.getByLabelText(/Minimum increase/)).toHaveValue(5);
    expect(screen.getByText(/billed per request/i)).toBeVisible();
    expect(screen.getByText(/about every 6 hours/)).toBeVisible();
    expect(screen.getByText(/off until you enable it/i)).toBeVisible();
  });

  it("creates the policy without a policy id when none exists, keeping detection off", async () => {
    const user = userEvent.setup();
    const onSaved = vi.fn();
    render(
      <CostAnomalyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={onSaved}
      />,
    );

    expect(screen.getByText(/has no policy yet/)).toBeVisible();
    await user.click(
      screen.getByRole("switch", { name: /detect cost anomalies/i }),
    );
    await user.click(
      screen.getByRole("button", { name: /save cost anomaly settings/i }),
    );

    await waitFor(() => expect(saveCost).toHaveBeenCalled());
    expect(saveCost.mock.calls[0][0]).toEqual({
      providerId: PROVIDER,
      policyId: undefined,
      settings: {
        cost_anomaly_enabled: true,
        cost_anomaly_min_ratio: 2,
        cost_anomaly_min_delta: 5,
      },
    });
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(policy));
  });

  it("updates the existing policy with the thresholds typed", async () => {
    const user = userEvent.setup();
    render(
      <CostAnomalyForm
        providerId={PROVIDER}
        policy={policy}
        canManage
        onSaved={vi.fn()}
      />,
    );

    const ratio = screen.getByLabelText("Minimum ratio");
    await user.clear(ratio);
    await user.type(ratio, "3.5");
    const delta = screen.getByLabelText(/Minimum increase/);
    await user.clear(delta);
    await user.type(delta, "20");
    await user.click(
      screen.getByRole("button", { name: /save cost anomaly settings/i }),
    );

    await waitFor(() => expect(saveCost).toHaveBeenCalled());
    expect(saveCost.mock.calls[0][0]).toMatchObject({
      policyId: "pol-1",
      settings: { cost_anomaly_min_ratio: 3.5, cost_anomaly_min_delta: 20 },
    });
  });

  it("shows range errors and does not call the API", async () => {
    const user = userEvent.setup();
    render(
      <CostAnomalyForm
        providerId={PROVIDER}
        policy={policy}
        canManage
        onSaved={vi.fn()}
      />,
    );

    const ratio = screen.getByLabelText("Minimum ratio");
    await user.clear(ratio);
    await user.type(ratio, "50");
    await user.click(
      screen.getByRole("button", { name: /save cost anomaly settings/i }),
    );

    expect(
      await screen.findByText("Must be between 1.1 and 20."),
    ).toBeVisible();
    expect(saveCost).not.toHaveBeenCalled();
  });

  it("is read only without the permission", () => {
    render(
      <CostAnomalyForm
        providerId={PROVIDER}
        policy={policy}
        canManage={false}
        onSaved={vi.fn()}
      />,
    );

    expect(screen.getByText("Read only")).toBeVisible();
    expect(
      screen.getByRole("switch", { name: /detect cost anomalies/i }),
    ).toBeDisabled();
    expect(screen.getByLabelText("Minimum ratio")).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: /save cost anomaly settings/i }),
    ).not.toBeInTheDocument();
  });

  it("explains a 403 from the API", async () => {
    saveCost.mockResolvedValue({ ok: false, status: 403, error: "no" });
    const user = userEvent.setup();
    render(
      <CostAnomalyForm
        providerId={PROVIDER}
        policy={policy}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /save cost anomaly settings/i }),
    );

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "You cannot change these settings" }),
      ),
    );
  });
});
