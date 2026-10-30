import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getSetup: vi.fn(),
  getPolicy: vi.fn(),
  getCredential: vi.fn(),
  getFrameworks: vi.fn(),
  getTargets: vi.fn(),
  savePolicy: vi.fn(),
  patchPolicy: vi.fn(),
  push: vi.fn(),
  toast: vi.fn(),
  permissions: { manage_prowler_realtime: true } as Record<string, boolean>,
}));

vi.mock("@/actions/realtime", () => ({
  getRealtimeSetup: mocks.getSetup,
  getRealtimePolicy: mocks.getPolicy,
  getRealtimeCredential: mocks.getCredential,
  getRealtimeFrameworks: mocks.getFrameworks,
  getRealtimeNotificationTargets: mocks.getTargets,
  saveRealtimePolicy: mocks.savePolicy,
  patchRealtimePolicy: mocks.patchPolicy,
}));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mocks.push }),
}));
vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: mocks.permissions }),
}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast: mocks.toast }),
}));
vi.mock("@/components/realtime/feed-setup-panel", () => ({
  FeedSetupPanel: () => <div>Event feed setup</div>,
}));
vi.mock("@/components/realtime/credentials-form", () => ({
  CredentialsForm: () => <div>Credentials for remediation only</div>,
}));
vi.mock("@/components/realtime/notifications-section", () => ({
  AlertsSection: () => <div>Alerts section</div>,
}));
vi.mock("@/components/realtime/cost-anomaly-settings", () => ({
  CostAnomalyForm: () => <div>Cost anomaly form</div>,
}));

import type {
  RealtimePolicy,
  RealtimeSetupPayload,
  RealtimeSetupStepId,
} from "@/types/realtime";

import { RealtimeSetupWizard } from "./realtime-setup-wizard";

const P1 = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";
const P2 = "1c9d3c57-8a4b-4e2f-8b63-4a6a2e7b8d21";
const providers = [
  { id: P1, uid: "111111111111", alias: "prod" },
  { id: P2, uid: "222222222222", alias: null },
];

const setup = (
  next: RealtimeSetupStepId | null,
  done: RealtimeSetupStepId[] = [],
  activated = false,
): RealtimeSetupPayload => ({
  activated,
  next_step: next,
  steps: (
    [
      ["feed", true],
      ["enforcement", true],
      ["remediation", false],
      ["alerts", false],
      ["cost", false],
      ["activate", true],
    ] as Array<[RealtimeSetupStepId, boolean]>
  ).map(([id, required]) => ({
    id,
    required,
    done: done.includes(id),
    detail: id === "feed" && done.includes(id) ? "CloudTrail lookup" : null,
  })),
});

const policy = (overrides: Partial<RealtimePolicy> = {}): RealtimePolicy => ({
  id: "1f2e3d4c-5b6a-4798-8a9b-0c1d2e3f4a5b",
  provider_id: P1,
  enabled: false,
  mode: "monitor",
  dry_run: true,
  min_severity: "low",
  deny_checks: [],
  allow_regions: [],
  scope_tags: {},
  iac_repo: "",
  iac_path: "",
  open_pr: false,
  use_lighthouse: true,
  frameworks: ["soc2_aws"],
  cost_anomaly_enabled: false,
  cost_anomaly_min_ratio: 2,
  cost_anomaly_min_delta: 5,
  notifications: {
    min_severity: "high",
    slack: { enabled: false, channel_ids: [] },
    email: { enabled: false, recipient_ids: [] },
  },
  ...overrides,
});

const ok = <T,>(data: T) => ({ ok: true as const, data });

beforeAll(() => {
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

describe("RealtimeSetupWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.permissions = { manage_prowler_realtime: true };
    mocks.getSetup.mockResolvedValue(ok(setup("feed")));
    mocks.getPolicy.mockResolvedValue(ok(null));
    mocks.getCredential.mockResolvedValue(ok(null));
    mocks.getFrameworks.mockResolvedValue(
      ok([{ id: "soc2_aws", name: "SOC 2", version: "2017" }]),
    );
    mocks.getTargets.mockResolvedValue(ok({ slack: [], email: [] }));
    mocks.savePolicy.mockImplementation(async ({ policy: input }) =>
      ok(policy(input)),
    );
    mocks.patchPolicy.mockImplementation(async ({ patch }) =>
      ok(policy(patch)),
    );
  });

  it("explains and links to Providers when the tenant has no AWS provider", () => {
    render(<RealtimeSetupWizard providers={[]} />);

    expect(screen.getByText("Connect an AWS account first")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Go to Providers" }),
    ).toHaveAttribute("href", "/providers");
  });

  it("explains and changes nothing without the permission", () => {
    mocks.permissions = { manage_prowler_realtime: false };
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(screen.getByText("You cannot set this up")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Back to the dashboard" }),
    ).toHaveAttribute("href", "/realtime");
    expect(mocks.getSetup).not.toHaveBeenCalled();
    expect(mocks.savePolicy).not.toHaveBeenCalled();
  });

  it("offers the Lighthouse AI alternative, secondary, in the header", async () => {
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByRole("link", {
        name: "Ask Lighthouse AI to set it up",
      }),
    ).toHaveAttribute("href", "/lighthouse");
    expect(screen.getByText(/Nothing runs until you activate/)).toBeVisible();
  });

  it("starts at the account step when no provider is in the URL, then resumes", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(ok(setup("enforcement", ["feed"])));
    render(<RealtimeSetupWizard providers={providers} />);

    expect(
      await screen.findByRole("heading", { name: /Step 1 of 7: Account/ }),
    ).toBeVisible();
    await user.click(await screen.findByRole("button", { name: "Continue" }));

    expect(
      await screen.findByRole("heading", {
        name: /Step 3 of 7: What to enforce/,
      }),
    ).toBeVisible();
  });

  it("resumes at the first required unfinished step and draws the progress", async () => {
    mocks.getSetup.mockResolvedValue(ok(setup("enforcement", ["feed"])));
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByRole("heading", {
        name: /Step 3 of 7: What to enforce/,
      }),
    ).toBeVisible();
    expect(mocks.getSetup).toHaveBeenCalledWith(P1);
    const progress = screen.getByRole("list", { name: "Setup steps" });
    expect(within(progress).getAllByRole("listitem")).toHaveLength(7);
    expect(
      within(progress).getByRole("button", { name: /What to enforce/ }),
    ).toHaveAttribute("aria-current", "step");
    expect(
      within(progress).getByRole("button", { name: /Event feed/ }),
    ).toHaveTextContent("done");
    // The review is not reachable while the enforcement step is open.
    expect(
      within(progress).getByRole("button", { name: /Review and activate/ }),
    ).toBeDisabled();
  });

  it("resumes at the feed for a provider with nothing done", async () => {
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByRole("heading", { name: /Step 2 of 7: Event feed/ }),
    ).toBeVisible();
    expect(screen.getByText("Event feed setup")).toBeVisible();
    // Required and not done: it blocks Continue.
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  it("creates the policy switched off, in monitor mode with dry run on, on the first save", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(ok(setup("enforcement", ["feed"])));
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByRole("radio", { name: /Monitor only/ }),
    ).toBeChecked();
    expect(screen.getByRole("switch", { name: /Dry run/ })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save and continue" }));

    await waitFor(() => expect(mocks.savePolicy).toHaveBeenCalledTimes(1));
    expect(mocks.savePolicy.mock.calls[0][0]).toMatchObject({
      providerId: P1,
      policy: { enabled: false, mode: "monitor", dry_run: true },
    });
    expect(mocks.patchPolicy).not.toHaveBeenCalled();
    expect(
      await screen.findByRole("heading", {
        name: /Step 4 of 7: Remediation permission/,
      }),
    ).toBeVisible();
    expect(screen.getByText("Credentials for remediation only")).toBeVisible();
  });

  it("patches an existing policy with enabled false and only what the step edits", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(ok(setup("enforcement", ["feed"])));
    mocks.getPolicy.mockResolvedValue(ok(policy()));
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    await user.click(
      await screen.findByRole("radio", { name: /Propose a change/ }),
    );
    await user.click(screen.getByRole("button", { name: "Save and continue" }));

    await waitFor(() => expect(mocks.patchPolicy).toHaveBeenCalledTimes(1));
    const { policyId, patch } = mocks.patchPolicy.mock.calls[0][0];
    expect(policyId).toBe(policy().id);
    expect(patch).toMatchObject({ enabled: false, mode: "pr", dry_run: true });
    expect(Object.keys(patch).sort()).toEqual([
      "dry_run",
      "enabled",
      "frameworks",
      "min_severity",
      "mode",
      "scope_tags",
      "use_lighthouse",
    ]);
    expect(mocks.savePolicy).not.toHaveBeenCalled();
  });

  it("shows the API's message when a step cannot be saved", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(ok(setup("enforcement", ["feed"])));
    mocks.savePolicy.mockResolvedValue({
      ok: false,
      status: 403,
      error: "Forbidden",
    });
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Save and continue" }),
    );

    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Could not save your choices" }),
      ),
    );
    expect(screen.getByRole("heading", { name: /Step 3 of 7/ })).toBeVisible();
  });

  it("lets the optional steps be skipped", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(
      ok(setup("activate", ["feed", "enforcement"])),
    );
    mocks.getPolicy.mockResolvedValue(ok(policy()));
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    await user.click(
      await screen.findByRole("button", { name: /Remediation permission/ }),
    );
    expect(screen.getByText("Credentials for remediation only")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Skip for now" }));
    expect(await screen.findByText("Alerts section")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Skip for now" }));
    expect(await screen.findByText("Cost anomaly form")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Skip for now" }));

    expect(
      await screen.findByRole("heading", {
        name: /Step 7 of 7: Review and activate/,
      }),
    ).toBeVisible();
    expect(mocks.patchPolicy).not.toHaveBeenCalled();
  });

  it("sends enabled true only from the review step, and then opens the real dashboard", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(
      ok(setup("activate", ["feed", "enforcement"])),
    );
    mocks.getPolicy.mockResolvedValue(ok(policy()));
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByRole("heading", {
        name: /Step 7 of 7: Review and activate/,
      }),
    ).toBeVisible();
    // Nothing was written just by getting here.
    expect(mocks.savePolicy).not.toHaveBeenCalled();
    expect(mocks.patchPolicy).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole("button", { name: "Activate Prowler Realtime" }),
    );

    await waitFor(() => expect(mocks.patchPolicy).toHaveBeenCalledTimes(1));
    expect(mocks.patchPolicy.mock.calls[0][0]).toMatchObject({
      providerId: P1,
      patch: { enabled: true },
    });
    await waitFor(() =>
      expect(mocks.push).toHaveBeenCalledWith(`/realtime?provider=${P1}`),
    );
  });

  it("summarises every choice before activating", async () => {
    mocks.getSetup.mockResolvedValue(
      ok(setup("activate", ["feed", "enforcement"])),
    );
    mocks.getPolicy.mockResolvedValue(
      ok(
        policy({
          cost_anomaly_enabled: true,
          scope_tags: { env: "prod" },
          notifications: {
            min_severity: "critical",
            slack: { enabled: true, channel_ids: ["C1"] },
            email: { enabled: false, recipient_ids: [] },
          },
        }),
      ),
    );
    mocks.getTargets.mockResolvedValue(
      ok({
        slack: [{ integration_id: "i", channel_id: "C1", name: "security" }],
        email: [],
      }),
    );
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    const dl = await screen.findByLabelText("Summary of your choices");
    expect(within(dl).getByText("prod (111111111111)")).toBeVisible();
    expect(within(dl).getByText("CloudTrail lookup")).toBeVisible();
    expect(await within(dl).findByText("SOC 2")).toBeVisible();
    expect(within(dl).getByText("Monitor only")).toBeVisible();
    expect(within(dl).getByText("env=prod")).toBeVisible();
    expect(await within(dl).findByText("Slack: #security")).toBeVisible();
    expect(within(dl).getByText(/^On \(from 2x/)).toBeVisible();
    expect(
      within(dl).getByText("Not set: Prowler cannot change the account"),
    ).toBeVisible();
  });

  it("asks once more before activating live fixes", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(
      ok(setup("activate", ["feed", "enforcement"])),
    );
    mocks.getPolicy.mockResolvedValue(
      ok(policy({ mode: "auto", dry_run: false })),
    );
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Activate Prowler Realtime" }),
    );

    expect(
      await screen.findByText("Let Prowler Realtime change your AWS account?"),
    ).toBeVisible();
    expect(mocks.patchPolicy).not.toHaveBeenCalled();
    await user.click(
      screen.getByRole("button", { name: "Activate with live fixes" }),
    );
    await waitFor(() => expect(mocks.patchPolicy).toHaveBeenCalledTimes(1));
    expect(mocks.patchPolicy.mock.calls[0][0].patch).toEqual({ enabled: true });
  });

  it("does not leave for the dashboard when activation fails", async () => {
    const user = userEvent.setup();
    mocks.getSetup.mockResolvedValue(
      ok(setup("activate", ["feed", "enforcement"])),
    );
    mocks.getPolicy.mockResolvedValue(ok(policy()));
    mocks.patchPolicy.mockResolvedValue({
      ok: false,
      status: 400,
      error: "Add a feed first.",
    });
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Activate Prowler Realtime" }),
    );

    expect(await screen.findByText("Add a feed first.")).toBeVisible();
    expect(mocks.push).not.toHaveBeenCalled();
  });

  it("says so when the account is already on, instead of starting over", async () => {
    mocks.getSetup.mockResolvedValue(
      ok(setup(null, ["feed", "enforcement"], true)),
    );
    mocks.getPolicy.mockResolvedValue(ok(policy({ enabled: true })));
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByText(
        "Prowler Realtime is already on for this account",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Open the dashboard" }),
    ).toHaveAttribute("href", `/realtime?provider=${P1}`);
  });

  it("explains a 503 or 404 from the setup endpoint as a notice", async () => {
    mocks.getSetup.mockResolvedValue({ ok: false, status: 503, error: "x" });
    render(
      <RealtimeSetupWizard providers={providers} initialProviderId={P1} />,
    );

    expect(
      await screen.findByText("Real-time data store not configured"),
    ).toBeVisible();
  });
});
