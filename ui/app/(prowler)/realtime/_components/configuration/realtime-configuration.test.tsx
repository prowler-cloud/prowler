import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_REALTIME_POLICY } from "@/app/(prowler)/realtime/_lib/policy-schema";
import {
  REALTIME_FEED_STATUS,
  REALTIME_MODE,
  type RealtimeFeed,
  type RealtimePolicy,
  type RealtimeSetupPayload,
} from "@/app/(prowler)/realtime/_types";

import {
  RealtimeConfiguration,
  type RealtimeConfigurationProps,
} from "./realtime-configuration";

const actions = vi.hoisted(() => ({
  saveRealtimePolicy: vi.fn(),
  patchRealtimePolicy: vi.fn(),
  saveRealtimeFeed: vi.fn(),
  pollRealtimeFeed: vi.fn(),
  saveRealtimeCredential: vi.fn(),
  deleteRealtimeCredential: vi.fn(),
  saveRealtimeNotifications: vi.fn(),
  saveRealtimeCostSettings: vi.fn(),
}));

const router = vi.hoisted(() => ({
  refresh: vi.fn(),
  replace: vi.fn(),
  push: vi.fn(),
}));

vi.mock("@/app/(prowler)/realtime/_actions", () => actions);
vi.mock("next/navigation", () => ({
  useRouter: () => router,
  usePathname: () => "/realtime/configuration",
  useSearchParams: () => new URLSearchParams("provider=p1"),
}));

const PROVIDER_ID = "8b5ff0f4-5b4b-4f2a-9c6d-3c3e0b0f1a11";

const setup = (
  done: Partial<Record<string, boolean>> = {},
  next: RealtimeSetupPayload["next_step"] = "feed",
): RealtimeSetupPayload => ({
  activated: Boolean(done.activate),
  next_step: next,
  steps: [
    ["feed", true],
    ["enforcement", true],
    ["remediation", false],
    ["alerts", false],
    ["cost", false],
    ["activate", true],
  ].map(([id, required]) => ({
    id: id as RealtimeSetupPayload["steps"][number]["id"],
    required: required as boolean,
    done: Boolean(done[id as string]),
    detail: null,
  })),
});

const policy = (overrides: Partial<RealtimePolicy> = {}): RealtimePolicy => ({
  id: "c0b4d2a1-1111-4a2b-8c3d-111111111111",
  provider_id: PROVIDER_ID,
  ...DEFAULT_REALTIME_POLICY,
  ...overrides,
});

const feed: RealtimeFeed = {
  id: "f0b4d2a1-2222-4a2b-8c3d-222222222222",
  provider_id: PROVIDER_ID,
  queue_url: "",
  region: "us-east-1",
  status: REALTIME_FEED_STATUS.CONNECTED,
  last_polled_at: null,
  last_event_at: null,
  last_error: "",
};

const renderPage = (overrides: Partial<RealtimeConfigurationProps> = {}) =>
  render(
    <RealtimeConfiguration
      providerId={PROVIDER_ID}
      accountLabel="production (123456789012)"
      canManage
      policy={null}
      feed={feed}
      credential={null}
      setup={setup({ feed: true }, "enforcement")}
      frameworks={[{ id: "soc2_aws", name: "SOC 2", version: "" }]}
      targets={{ slack: [], email: [] }}
      remediations={[]}
      lighthouseConfigured
      initialSection="enforcement"
      {...overrides}
    />,
  );

const enforcementCard = () =>
  screen
    .getByRole("heading", { name: "What to enforce" })
    .closest("[data-slot=card]") as HTMLElement;

beforeEach(() => {
  Object.values(actions).forEach((mock) => mock.mockReset());
  Object.values(router).forEach((mock) => mock.mockReset());
  Element.prototype.scrollIntoView = vi.fn();
});

describe("What to enforce", () => {
  it("creates the policy switched off on the first save", async () => {
    actions.saveRealtimePolicy.mockResolvedValue({ ok: true, data: policy() });
    const user = userEvent.setup();
    renderPage();

    await user.click(screen.getByRole("button", { name: "Save and continue" }));

    await waitFor(() => expect(actions.saveRealtimePolicy).toHaveBeenCalled());
    const [{ providerId, policy: sent }] =
      actions.saveRealtimePolicy.mock.calls[0];
    expect(providerId).toBe(PROVIDER_ID);
    expect(sent).toMatchObject({ enabled: false, mode: REALTIME_MODE.MONITOR });
    expect(actions.patchRealtimePolicy).not.toHaveBeenCalled();
    expect(router.refresh).toHaveBeenCalled();
  });

  it("patches only its own fields once a policy exists", async () => {
    const stored = policy({ enabled: true, mode: REALTIME_MODE.PR });
    actions.patchRealtimePolicy.mockResolvedValue({ ok: true, data: stored });
    const user = userEvent.setup();
    renderPage({ policy: stored });

    await user.click(
      within(enforcementCard()).getByRole("button", { name: "Save" }),
    );

    await waitFor(() => expect(actions.patchRealtimePolicy).toHaveBeenCalled());
    const [{ patch }] = actions.patchRealtimePolicy.mock.calls[0];
    expect(patch).not.toHaveProperty("enabled");
    expect(patch).not.toHaveProperty("notifications");
    expect(patch).not.toHaveProperty("cost_anomaly_enabled");
    expect(patch.mode).toBe(REALTIME_MODE.PR);
    expect(actions.saveRealtimePolicy).not.toHaveBeenCalled();
  });

  it("asks for code settings only when the mode changes code", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(screen.queryByText("Changes in code")).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: /Propose a change/ }));
    expect(screen.getByText("Changes in code")).toBeInTheDocument();
  });

  it("offers dry run only for automatic fixes", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(
      screen.queryByRole("switch", { name: "Dry run" }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: /Fix automatically/ }));
    const dryRun = screen.getByRole("switch", { name: "Dry run" });
    expect(dryRun).toBeChecked();

    await user.click(dryRun);
    expect(
      screen.getByText(/Prowler will change this AWS account/),
    ).toBeInTheDocument();
  });

  it("shows the API's field errors next to the field", async () => {
    const stored = policy({ mode: REALTIME_MODE.PR });
    actions.patchRealtimePolicy.mockResolvedValue({
      ok: false,
      status: 400,
      error: "Invalid",
      fieldErrors: { iac_repo: "Must look like owner/repository." },
    });
    const user = userEvent.setup();
    renderPage({ policy: stored });

    await user.click(
      within(enforcementCard()).getByRole("button", { name: "Save" }),
    );

    expect(
      await screen.findByText("Must look like owner/repository."),
    ).toBeInTheDocument();
  });
});

describe("Activate", () => {
  it("stays disabled until the required steps are done", () => {
    renderPage({ initialSection: null });

    expect(screen.getByRole("button", { name: "Activate" })).toBeDisabled();
    expect(
      screen.getByText(/Finish first: What to enforce/),
    ).toBeInTheDocument();
  });

  it("warns about automatic fixes without a role and activates in dry run", async () => {
    actions.patchRealtimePolicy.mockResolvedValue({
      ok: true,
      data: policy({ enabled: true }),
    });
    const user = userEvent.setup();
    renderPage({
      initialSection: null,
      policy: policy({ mode: REALTIME_MODE.AUTO, dry_run: true }),
      setup: setup({ feed: true, enforcement: true }, "activate"),
    });

    expect(
      screen.getByText(/no remediation role, so fixes would fail/),
    ).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Activate in dry run" }),
    );

    await waitFor(() =>
      expect(actions.patchRealtimePolicy).toHaveBeenCalledWith(
        expect.objectContaining({ patch: { enabled: true } }),
      ),
    );
  });

  it("confirms before turning on live fixes", async () => {
    const user = userEvent.setup();
    renderPage({
      initialSection: null,
      policy: policy({ mode: REALTIME_MODE.AUTO, dry_run: false }),
      setup: setup({ feed: true, enforcement: true }, "activate"),
    });

    await user.click(screen.getByRole("button", { name: "Activate" }));

    expect(
      await screen.findByText("Let Prowler change your AWS account?"),
    ).toBeInTheDocument();
    expect(actions.patchRealtimePolicy).not.toHaveBeenCalled();
  });
});

describe("read-only role", () => {
  it("says so once and disables the forms", () => {
    renderPage({ canManage: false });

    expect(
      screen.getAllByText(/needs the Manage Realtime permission/),
    ).toHaveLength(1);
    expect(
      screen.getByRole("button", { name: "Save and continue" }),
    ).toBeDisabled();
  });
});
