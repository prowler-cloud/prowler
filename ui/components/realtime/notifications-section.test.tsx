import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { getTargets, saveNotifications, toast } = vi.hoisted(() => ({
  getTargets: vi.fn(),
  saveNotifications: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/actions/realtime", () => ({
  getRealtimeNotificationTargets: getTargets,
  saveRealtimeNotifications: saveNotifications,
}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast }),
}));

import type { RealtimePolicy } from "@/types/realtime";

import { AlertsSection } from "./notifications-section";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

const policy = {
  id: "pol-1",
  provider_id: PROVIDER,
  notifications: {
    min_severity: "high",
    slack: { enabled: false, channel_ids: [] },
    email: { enabled: false, recipient_ids: [] },
  },
} as unknown as RealtimePolicy;

const TARGETS = {
  slack: [
    { integration_id: "i1", channel_id: "C1", name: "security" },
    { integration_id: "i1", channel_id: "C2", name: "ops" },
  ],
  email: [
    { id: "r1", email: "ana@example.com", status: "confirmed" },
    { id: "r2", email: "bob@example.com", status: "pending" },
    { id: "r3", email: "cy@example.com", status: "bounced" },
  ],
};

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

const renderSection = (
  overrides: Partial<React.ComponentProps<typeof AlertsSection>> = {},
) =>
  render(
    <AlertsSection
      providerId={PROVIDER}
      policy={policy}
      canManage
      onSaved={vi.fn()}
      {...overrides}
    />,
  );

describe("AlertsSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getTargets.mockResolvedValue({ ok: true, data: TARGETS });
    saveNotifications.mockResolvedValue({ ok: true, data: policy });
  });

  it("explains when alerts go out and that nothing is sent until a channel is on", async () => {
    renderSection();

    expect(await screen.findByText("When an alert goes out")).toBeVisible();
    expect(screen.getByText(/confirmed violation/)).toBeVisible();
    expect(screen.getByText(/result of a verified fix/)).toBeVisible();
    expect(
      screen.getByText(/Nothing is sent until you turn a channel on/),
    ).toBeVisible();
    expect(screen.getByRole("switch", { name: /slack/i })).not.toBeChecked();
    expect(screen.getByRole("switch", { name: /email/i })).not.toBeChecked();
  });

  it("links to where destinations are created", async () => {
    renderSection();

    await screen.findByText("When an alert goes out");
    expect(
      screen.getAllByRole("link", { name: "Integrations" })[0],
    ).toHaveAttribute("href", "/integrations");
    expect(screen.getAllByRole("link", { name: "Alerts" })[0]).toHaveAttribute(
      "href",
      "/alerts",
    );
  });

  it("offers the channels once Slack is on and saves the selection with the severity", async () => {
    const user = userEvent.setup();
    const onSaved = vi.fn();
    renderSection({ onSaved });

    await user.click(await screen.findByRole("switch", { name: /slack/i }));
    await user.click(screen.getByRole("checkbox", { name: "#security" }));
    await user.click(screen.getByRole("button", { name: "Save alerts" }));

    await waitFor(() => expect(saveNotifications).toHaveBeenCalled());
    expect(saveNotifications).toHaveBeenCalledWith({
      providerId: PROVIDER,
      policyId: "pol-1",
      notifications: {
        min_severity: "high",
        slack: { enabled: true, channel_ids: ["C1"] },
        email: { enabled: false, recipient_ids: [] },
      },
    });
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(policy));
  });

  it("lets only confirmed recipients be selected and shows the others disabled with their status", async () => {
    const user = userEvent.setup();
    renderSection();

    await user.click(await screen.findByRole("switch", { name: /email/i }));

    expect(
      screen.getByRole("checkbox", { name: "ana@example.com" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("checkbox", { name: "bob@example.com" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "cy@example.com" }),
    ).toBeDisabled();
    expect(screen.getByText("Pending")).toBeVisible();
    expect(screen.getByText("Bounced")).toBeVisible();
  });

  it("refuses a turned-on channel with nothing selected, without calling the API", async () => {
    const user = userEvent.setup();
    renderSection();

    await user.click(await screen.findByRole("switch", { name: /slack/i }));
    await user.click(screen.getByRole("button", { name: "Save alerts" }));

    expect(
      await screen.findByText(/Select at least one Slack channel/),
    ).toBeVisible();
    expect(saveNotifications).not.toHaveBeenCalled();
  });

  it("shows the API's message when a destination is rejected", async () => {
    const user = userEvent.setup();
    saveNotifications.mockResolvedValue({
      ok: false,
      status: 400,
      error: "Recipient r1 is not confirmed.",
      fieldErrors: { notifications: "Recipient r1 is not confirmed." },
    });
    renderSection();

    await user.click(await screen.findByRole("switch", { name: /email/i }));
    await user.click(screen.getByRole("checkbox", { name: "ana@example.com" }));
    await user.click(screen.getByRole("button", { name: "Save alerts" }));

    expect(
      await screen.findByText("Recipient r1 is not confirmed."),
    ).toBeVisible();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Could not save the alerts" }),
    );
  });

  it("points at Integrations and Alerts when there is nowhere to send to", async () => {
    const user = userEvent.setup();
    getTargets.mockResolvedValue({ ok: true, data: { slack: [], email: [] } });
    renderSection();

    await user.click(await screen.findByRole("switch", { name: /slack/i }));
    expect(screen.getByText(/No Slack channel is available/)).toBeVisible();
    await user.click(screen.getByRole("switch", { name: /email/i }));
    expect(screen.getByText(/No recipient exists yet/)).toBeVisible();
  });

  it("keeps a selection whose destination vanished removable", async () => {
    renderSection({
      policy: {
        ...policy,
        notifications: {
          ...policy.notifications,
          slack: { enabled: true, channel_ids: ["C-gone"] },
        },
      },
    });

    expect(
      await screen.findByRole("checkbox", { name: "C-gone" }),
    ).toBeChecked();
    expect(screen.getByText("No longer available")).toBeVisible();
  });

  it("is read only without the permission", async () => {
    renderSection({ canManage: false });

    expect(
      await screen.findByRole("switch", { name: /slack/i }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Save alerts" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/needs the Manage Realtime permission/),
    ).toBeVisible();
  });

  it("explains a 503 or 403 loading the destinations", async () => {
    getTargets.mockResolvedValue({ ok: false, status: 403, error: "no" });
    renderSection();

    expect(
      await screen.findByText("You do not have access to this"),
    ).toBeVisible();
  });
});
