import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getPolicy, tab } = vi.hoisted(() => ({
  getPolicy: vi.fn(),
  tab:
    (name: string) =>
    ({ providerId, demo }: { providerId: string; demo?: boolean }) => (
      <div>
        {name} for [{providerId}] demo={String(demo)}
      </div>
    ),
}));

vi.mock("@/actions/realtime", () => ({ getRealtimePolicy: getPolicy }));

vi.mock("@/components/realtime/findings-tab", () => ({
  FindingsTab: tab("findings"),
}));
vi.mock("@/components/realtime/remediation-tab", () => ({
  RemediationTab: tab("remediation"),
}));
vi.mock("@/components/realtime/status-statement-card", () => ({
  StatusStatementCard: tab("status"),
}));
vi.mock("@/components/realtime/stream-tab", () => ({
  StreamTab: tab("stream"),
}));
vi.mock("@/components/realtime/overview-tab", () => ({
  OverviewTab: tab("overview"),
}));
vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_prowler_realtime: false } }),
}));

import {
  providerLabel,
  RealtimeWorkspace,
  resolveProviderId,
} from "./realtime-workspace";

const providers = [
  { id: "p1", uid: "111111111111", alias: "prod" },
  { id: "p2", uid: "222222222222", alias: null },
];

const policy = (enabled: boolean) => ({
  ok: true,
  data: { id: "pol", provider_id: "p2", enabled },
});

const BANNER = /DEMO DATA/;

describe("RealtimeWorkspace", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getPolicy.mockResolvedValue(policy(true));
  });

  it("shows demo data with a banner when there is no AWS provider at all", async () => {
    render(<RealtimeWorkspace providers={[]} />);

    expect(await screen.findByText(BANNER)).toBeVisible();
    expect(screen.getByText("overview for [] demo=true")).toBeVisible();
    expect(getPolicy).not.toHaveBeenCalled();
    expect(
      screen.getByRole("link", { name: "Set up Prowler Realtime" }),
    ).toHaveAttribute("href", "/realtime/setup");
    expect(
      screen.getByRole("link", { name: "Go to Providers" }),
    ).toHaveAttribute("href", "/providers");
    expect(screen.queryByText("Configure")).not.toBeInTheDocument();
  });

  it("is a demo while the selected account has no policy", async () => {
    getPolicy.mockResolvedValue({ ok: true, data: null });
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    expect(await screen.findByText(BANNER)).toBeVisible();
    expect(screen.getByText("overview for [p2] demo=true")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Set up Prowler Realtime" }),
    ).toHaveAttribute("href", "/realtime/setup?provider=p2");
  });

  it("is a demo while the policy exists but is not enabled, on every tab", async () => {
    const user = userEvent.setup();
    getPolicy.mockResolvedValue(policy(false));
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    for (const [name, marker] of [
      ["Overview", "overview"],
      ["Live stream", "stream"],
      ["Findings & signals", "findings"],
      ["Remediation", "remediation"],
      ["Status", "status"],
    ]) {
      await user.click(await screen.findByRole("tab", { name }));
      expect(screen.getByRole("status", { name: "Demo data" })).toBeVisible();
      expect(screen.getByText(BANNER)).toBeVisible();
      expect(screen.getByText(`${marker} for [p2] demo=true`)).toBeVisible();
    }
  });

  it("points the banner at Lighthouse AI as a secondary way to set up", async () => {
    getPolicy.mockResolvedValue(policy(false));
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    expect(
      await screen.findByRole("link", {
        name: "Ask Lighthouse AI to set it up",
      }),
    ).toHaveAttribute("href", "/lighthouse");
  });

  it("shows the account's own data, with no banner, once the policy is enabled", async () => {
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    expect(
      await screen.findByText("overview for [p2] demo=false"),
    ).toBeVisible();
    expect(screen.queryByText(BANNER)).not.toBeInTheDocument();
    expect(getPolicy).toHaveBeenCalledWith("p2");
  });

  it("does not flash the demo while it checks the account", () => {
    getPolicy.mockReturnValue(new Promise(() => {}));
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    expect(
      screen.getByRole("status", { name: "Checking the account" }),
    ).toBeVisible();
    expect(screen.queryByText(BANNER)).not.toBeInTheDocument();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it("explains a failure to read the policy instead of guessing demo or real", async () => {
    getPolicy.mockResolvedValue({ ok: false, status: 403, error: "no" });
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    expect(
      await screen.findByText("You do not have access to this"),
    ).toBeVisible();
    expect(screen.queryByText(BANNER)).not.toBeInTheDocument();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it("opens on the provider named in the URL, read only without permission", async () => {
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    await waitFor(() =>
      expect(screen.getByText("overview for [p2] demo=false")).toBeVisible(),
    );
    expect(screen.getByText("Read only")).toBeVisible();
    expect(screen.getByRole("tab", { name: "Live stream" })).toBeVisible();
  });

  it("has no Policy tab and links to the settings of the selected account", async () => {
    render(<RealtimeWorkspace providers={providers} initialProviderId="p2" />);

    await screen.findByRole("tab", { name: "Overview" });
    expect(
      screen.queryByRole("tab", { name: "Policy" }),
    ).not.toBeInTheDocument();
    expect(screen.getAllByRole("tab").map((item) => item.textContent)).toEqual([
      "Overview",
      "Live stream",
      "Findings & signals",
      "Remediation",
      "Status",
    ]);
    expect(screen.getByRole("link", { name: "Configure" })).toHaveAttribute(
      "href",
      "/realtime/settings?provider=p2",
    );
  });

  it("falls back to the first provider for an unknown id", () => {
    expect(resolveProviderId(providers, "nope")).toBe("p1");
    expect(resolveProviderId([], "p1")).toBeUndefined();
  });

  it("labels providers with alias and account id", () => {
    expect(providerLabel(providers[0])).toBe("prod (111111111111)");
    expect(providerLabel(providers[1])).toBe("222222222222");
  });
});
