import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/actions/realtime", () => ({}));
vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_prowler_realtime: false } }),
}));
vi.mock("@/components/realtime/policy-form", () => ({
  PolicyForm: ({
    lighthouseConfigured,
    frameworkCatalog,
  }: {
    lighthouseConfigured?: boolean;
    frameworkCatalog?: unknown[];
  }) => (
    <div>
      policy form, lighthouse {String(lighthouseConfigured)}, catalog{" "}
      {frameworkCatalog?.length}
    </div>
  ),
}));
vi.mock("@/components/realtime/notifications-section", () => ({
  AlertsSection: ({ policy }: { policy: { id: string } | null }) => (
    <div>alerts section for {policy?.id ?? "no policy"}</div>
  ),
}));
vi.mock("@/components/realtime/credentials-form", () => ({
  CredentialsForm: () => <div>Credentials for remediation only</div>,
}));
vi.mock("@/components/realtime/feed-setup-panel", () => ({
  FeedSetupPanel: () => <div>Event feed setup</div>,
}));
vi.mock("@/components/realtime/use-realtime-resource", () => ({
  useRealtimeResource: (_fetcher: unknown, key: string) => ({
    loading: false,
    failure: undefined,
    reload: vi.fn(),
    setData: vi.fn(),
    data:
      key === "frameworks"
        ? [{ id: "soc2_aws", name: "SOC 2", version: "" }]
        : key.startsWith("policy")
          ? { id: "pol", frameworks: ["soc2_aws"] }
          : null,
  }),
}));

import { RealtimeSettings } from "./realtime-settings";

const providers = [
  { id: "p1", uid: "111111111111", alias: "prod" },
  { id: "p2", uid: "222222222222", alias: null },
];

describe("RealtimeSettings", () => {
  it("holds the policy, the alerts, the remediation credentials and the event feed", () => {
    render(
      <RealtimeSettings
        providers={providers}
        initialProviderId="p2"
        lighthouseConfigured
      />,
    );

    expect(
      screen.getByText(/policy form, lighthouse true, catalog 1/),
    ).toBeVisible();
    expect(screen.getByText("alerts section for pol")).toBeVisible();
    expect(screen.getByText("Credentials for remediation only")).toBeVisible();
    expect(screen.getByText("Event feed setup")).toBeVisible();
    expect(screen.getByText("Read only")).toBeVisible();
  });

  it("shows the enforced frameworks as badges", () => {
    render(<RealtimeSettings providers={providers} />);

    expect(
      screen.getByRole("list", { name: "Enforced frameworks" }),
    ).toHaveTextContent("SOC 2");
  });

  it("links to the cost anomalies page and back to the dashboard for the account", () => {
    render(<RealtimeSettings providers={providers} initialProviderId="p2" />);

    expect(
      screen.getByRole("link", { name: "Cost anomalies" }),
    ).toHaveAttribute("href", "/realtime/settings/cost-anomalies?provider=p2");
    expect(
      screen.getByRole("link", { name: "Back to the dashboard" }),
    ).toHaveAttribute("href", "/realtime?provider=p2");
  });

  it("asks for an AWS account first when there is none", () => {
    render(<RealtimeSettings providers={[]} />);

    expect(screen.getByText("Connect an AWS account first")).toBeVisible();
  });
});
