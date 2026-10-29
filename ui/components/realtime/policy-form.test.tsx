import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { savePolicy, toast } = vi.hoisted(() => ({
  savePolicy: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/actions/realtime", () => ({ saveRealtimePolicy: savePolicy }));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast }),
}));

import type { RealtimePolicy } from "@/types/realtime";

import { PolicyForm } from "./policy-form";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

const savedPolicy: RealtimePolicy = {
  id: "p1",
  provider_id: PROVIDER,
  enabled: false,
  mode: "pr",
  dry_run: true,
  min_severity: "low",
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
    min_severity: "high",
    slack: { enabled: false, channel_ids: [] },
    email: { enabled: false, recipient_ids: [] },
  },
};

const CATALOG = [
  { id: "soc2_aws", name: "SOC 2", version: "2017" },
  { id: "pci_4.0_aws", name: "PCI DSS", version: "4.0" },
  { id: "cis_5.0_aws", name: "CIS Foundations", version: "5.0" },
  { id: "hipaa_aws", name: "HIPAA", version: "" },
  { id: "gdpr_aws", name: "GDPR", version: "" },
  { id: "nist_aws", name: "NIST 800-53", version: "r5" },
];

describe("PolicyForm", () => {
  beforeEach(() => {
    savePolicy.mockResolvedValue({ ok: true, data: savedPolicy });
  });

  it("starts from the safe defaults", () => {
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    expect(screen.getByRole("switch", { name: /dry run/i })).toBeChecked();
    expect(
      screen.getByRole("switch", { name: /enable prowler realtime/i }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("radio", { name: /propose a change/i }),
    ).toBeChecked();
  });

  it("is read only without the permission", () => {
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage={false}
        onSaved={vi.fn()}
      />,
    );

    expect(screen.getByText("Read only")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /dry run/i })).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: /save policy/i }),
    ).not.toBeInTheDocument();
  });

  it("warns when dry run is turned off in auto mode", async () => {
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("radio", { name: /fix automatically/i }));
    expect(screen.queryByText("Dry run is off")).not.toBeInTheDocument();
    await user.click(screen.getByRole("switch", { name: /dry run/i }));

    expect(screen.getByText("Dry run is off")).toBeInTheDocument();
  });

  it("shows a validation error and does not call the API for a bad repository", async () => {
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.type(screen.getByLabelText("GitHub repository"), "not-a-repo");
    await user.click(screen.getByRole("button", { name: /save policy/i }));

    expect(await screen.findByText('Use the "owner/repo" form.')).toBeVisible();
    expect(savePolicy).not.toHaveBeenCalled();
  });

  it("limits the scope to ten tags", async () => {
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    const add = screen.getByRole("button", { name: "Add tag" });
    for (let i = 0; i < 10; i += 1) await user.click(add);

    expect(screen.getAllByLabelText(/^Tag key/)).toHaveLength(10);
    expect(
      screen.getByRole("button", { name: /limit of 10 tags reached/i }),
    ).toBeDisabled();
  });

  it("sends the scope, lists and settings it was given", async () => {
    const user = userEvent.setup();
    const onSaved = vi.fn();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={onSaved}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Add tag" }));
    await user.type(screen.getByLabelText("Tag key 1"), "env");
    await user.type(screen.getByLabelText("Tag value 1"), "prod");
    await user.type(
      screen.getByLabelText("Allowed regions"),
      "eu-west-1, us-east-1",
    );
    await user.click(screen.getByRole("button", { name: /save policy/i }));

    await waitFor(() => expect(savePolicy).toHaveBeenCalled());
    expect(savePolicy.mock.calls[0][0]).toMatchObject({
      providerId: PROVIDER,
      policy: {
        scope_tags: { env: "prod" },
        allow_regions: ["eu-west-1", "us-east-1"],
        mode: "pr",
        dry_run: true,
      },
    });
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(savedPolicy));
  });

  it("asks for confirmation before going live in the account", async () => {
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(
      screen.getByRole("switch", { name: /enable prowler realtime/i }),
    );
    await user.click(screen.getByRole("radio", { name: /fix automatically/i }));
    await user.click(screen.getByRole("switch", { name: /dry run/i }));
    await user.click(screen.getByRole("button", { name: /save policy/i }));

    expect(
      await screen.findByText("Let Prowler Realtime change your AWS account?"),
    ).toBeVisible();
    expect(savePolicy).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole("button", { name: /enable live fixes/i }),
    );
    await waitFor(() => expect(savePolicy).toHaveBeenCalledTimes(1));
    expect(savePolicy.mock.calls[0][0].policy).toMatchObject({
      mode: "auto",
      dry_run: false,
      enabled: true,
    });
  });

  it("explains a 403 from the API", async () => {
    savePolicy.mockResolvedValue({ ok: false, status: 403, error: "no" });
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /save policy/i }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "You cannot change the policy" }),
      ),
    );
  });
  it("keeps the cost anomaly settings of a loaded policy when saving it", async () => {
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={{
          ...savedPolicy,
          cost_anomaly_enabled: true,
          cost_anomaly_min_ratio: 3.5,
          cost_anomaly_min_delta: 12,
        }}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /save policy/i }));

    await waitFor(() => expect(savePolicy).toHaveBeenCalled());
    expect(savePolicy.mock.calls[0][0].policy).toMatchObject({
      cost_anomaly_enabled: true,
      cost_anomaly_min_ratio: 3.5,
      cost_anomaly_min_delta: 12,
    });
  });

  it("selects up to five frameworks with search and removes them with the chip", async () => {
    const user = userEvent.setup();
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
        frameworkCatalog={CATALOG}
      />,
    );
    const search = screen.getByLabelText("Enforce compliance frameworks");

    await user.type(search, "soc");
    await user.click(screen.getByRole("button", { name: /SOC 2/ }));
    expect(
      screen.getByRole("list", { name: "Enforced frameworks" }),
    ).toHaveTextContent("SOC 2");

    await user.click(screen.getByRole("button", { name: /PCI DSS/ }));
    await user.click(screen.getByRole("button", { name: /CIS Foundations/ }));
    await user.click(screen.getByRole("button", { name: /^HIPAA/ }));
    await user.click(screen.getByRole("button", { name: /GDPR/ }));

    // Five chosen: the search is closed and the limit is stated.
    expect(search).toBeDisabled();
    expect(
      screen.queryByRole("list", { name: "Available frameworks" }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Remove GDPR" }));
    expect(search).toBeEnabled();

    await user.click(screen.getByRole("button", { name: /save policy/i }));
    await waitFor(() => expect(savePolicy).toHaveBeenCalled());
    expect(savePolicy.mock.calls[0][0].policy.frameworks).toEqual([
      "soc2_aws",
      "pci_4.0_aws",
      "cis_5.0_aws",
      "hipaa_aws",
    ]);
  });

  it("explains what enforcing frameworks does, and that empty means every check", () => {
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
        frameworkCatalog={CATALOG}
      />,
    );

    expect(
      screen.getByText(/acts only on checks that belong to them/),
    ).toBeVisible();
    expect(screen.getByText(/about every 10 minutes/)).toBeVisible();
    expect(
      screen.getByText(/No framework selected: every check is in scope/),
    ).toBeVisible();
  });

  it("shows a saved framework as a chip even when the catalog is missing", () => {
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={{ ...savedPolicy, frameworks: ["soc2_aws"] }}
        canManage
        onSaved={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Remove soc2_aws" }),
    ).toBeVisible();
  });

  it("switches Lighthouse AI code fixes, links to its settings and warns without a configuration", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
        lighthouseConfigured={false}
      />,
    );
    const toggle = screen.getByRole("switch", {
      name: /let lighthouse ai write the code change/i,
    });

    expect(toggle).toBeChecked();
    expect(
      screen.getByText("No Lighthouse AI configuration connected"),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: /lighthouse ai settings/i }),
    ).toHaveAttribute("href", "/lighthouse/settings");
    expect(screen.getByText(/sent to that LLM provider/)).toBeVisible();

    rerender(
      <PolicyForm
        providerId={PROVIDER}
        policy={null}
        canManage
        onSaved={vi.fn()}
        lighthouseConfigured
      />,
    );
    expect(
      screen.queryByText("No Lighthouse AI configuration connected"),
    ).not.toBeInTheDocument();

    await user.click(toggle);
    await user.click(screen.getByRole("button", { name: /save policy/i }));
    await waitFor(() => expect(savePolicy).toHaveBeenCalled());
    expect(savePolicy.mock.calls[0][0].policy.use_lighthouse).toBe(false);
  });

  it("carries the alert settings unchanged in the whole-policy save", async () => {
    const user = userEvent.setup();
    const notifications = {
      min_severity: "critical" as const,
      slack: { enabled: true, channel_ids: ["C1"] },
      email: { enabled: true, recipient_ids: ["r1"] },
    };
    render(
      <PolicyForm
        providerId={PROVIDER}
        policy={{ ...savedPolicy, notifications }}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /save policy/i }));

    await waitFor(() => expect(savePolicy).toHaveBeenCalled());
    expect(savePolicy.mock.calls[0][0].policy.notifications).toEqual(
      notifications,
    );
  });

  it("sends what is stored now for the alerts and cost, not what it loaded", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <PolicyForm
        providerId={PROVIDER}
        policy={savedPolicy}
        canManage
        onSaved={vi.fn()}
      />,
    );
    const newer = {
      ...savedPolicy,
      cost_anomaly_enabled: true,
      notifications: {
        min_severity: "low" as const,
        slack: { enabled: true, channel_ids: ["C9"] },
        email: { enabled: false, recipient_ids: [] },
      },
    };
    // Another section saved meanwhile and the page handed the form the result.
    rerender(
      <PolicyForm
        providerId={PROVIDER}
        policy={newer}
        canManage
        onSaved={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: /save policy/i }));

    await waitFor(() => expect(savePolicy).toHaveBeenCalled());
    expect(savePolicy.mock.calls[0][0].policy).toMatchObject({
      cost_anomaly_enabled: true,
      notifications: newer.notifications,
    });
  });
});
