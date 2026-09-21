import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

import { AwsQuickFlow } from "./aws-quick-flow";
import { AWS_QUICK_STEP, AwsQuickStep } from "./types";

const {
  addProvider,
  addCredentialsProvider,
  testProviderConnection,
  scanOnDemand,
  updateProvider,
} = vi.hoisted(() => ({
  addProvider: vi.fn(),
  addCredentialsProvider: vi.fn(),
  testProviderConnection: vi.fn(),
  scanOnDemand: vi.fn(),
  updateProvider: vi.fn(),
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { tenantId: "tenant-abc" },
    status: "authenticated",
  }),
}));
vi.mock("@/actions/providers/providers", () => ({
  addProvider,
  addCredentialsProvider,
  updateCredentialsProvider: vi.fn(),
  updateProvider,
}));
vi.mock("@/actions/scans", () => ({ scanOnDemand }));
vi.mock("@/lib/provider-helpers", () => ({ testProviderConnection }));

// Stands in for the modal footer: the flow only publishes its config.
function Harness(props: Partial<React.ComponentProps<typeof AwsQuickFlow>>) {
  const [footer, setFooter] = useState<WizardFooterConfig | null>(null);
  const [step, setStep] = useState<AwsQuickStep>(AWS_QUICK_STEP.CONNECT);
  return (
    <>
      <AwsQuickFlow
        step={step}
        onStepChange={setStep}
        onBack={vi.fn()}
        onClose={vi.fn()}
        onSelectOrganizations={vi.fn()}
        onFooterChange={setFooter}
        capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        {...props}
      />
      {footer?.showAction && (
        <button
          type={footer.actionType === "submit" ? "submit" : "button"}
          form={footer.actionFormId}
          disabled={footer.actionDisabled}
          onClick={footer.actionType === "button" ? footer.onAction : undefined}
        >
          {footer.actionLabel}
        </button>
      )}
    </>
  );
}

function renderFlow(
  props: Partial<React.ComponentProps<typeof AwsQuickFlow>> = {},
) {
  const onClose = vi.fn();
  render(<Harness onClose={onClose} {...props} />);
  return { onClose };
}

const action = (name: string) => screen.getByRole("button", { name });

describe("AwsQuickFlow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    useProviderWizardStore.getState().reset();
    addProvider.mockResolvedValue({ data: { id: "provider-1" } });
    addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    testProviderConnection.mockResolvedValue({ connected: true, error: null });
    updateProvider.mockResolvedValue({ data: { id: "provider-1" } });
    scanOnDemand.mockResolvedValue({ data: { id: "scan-1" } });
  });

  it("links the quick-create stack with the tenant external id", async () => {
    const user = userEvent.setup();
    renderFlow();

    expect(
      screen.queryByRole("link", { name: /Create IAM Role & Policy/ }),
    ).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: /Create it with CloudFormation/ }),
    );

    const link = screen.getByRole("link", { name: /Create IAM Role & Policy/ });
    const href = link.getAttribute("href") ?? "";
    const params = new URLSearchParams(href.slice(href.lastIndexOf("?") + 1));

    expect(href).toContain("#/stacks/quickcreate");
    expect(params.get("param_ExternalId")).toBe("tenant-abc");
    expect(params.get("templateURL")).toContain("prowler-scan-role-quick.yml");
    expect(params.get("stackName")).toBe("ProwlerScan");
    expect(
      Array.from(params.keys()).filter((key) => key.startsWith("param_")),
    ).toEqual(["param_ExternalId"]);
    expect(screen.getByText("tenant-abc")).toBeVisible();
  });

  it("walks ARN -> test connection -> name and launches the first scan", async () => {
    const user = userEvent.setup();
    const { onClose } = renderFlow();

    const arnInput = screen.getByRole("textbox", { name: "IAM Role ARN" });
    expect(action("Test connection")).toBeDisabled();
    await user.type(arnInput, "arn:aws:iam::123456789012:role/ProwlerScan");
    expect(
      screen.getByText("Account 123456789012 will be added to Prowler."),
    ).toBeVisible();
    await waitFor(() => expect(action("Test connection")).toBeEnabled());

    await user.click(action("Test connection"));

    await waitFor(() => expect(testProviderConnection).toHaveBeenCalledOnce());
    expect(
      await screen.findByText("It worked! Everything seems to be connected."),
    ).toBeVisible();

    await user.type(
      screen.getByRole("textbox", { name: "Name (optional)" }),
      "Production",
    );
    await user.click(action("Launch scan"));

    expect(updateProvider).toHaveBeenCalledOnce();
    expect(
      Object.fromEntries(updateProvider.mock.calls[0][0].entries()),
    ).toEqual({ providerId: "provider-1", providerAlias: "Production" });
    expect(scanOnDemand).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("asks for the account id when static keys are chosen", async () => {
    const user = userEvent.setup();
    renderFlow();

    await user.click(screen.getByRole("radio", { name: "Static access keys" }));

    expect(
      screen.getByRole("textbox", { name: "AWS Account ID" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("textbox", { name: "IAM Role ARN" }),
    ).not.toBeInTheDocument();
  });

  it("shows the connection error and stays on the connect step", async () => {
    testProviderConnection.mockResolvedValueOnce({
      connected: false,
      error: "AccessDenied when calling AssumeRole",
    });
    const user = userEvent.setup();
    renderFlow();

    await user.type(
      screen.getByRole("textbox", { name: "IAM Role ARN" }),
      "arn:aws:iam::123456789012:role/ProwlerScan",
    );
    await user.click(action("Test connection"));

    await waitFor(() => expect(testProviderConnection).toHaveBeenCalledOnce());
    expect(
      await screen.findByText("AccessDenied when calling AssumeRole"),
    ).toBeVisible();
    expect(
      screen.queryByText("It worked! Everything seems to be connected."),
    ).not.toBeInTheDocument();
  });

  it("finishes without a scan when scanning is blocked", async () => {
    const user = userEvent.setup();
    const { onClose } = renderFlow({
      capability: SCAN_SCHEDULE_CAPABILITY.BLOCKED,
    });

    await user.type(
      screen.getByRole("textbox", { name: "IAM Role ARN" }),
      "arn:aws:iam::123456789012:role/ProwlerScan",
    );
    await user.click(action("Test connection"));
    await screen.findByText("It worked! Everything seems to be connected.");

    await user.click(action("Finish"));

    expect(scanOnDemand).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledOnce();
  });
});
