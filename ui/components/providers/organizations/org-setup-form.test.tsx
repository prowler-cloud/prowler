import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import { ORG_SETUP_PHASE } from "@/types/organizations";

import { OrgSetupForm } from "./org-setup-form";

const {
  setApiErrorMock,
  submitOrganizationSetupMock,
  updateOrganizationNameMock,
} = vi.hoisted(() => ({
  setApiErrorMock: vi.fn(),
  submitOrganizationSetupMock: vi.fn(),
  updateOrganizationNameMock: vi.fn(),
}));

vi.mock("@/actions/organizations/organizations", () => ({
  updateOrganizationName: updateOrganizationNameMock,
}));

vi.mock("@/lib", () => ({
  getAWSOrgDeploymentQuickLink: ({
    deployFromDelegatedAdmin,
  }: {
    deployFromDelegatedAdmin?: boolean;
  }) => {
    const params = new URLSearchParams();
    if (deployFromDelegatedAdmin) {
      params.set("param_DeployFromDelegatedAdmin", "true");
    }
    return `https://console.aws.amazon.com/#/quick-create?${params.toString()}`;
  },
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: {
      tenantId: "tenant&id",
    },
  }),
}));

vi.mock("./hooks/use-org-setup-submission", () => ({
  useOrgSetupSubmission: () => ({
    apiError: null,
    setApiError: setApiErrorMock,
    submitOrganizationSetup: submitOrganizationSetupMock,
  }),
}));

function renderOrgSetupForm() {
  return render(
    <OrgSetupForm
      onBack={vi.fn()}
      onNext={vi.fn()}
      onFooterChange={vi.fn()}
      onPhaseChange={vi.fn()}
      initialPhase={ORG_SETUP_PHASE.ACCESS}
    />,
  );
}

describe("OrgSetupForm", () => {
  beforeEach(() => {
    setApiErrorMock.mockReset();
    submitOrganizationSetupMock.mockReset();
    updateOrganizationNameMock.mockReset();
    useOrgSetupStore.getState().reset();
  });

  it("should render a real disabled button until the deployment link is valid", () => {
    // Given
    renderOrgSetupForm();

    // When
    const deploymentLink = screen.queryByRole("link", {
      name: /create stack in management account/i,
    });
    const deploymentButton = screen.getByRole("button", {
      name: /create stack in management account/i,
    });

    // Then
    expect(deploymentLink).not.toBeInTheDocument();
    expect(deploymentButton).toBeDisabled();
  });

  it("should target the delegated administrator account when selected", async () => {
    // Given
    const user = userEvent.setup();
    renderOrgSetupForm();

    // When
    await user.type(
      screen.getByLabelText("Organizational Unit or Root ID"),
      "r-abcd",
    );
    await user.click(
      screen.getByRole("checkbox", {
        name: /deploying from a delegated administrator account/i,
      }),
    );

    // Then
    const deploymentLink = await screen.findByRole("link", {
      name: /create stack in delegated administrator account/i,
    });
    const hashQuery = new URL(
      deploymentLink.getAttribute("href") ?? "",
    ).hash.split("?")[1];
    const params = new URLSearchParams(hashQuery);

    expect(params.get("param_DeployFromDelegatedAdmin")).toBe("true");
    expect(
      screen.getByLabelText("Delegated Administrator Account IAM Role ARN"),
    ).toBeInTheDocument();
  });
});
