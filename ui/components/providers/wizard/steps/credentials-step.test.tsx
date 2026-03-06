import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import { CredentialsStep } from "./credentials-step";

vi.mock("../../workflow/forms", () => ({
  AddViaCredentialsForm: () => <div>add-via-credentials-form</div>,
  AddViaRoleForm: () => <div>add-via-role-form</div>,
  UpdateViaCredentialsForm: () => <div>update-via-credentials-form</div>,
  UpdateViaRoleForm: () => <div>update-via-role-form</div>,
}));

vi.mock("../../workflow/forms/select-credentials-type/aws", () => ({
  SelectViaAWS: () => <div>select-via-aws</div>,
}));

vi.mock("../../workflow/forms/select-credentials-type/alibabacloud", () => ({
  SelectViaAlibabaCloud: () => <div>select-via-alibabacloud</div>,
}));

vi.mock("../../workflow/forms/select-credentials-type/cloudflare", () => ({
  SelectViaCloudflare: () => <div>select-via-cloudflare</div>,
}));

vi.mock("../../workflow/forms/select-credentials-type/gcp", () => ({
  AddViaServiceAccountForm: () => <div>add-via-service-account-form</div>,
  SelectViaGCP: () => <div>select-via-gcp</div>,
}));

vi.mock("../../workflow/forms/select-credentials-type/github", () => ({
  SelectViaGitHub: () => <div>select-via-github</div>,
}));

vi.mock("../../workflow/forms/select-credentials-type/m365", () => ({
  SelectViaM365: () => <div>select-via-m365</div>,
}));

vi.mock("../../workflow/forms/update-via-service-account-key-form", () => ({
  UpdateViaServiceAccountForm: () => <div>update-via-service-account-form</div>,
}));

describe("CredentialsStep", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useProviderWizardStore.getState().reset();
  });

  it("renders update role form when secret already exists in add mode", () => {
    // Given
    useProviderWizardStore.setState({
      providerId: "provider-1",
      providerType: "aws",
      providerUid: "111111111111",
      providerAlias: "Production",
      via: "role",
      secretId: "secret-1",
      mode: PROVIDER_WIZARD_MODE.ADD,
    });

    // When
    render(
      <CredentialsStep
        onNext={vi.fn()}
        onBack={vi.fn()}
        onFooterChange={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText("update-via-role-form")).toBeInTheDocument();
    expect(screen.queryByText("add-via-role-form")).not.toBeInTheDocument();
  });
});
