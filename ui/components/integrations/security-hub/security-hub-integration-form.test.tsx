import { render, screen } from "@testing-library/react";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";

import { SecurityHubIntegrationForm } from "./security-hub-integration-form";

vi.mock("@/actions/integrations", () => ({
  createIntegration: vi.fn(),
  updateIntegration: vi.fn(),
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: {
      tenantId: "tenant-id",
    },
  }),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

vi.mock(
  "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form",
  () => ({
    AWSRoleCredentialsForm: () => null,
  }),
);

vi.mock("@/lib", () => ({
  getAWSCredentialsTemplateLinks: () => ({
    cloudformation: "https://example.com/cloudformation",
    terraform: "https://example.com/terraform",
    cloudformationQuickLink: "https://example.com/quick-create",
  }),
}));

function renderSecurityHubIntegrationForm(
  props?: Partial<ComponentProps<typeof SecurityHubIntegrationForm>>,
) {
  return render(
    <SecurityHubIntegrationForm
      providers={[]}
      onSuccess={vi.fn()}
      onCancel={vi.fn()}
      {...props}
    />,
  );
}

const integration: IntegrationProps = {
  type: "integrations",
  id: "integration-1",
  attributes: {
    inserted_at: "2026-07-28T00:00:00Z",
    updated_at: "2026-07-28T00:00:00Z",
    enabled: true,
    connected: true,
    connection_last_checked_at: "2026-07-28T00:00:00Z",
    integration_type: "aws_security_hub",
    configuration: {
      send_only_fails: true,
      archive_previous_findings: false,
    },
  },
  relationships: {
    providers: {
      data: [{ type: "providers", id: "aws-provider" }],
    },
  },
  links: {
    self: "/integrations/integration-1",
  },
};

describe("SecurityHubIntegrationForm", () => {
  it("uses the short update label when editing configuration", () => {
    renderSecurityHubIntegrationForm({
      integration,
      editMode: "configuration",
    });

    expect(screen.getByRole("button", { name: "Update" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Update Configuration" }),
    ).not.toBeInTheDocument();
  });

  it("uses the short update label when editing credentials", () => {
    renderSecurityHubIntegrationForm({
      integration,
      editMode: "credentials",
    });

    expect(screen.getByRole("button", { name: "Update" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Update Credentials" }),
    ).not.toBeInTheDocument();
  });
});
