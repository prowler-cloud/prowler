import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";
import type { ProviderProps } from "@/types/providers";

import { S3IntegrationForm } from "./s3-integration-form";

const { createIntegrationMock, toastMock, updateIntegrationMock } = vi.hoisted(
  () => ({
    createIntegrationMock: vi.fn(),
    toastMock: vi.fn(),
    updateIntegrationMock: vi.fn(),
  }),
);

vi.mock("@/actions/integrations", () => ({
  createIntegration: createIntegrationMock,
  updateIntegration: updateIntegrationMock,
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
    toast: toastMock,
  }),
}));

interface MockEnhancedMultiSelectProps {
  onValueChange: (values: string[]) => void;
  options: Array<{ value: string }>;
}

vi.mock("@/components/shadcn/select/enhanced-multi-select", () => ({
  EnhancedMultiSelect: ({
    onValueChange,
    options,
  }: MockEnhancedMultiSelectProps) => (
    <button
      type="button"
      onClick={() => onValueChange(options[0] ? [options[0].value] : [])}
    >
      Select first provider
    </button>
  ),
}));

vi.mock(
  "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form",
  () => ({
    AWSRoleCredentialsForm: ({
      templateLinks,
    }: {
      templateLinks: { cloudformationQuickLink: string };
    }) => (
      <output aria-label="CloudFormation quick link">
        {templateLinks.cloudformationQuickLink}
      </output>
    ),
  }),
);

vi.mock("@/lib", () => ({
  getAWSCredentialsTemplateLinks: (
    _externalId: string,
    _bucketName: string,
    _integrationType: string,
    bucketAccountId?: string,
  ) => ({
    cloudformation: "https://example.com/cloudformation",
    terraform: "https://example.com/terraform",
    cloudformationQuickLink: `https://example.com/quick-create?bucketAccountId=${bucketAccountId ?? ""}`,
  }),
}));

function createProvider(
  provider: ProviderProps["attributes"]["provider"],
  uid: string,
): ProviderProps {
  return {
    id: `${provider}-provider`,
    type: "providers",
    attributes: {
      provider,
      is_dynamic: false,
      uid,
      alias: `${provider} provider`,
      status: "completed",
      resources: 0,
      connection: {
        connected: true,
        last_checked_at: "2026-07-16T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-07-16T00:00:00Z",
      updated_at: "2026-07-16T00:00:00Z",
      created_by: {
        object: "users",
        id: "user-1",
      },
    },
    relationships: {
      secret: {
        data: null,
      },
      provider_groups: {
        meta: {
          count: 0,
        },
        data: [],
      },
    },
  };
}

function renderS3IntegrationForm(
  props?: Partial<ComponentProps<typeof S3IntegrationForm>>,
) {
  return render(
    <S3IntegrationForm
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
    inserted_at: "2026-07-16T00:00:00Z",
    updated_at: "2026-07-16T00:00:00Z",
    enabled: true,
    connected: true,
    connection_last_checked_at: "2026-07-16T00:00:00Z",
    integration_type: "amazon_s3",
    configuration: {
      bucket_name: "prowler-reports",
      output_directory: "output",
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

describe("S3IntegrationForm", () => {
  beforeEach(() => {
    createIntegrationMock.mockReset();
    toastMock.mockReset();
    updateIntegrationMock.mockReset();
  });

  it("should require the bucket owner account ID when it cannot derive one", async () => {
    // Given
    const user = userEvent.setup();
    renderS3IntegrationForm({
      providers: [createProvider("azure", "subscription-id")],
    });

    // When
    await user.type(screen.getByLabelText(/Bucket name/i), "prowler-reports");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Then
    expect(
      await screen.findByText(
        "Bucket owner account ID is required when no AWS account is selected",
      ),
    ).toBeVisible();
    expect(
      screen.queryByLabelText("CloudFormation quick link"),
    ).not.toBeInTheDocument();
  });

  it("should derive the bucket owner account ID from the selected AWS provider", async () => {
    // Given
    const user = userEvent.setup();
    renderS3IntegrationForm({
      providers: [createProvider("aws", "123456789012")],
    });

    // When
    await user.click(
      screen.getByRole("button", { name: "Select first provider" }),
    );
    await user.type(screen.getByLabelText(/Bucket name/i), "prowler-reports");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Then
    expect(
      await screen.findByLabelText("CloudFormation quick link"),
    ).toHaveTextContent("bucketAccountId=123456789012");
  });

  it("should not show a bucket account field that configuration updates cannot persist", () => {
    // When
    renderS3IntegrationForm({
      integration,
      providers: [createProvider("aws", "123456789012")],
      editMode: "configuration",
    });

    // Then
    expect(
      screen.queryByLabelText(/Bucket owner account ID/i),
    ).not.toBeInTheDocument();
  });

  it("should allow changing the bucket owner account for credential updates", () => {
    // When
    renderS3IntegrationForm({
      integration,
      providers: [createProvider("aws", "123456789012")],
      editMode: "credentials",
    });

    // Then
    expect(
      screen.getByLabelText(/Bucket owner account ID/i),
    ).toBeInTheDocument();
  });
});
