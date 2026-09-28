import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";

import { JiraIntegrationForm } from "./jira-integration-form";

vi.mock("@/actions/integrations", () => ({
  createIntegration: vi.fn(),
  updateIntegration: vi.fn(),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

const integration: IntegrationProps = {
  type: "integrations",
  id: "integration-1",
  attributes: {
    inserted_at: "2026-07-28T00:00:00Z",
    updated_at: "2026-07-28T00:00:00Z",
    enabled: true,
    connected: true,
    connection_last_checked_at: "2026-07-28T00:00:00Z",
    integration_type: "jira",
    configuration: {
      domain: "prowler.atlassian.net",
    },
  },
  links: {
    self: "/integrations/integration-1",
  },
};

describe("JiraIntegrationForm", () => {
  it("uses the short update label when editing credentials", () => {
    render(
      <JiraIntegrationForm
        integration={integration}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    expect(screen.getByRole("button", { name: "Update" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Update Credentials" }),
    ).not.toBeInTheDocument();
  });
});
