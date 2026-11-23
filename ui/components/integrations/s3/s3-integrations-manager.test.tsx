import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import {
  CLOUD_UPGRADE_FEATURE,
  PAID_PLAN_UPGRADE_FEATURE,
} from "@/types/cloud-upgrade";
import type { IntegrationProps } from "@/types/integrations";

import { S3IntegrationsManager } from "./s3-integrations-manager";

vi.mock("@/actions/integrations", () => ({
  createIntegration: vi.fn(),
  deleteIntegration: vi.fn(),
  revalidateIntegrationConnectionPages: vi.fn(),
  testIntegrationConnection: vi.fn(),
  updateIntegration: vi.fn(),
}));

vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: { tenantId: "tenant-id" } }),
}));

const s3Integration: IntegrationProps = {
  type: "integrations",
  id: "integration-1",
  attributes: {
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    enabled: true,
    connected: true,
    connection_last_checked_at: "2026-01-01T00:00:00Z",
    integration_type: "amazon_s3",
    configuration: {
      bucket_name: "prowler-exports",
      output_directory: "output",
    },
  },
  links: { self: "https://api.example.com/integrations/integration-1" },
};

describe("S3IntegrationsManager", () => {
  beforeEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("offers Prowler Cloud instead of adding an integration on Local Server", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const user = userEvent.setup();
    render(<S3IntegrationsManager integrations={[]} providers={[]} />);

    // When
    await user.click(screen.getByRole("button", { name: /Add Integration/ }));

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.AMAZON_S3,
    );
    expect(screen.queryByText("Add S3 Integration")).not.toBeInTheDocument();
  });

  it("opens the add form in Prowler Cloud", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();
    render(<S3IntegrationsManager integrations={[]} providers={[]} />);

    // When
    await user.click(screen.getByRole("button", { name: /Add Integration/ }));

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
    expect(await screen.findByText("Add S3 Integration")).toBeVisible();
  });

  it("offers a paid plan instead of adding an integration for a non-paying Cloud tenant", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();
    render(
      <S3IntegrationsManager
        integrations={[]}
        providers={[]}
        subscriptionOnly
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Add Integration/ }));

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      PAID_PLAN_UPGRADE_FEATURE.S3_INTEGRATION,
    );
    expect(screen.queryByText("Add S3 Integration")).not.toBeInTheDocument();
  });

  it("marks the feature as Cloud only on Local Server", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(<S3IntegrationsManager integrations={[]} providers={[]} />);

    // Then
    expect(screen.getByText("Cloud")).toBeVisible();
  });

  it("keeps existing integrations deletable on Local Server", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const user = userEvent.setup();
    render(
      <S3IntegrationsManager integrations={[s3Integration]} providers={[]} />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Delete/ }));

    // Then
    expect(await screen.findByText("Delete S3 Integration")).toBeVisible();
    expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
  });
});
