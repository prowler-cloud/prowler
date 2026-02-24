import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import { APPLY_STATUS } from "@/types/organizations";

import { useOrgAccountSelectionFlow } from "./use-org-account-selection-flow";

const organizationsActionsMock = vi.hoisted(() => ({
  applyDiscovery: vi.fn(),
}));

const providersActionsMock = vi.hoisted(() => ({
  checkConnectionProvider: vi.fn(),
  getProvider: vi.fn(),
}));

vi.mock("@/actions/organizations/organizations", () => organizationsActionsMock);
vi.mock("@/actions/providers/providers", () => providersActionsMock);

describe("useOrgAccountSelectionFlow", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useOrgSetupStore.getState().reset();
    organizationsActionsMock.applyDiscovery.mockReset();

    useOrgSetupStore
      .getState()
      .setOrganization("org-1", "My Organization", "o-abc123def4");
    useOrgSetupStore.getState().setDiscovery("discovery-1", {
      roots: [
        { id: "r-root", arn: "arn:root", name: "Root", policy_types: [] },
      ],
      organizational_units: [],
      accounts: [
        {
          id: "111111111111",
          name: "Account One",
          arn: "arn:aws:organizations::111111111111:account/o-123/111111111111",
          email: "one@example.com",
          status: "ACTIVE",
          joined_method: "CREATED",
          joined_timestamp: "2024-01-01T00:00:00Z",
          parent_id: "r-root",
          registration: {
            provider_exists: false,
            provider_id: null,
            organization_relation: "link_required",
            organizational_unit_relation: "not_applicable",
            provider_secret_state: "will_create",
            apply_status: APPLY_STATUS.READY,
            blocked_reasons: [],
          },
        },
        {
          id: "222222222222",
          name: "Account Two",
          arn: "arn:aws:organizations::222222222222:account/o-123/222222222222",
          email: "two@example.com",
          status: "ACTIVE",
          joined_method: "CREATED",
          joined_timestamp: "2024-01-01T00:00:00Z",
          parent_id: "r-root",
          registration: {
            provider_exists: false,
            provider_id: null,
            organization_relation: "link_required",
            organizational_unit_relation: "not_applicable",
            provider_secret_state: "will_create",
            apply_status: APPLY_STATUS.READY,
            blocked_reasons: [],
          },
        },
      ],
    });
    useOrgSetupStore.getState().setSelectedAccountIds(["111111111111"]);
  });

  it("keeps Test Connections action visible after reselection in testing view", async () => {
    // Given
    organizationsActionsMock.applyDiscovery.mockResolvedValue({
      errors: [{ detail: "Apply failed." }],
    });
    const onFooterChange = vi.fn();
    let latestFooterConfig: {
      showAction?: boolean;
      actionDisabled?: boolean;
      onAction?: () => void;
    } | null = null;
    onFooterChange.mockImplementation((config) => {
      latestFooterConfig = config;
    });

    const { result } = renderHook(() =>
      useOrgAccountSelectionFlow({
        onBack: vi.fn(),
        onNext: vi.fn(),
        onSkip: vi.fn(),
        onFooterChange,
      }),
    );

    // When
    await waitFor(() => {
      expect(latestFooterConfig?.showAction).toBe(true);
      expect(latestFooterConfig?.onAction).toBeDefined();
    });
    act(() => {
      latestFooterConfig?.onAction?.();
    });

    await waitFor(() => {
      expect(organizationsActionsMock.applyDiscovery).toHaveBeenCalledTimes(1);
    });

    act(() => {
      result.current.handleTreeSelectionChange(["222222222222"]);
    });

    // Then
    await waitFor(() => {
      expect(latestFooterConfig?.showAction).toBe(true);
      expect(latestFooterConfig?.actionDisabled).toBe(false);
      expect(latestFooterConfig?.onAction).toBeDefined();
    });
  });
});
