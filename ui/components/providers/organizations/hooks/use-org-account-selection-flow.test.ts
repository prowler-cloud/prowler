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

vi.mock(
  "@/actions/organizations/organizations",
  () => organizationsActionsMock,
);
vi.mock("@/actions/providers/providers", () => providersActionsMock);

const TEST_ACCOUNTS = ["111111111111", "222222222222"] as const;

function setupDiscoveryAndSelection(
  selectedAccountIds: string[] = [TEST_ACCOUNTS[0]],
) {
  useOrgSetupStore
    .getState()
    .setOrganization("org-1", "My Organization", "o-abc123def4");
  useOrgSetupStore.getState().setDiscovery("discovery-1", {
    roots: [{ id: "r-root", arn: "arn:root", name: "Root", policy_types: [] }],
    organizational_units: [],
    accounts: [
      {
        id: TEST_ACCOUNTS[0],
        name: "Account One",
        arn: `arn:aws:organizations::${TEST_ACCOUNTS[0]}:account/o-123/${TEST_ACCOUNTS[0]}`,
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
        id: TEST_ACCOUNTS[1],
        name: "Account Two",
        arn: `arn:aws:organizations::${TEST_ACCOUNTS[1]}:account/o-123/${TEST_ACCOUNTS[1]}`,
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
  useOrgSetupStore.getState().setSelectedAccountIds(selectedAccountIds);
}

function buildApplySuccessResult(accountIds: string[]) {
  const accountProviderMappings = accountIds.map((accountId, index) => ({
    account_id: accountId,
    provider_id: `provider-${String.fromCharCode(97 + index)}`,
  }));
  const providers = accountProviderMappings.map((mapping) => ({
    id: mapping.provider_id,
  }));

  return {
    data: {
      attributes: {
        account_provider_mappings: accountProviderMappings,
      },
      relationships: {
        providers: {
          data: providers,
        },
      },
    },
  };
}

describe("useOrgAccountSelectionFlow", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useOrgSetupStore.getState().reset();
    organizationsActionsMock.applyDiscovery.mockReset();
    providersActionsMock.checkConnectionProvider.mockReset();
    providersActionsMock.getProvider.mockReset();
    setupDiscoveryAndSelection();
  });

  it("applies selected accounts, tests all connections, and advances on full success", async () => {
    // Given
    organizationsActionsMock.applyDiscovery.mockResolvedValue(
      buildApplySuccessResult([TEST_ACCOUNTS[0]]),
    );
    providersActionsMock.checkConnectionProvider.mockResolvedValue({
      data: {},
    });
    const onNext = vi.fn();
    const onFooterChange = vi.fn();
    let latestFooterConfig: {
      onAction?: () => void;
    } | null = null;
    onFooterChange.mockImplementation((config) => {
      latestFooterConfig = config;
    });

    renderHook(() =>
      useOrgAccountSelectionFlow({
        onBack: vi.fn(),
        onNext,
        onSkip: vi.fn(),
        onFooterChange,
      }),
    );

    // When
    await waitFor(() => {
      expect(latestFooterConfig?.onAction).toBeDefined();
    });
    act(() => {
      latestFooterConfig?.onAction?.();
    });

    // Then
    await waitFor(() => {
      expect(organizationsActionsMock.applyDiscovery).toHaveBeenCalledWith(
        "org-1",
        "discovery-1",
        [{ id: TEST_ACCOUNTS[0] }],
        [],
      );
      expect(
        providersActionsMock.checkConnectionProvider,
      ).toHaveBeenCalledTimes(1);
      expect(onNext).toHaveBeenCalledTimes(1);
    });
  });

  it("retests only failed providers when retrying without changing account selection", async () => {
    // Given
    setupDiscoveryAndSelection([...TEST_ACCOUNTS]);
    organizationsActionsMock.applyDiscovery.mockResolvedValue(
      buildApplySuccessResult([...TEST_ACCOUNTS]),
    );
    const testedProviderIds: string[] = [];
    const providerAttempts: Record<string, number> = {};
    providersActionsMock.checkConnectionProvider.mockImplementation(
      async (formData: FormData) => {
        const providerId = String(formData.get("providerId"));
        testedProviderIds.push(providerId);
        providerAttempts[providerId] = (providerAttempts[providerId] ?? 0) + 1;

        if (providerId === "provider-a" && providerAttempts[providerId] === 1) {
          return { error: "Connection failed." };
        }
        return { data: {} };
      },
    );
    const onNext = vi.fn();
    const onFooterChange = vi.fn();
    let latestFooterConfig: {
      onAction?: () => void;
      actionDisabled?: boolean;
    } | null = null;
    onFooterChange.mockImplementation((config) => {
      latestFooterConfig = config;
    });

    renderHook(() =>
      useOrgAccountSelectionFlow({
        onBack: vi.fn(),
        onNext,
        onSkip: vi.fn(),
        onFooterChange,
      }),
    );

    // When
    await waitFor(() => {
      expect(latestFooterConfig?.onAction).toBeDefined();
      expect(latestFooterConfig?.actionDisabled).toBe(false);
    });
    act(() => {
      latestFooterConfig?.onAction?.();
    });

    await waitFor(() => {
      expect(
        providersActionsMock.checkConnectionProvider,
      ).toHaveBeenCalledTimes(2);
    });

    act(() => {
      latestFooterConfig?.onAction?.();
    });

    // Then
    await waitFor(() => {
      expect(organizationsActionsMock.applyDiscovery).toHaveBeenCalledTimes(1);
      expect(
        providersActionsMock.checkConnectionProvider,
      ).toHaveBeenCalledTimes(3);
      expect(onNext).toHaveBeenCalledTimes(1);
    });
    expect(testedProviderIds.filter((id) => id === "provider-a")).toHaveLength(
      2,
    );
    expect(testedProviderIds.filter((id) => id === "provider-b")).toHaveLength(
      1,
    );
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

  it("uses latest selected accounts when applying discovery", async () => {
    // Given
    setupDiscoveryAndSelection([TEST_ACCOUNTS[0]]);
    organizationsActionsMock.applyDiscovery.mockResolvedValue(
      buildApplySuccessResult([TEST_ACCOUNTS[1]]),
    );
    providersActionsMock.checkConnectionProvider.mockResolvedValue({
      data: {},
    });
    const onFooterChange = vi.fn();
    let latestFooterConfig: {
      onAction?: () => void;
    } | null = null;
    onFooterChange.mockImplementation((config) => {
      latestFooterConfig = config;
    });

    renderHook(() =>
      useOrgAccountSelectionFlow({
        onBack: vi.fn(),
        onNext: vi.fn(),
        onSkip: vi.fn(),
        onFooterChange,
      }),
    );

    // When
    act(() => {
      useOrgSetupStore.getState().setSelectedAccountIds([TEST_ACCOUNTS[1]]);
    });
    await waitFor(() => {
      expect(latestFooterConfig?.onAction).toBeDefined();
    });
    act(() => {
      latestFooterConfig?.onAction?.();
    });

    // Then
    await waitFor(() => {
      expect(organizationsActionsMock.applyDiscovery).toHaveBeenCalledWith(
        "org-1",
        "discovery-1",
        [{ id: TEST_ACCOUNTS[1] }],
        [],
      );
    });
  });
});
