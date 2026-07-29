import { act, renderHook } from "@testing-library/react";
import { createElement, type PropsWithChildren, StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import {
  APPLY_STATUS,
  DISCOVERY_STATUS,
  ORGANIZATION_TYPE,
} from "@/types/organizations";

import { useOrgSetupSubmission } from "./use-org-setup-submission";

const organizationsActionsMock = vi.hoisted(() => ({
  createOrganization: vi.fn(),
  createOrganizationSecret: vi.fn(),
  getDiscovery: vi.fn(),
  listOrganizationsByExternalId: vi.fn(),
  listOrganizationSecretsByOrganizationId: vi.fn(),
  triggerDiscovery: vi.fn(),
  updateOrganizationSecret: vi.fn(),
}));

const AWS_DISCOVERY_RESULT = {
  roots: [{ id: "r-root", arn: "arn:root", name: "Root", policy_types: [] }],
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
        organization_node_relation: "not_applicable",
        provider_secret_state: "will_create",
        apply_status: "ready",
        blocked_reasons: [],
      },
    },
  ],
};

function mockFreshSetupChain() {
  organizationsActionsMock.listOrganizationsByExternalId.mockResolvedValue({
    data: [],
  });
  organizationsActionsMock.createOrganization.mockResolvedValue({
    data: { id: "org-1" },
  });
  organizationsActionsMock.listOrganizationSecretsByOrganizationId.mockResolvedValue(
    { data: [] },
  );
  organizationsActionsMock.createOrganizationSecret.mockResolvedValue({
    data: { id: "secret-1" },
  });
  organizationsActionsMock.triggerDiscovery.mockResolvedValue({
    data: { id: "discovery-1" },
  });
}

vi.mock(
  "@/actions/organizations/organizations",
  () => organizationsActionsMock,
);

function StrictModeWrapper({ children }: PropsWithChildren) {
  return createElement(StrictMode, null, children);
}

/** Mocks the chain up to (and including) triggering discovery, all succeeding. */
function mockChainThroughDiscoveryTrigger() {
  organizationsActionsMock.listOrganizationsByExternalId.mockResolvedValue({
    data: [],
  });
  organizationsActionsMock.createOrganization.mockResolvedValue({
    data: { id: "org-1" },
  });
  organizationsActionsMock.listOrganizationSecretsByOrganizationId.mockResolvedValue(
    { data: [] },
  );
  organizationsActionsMock.createOrganizationSecret.mockResolvedValue({
    data: { id: "secret-1" },
  });
  organizationsActionsMock.triggerDiscovery.mockResolvedValue({
    data: { id: "discovery-1" },
  });
}

const AWS_SETUP_DATA = {
  orgType: ORGANIZATION_TYPE.AWS,
  organizationName: "Acme",
  awsOrgId: "o-abc123def4",
  roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
} as const;

const UNEXPECTED_DISCOVERY_RESULT =
  "The organization was authenticated, but its discovery result could not be read. Please try again.";

describe("useOrgSetupSubmission", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useOrgSetupStore.getState().reset();
    for (const mockFn of Object.values(organizationsActionsMock)) {
      mockFn.mockReset();
    }
  });

  it("completes the setup chain and stores selectable candidates", async () => {
    // Given
    const onNext = vi.fn();
    const setFieldError = vi.fn();
    const discoveryResult = {
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
            organization_node_relation: "not_applicable",
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
            organization_node_relation: "not_applicable",
            provider_secret_state: "will_create",
            apply_status: APPLY_STATUS.BLOCKED,
            blocked_reasons: ["Already linked"],
          },
        },
      ],
    };

    organizationsActionsMock.listOrganizationsByExternalId.mockResolvedValue({
      data: [],
    });
    organizationsActionsMock.createOrganization.mockResolvedValue({
      data: { id: "org-1" },
    });
    organizationsActionsMock.listOrganizationSecretsByOrganizationId.mockResolvedValue(
      {
        data: [],
      },
    );
    organizationsActionsMock.createOrganizationSecret.mockResolvedValue({
      data: { id: "secret-1" },
    });
    organizationsActionsMock.triggerDiscovery.mockResolvedValue({
      data: { id: "discovery-1" },
    });
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.SUCCEEDED,
          result: discoveryResult,
        },
      },
    });

    const { result } = renderHook(
      () =>
        useOrgSetupSubmission({
          stackSetExternalId: "tenant-external-id",
          onNext,
          setFieldError,
        }),
      { wrapper: StrictModeWrapper },
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.AWS,
        organizationName: "Acme",
        awsOrgId: "o-abc123def4",
        roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
      });
    });

    // Then
    expect(onNext).toHaveBeenCalledTimes(1);
    expect(setFieldError).not.toHaveBeenCalled();

    const state = useOrgSetupStore.getState();
    expect(state.organizationId).toBe("org-1");
    expect(state.organizationExternalId).toBe("o-abc123def4");
    expect(state.discoveryId).toBe("discovery-1");
    expect(state.selectedCandidateIds).toEqual(["111111111111"]);
    expect(state.selectableCandidateIds).toEqual(["111111111111"]);
  });

  it("times out then resumes the same discovery via keep waiting", async () => {
    // Given — a discovery that stays running until the client budget is spent.
    vi.useFakeTimers();
    const onNext = vi.fn();
    const setFieldError = vi.fn();
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: { attributes: { status: DISCOVERY_STATUS.RUNNING, result: {} } },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError,
      }),
    );

    // When — polling exhausts its 60 × 3s budget.
    let submitPromise: Promise<void>;
    await act(async () => {
      submitPromise = result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.AWS,
        awsOrgId: "o-abc123def4",
        roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
      });
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000 * 61);
      await submitPromise;
    });

    // Then — the two-action timeout state is surfaced, not an error.
    expect(result.current.discoveryTimedOut).toBe(true);
    expect(onNext).not.toHaveBeenCalled();

    // When — keep waiting and the discovery has since succeeded.
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.SUCCEEDED,
          result: AWS_DISCOVERY_RESULT,
        },
      },
    });
    await act(async () => {
      await result.current.keepWaitingForDiscovery();
    });

    // Then — resumes the SAME discovery (no new trigger) and advances.
    expect(onNext).toHaveBeenCalledTimes(1);
    expect(result.current.discoveryTimedOut).toBe(false);
    expect(organizationsActionsMock.triggerDiscovery).toHaveBeenCalledTimes(1);
    expect(useOrgSetupStore.getState().selectedCandidateIds).toEqual([
      "111111111111",
    ]);
    vi.useRealTimers();
  });

  it("retry triggers a fresh discovery after a failed one", async () => {
    // Given — a discovery that completes as failed.
    const onNext = vi.fn();
    const setFieldError = vi.fn();
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValueOnce({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.FAILED,
          error: "boom",
          result: {},
        },
      },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError,
      }),
    );

    await act(async () => {
      await result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.AWS,
        awsOrgId: "o-abc123def4",
        roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
      });
    });

    // Then — failure state with a retry affordance.
    expect(result.current.discoveryFailed).toBe(true);
    expect(onNext).not.toHaveBeenCalled();

    // When — retry, and this time discovery succeeds.
    organizationsActionsMock.triggerDiscovery.mockResolvedValue({
      data: { id: "discovery-2" },
    });
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.SUCCEEDED,
          result: AWS_DISCOVERY_RESULT,
        },
      },
    });
    await act(async () => {
      await result.current.retryDiscovery();
    });

    // Then — a NEW discovery was triggered (2 total) and the flow advanced.
    expect(organizationsActionsMock.triggerDiscovery).toHaveBeenCalledTimes(2);
    expect(onNext).toHaveBeenCalledTimes(1);
    expect(result.current.discoveryFailed).toBe(false);
  });

  it("maps external_id server errors to awsOrgId field errors", async () => {
    // Given
    const onNext = vi.fn();
    const setFieldError = vi.fn();
    organizationsActionsMock.listOrganizationsByExternalId.mockResolvedValue({
      data: [],
    });
    organizationsActionsMock.createOrganization.mockResolvedValue({
      errors: [
        {
          detail: "Organization with this external_id already exists.",
          source: { pointer: "/data/attributes/external_id" },
        },
      ],
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError,
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.AWS,
        organizationName: "Acme",
        awsOrgId: "o-abc123def4",
        roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
      });
    });

    // Then
    expect(setFieldError).toHaveBeenCalledWith(
      "awsOrgId",
      "Organization with this external_id already exists.",
    );
    expect(result.current.apiError).toBe(
      "Organization with this external_id already exists.",
    );
    expect(onNext).not.toHaveBeenCalled();
    expect(
      organizationsActionsMock.createOrganizationSecret,
    ).not.toHaveBeenCalled();
  });

  it("blames the discovery result, not the credentials, when the result cannot be mapped", async () => {
    // Given — discovery succeeded, so the credentials are proven good, but the
    // payload carries no root organization and the AWS mapper throws on it.
    const onNext = vi.fn();
    mockChainThroughDiscoveryTrigger();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.SUCCEEDED,
          result: { roots: [], organizational_units: [], accounts: [] },
        },
      },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError: vi.fn(),
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup({ ...AWS_SETUP_DATA });
    });

    // Then — must not send the user off to re-check a Role ARN that works.
    expect(result.current.apiError).toBe(UNEXPECTED_DISCOVERY_RESULT);
    expect(result.current.apiError).not.toMatch(/Role ARN/);
    expect(onNext).not.toHaveBeenCalled();
  });

  it("reports a discovery poll response with no payload without blaming credentials", async () => {
    // Given — a 200 with no body makes the response helper return `{success: true}`,
    // which used to throw while reading the status and surface as an auth failure.
    const onNext = vi.fn();
    mockChainThroughDiscoveryTrigger();
    organizationsActionsMock.getDiscovery.mockResolvedValue({ success: true });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError: vi.fn(),
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup({ ...AWS_SETUP_DATA });
    });

    // Then
    expect(result.current.apiError).toBe(UNEXPECTED_DISCOVERY_RESULT);
    expect(onNext).not.toHaveBeenCalled();
  });
});
