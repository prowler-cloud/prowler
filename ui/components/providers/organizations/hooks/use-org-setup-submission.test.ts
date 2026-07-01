import { act, renderHook } from "@testing-library/react";
import { createElement, type PropsWithChildren, StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import { APPLY_STATUS, DISCOVERY_STATUS } from "@/types/organizations";

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

vi.mock(
  "@/actions/organizations/organizations",
  () => organizationsActionsMock,
);

function StrictModeWrapper({ children }: PropsWithChildren) {
  return createElement(StrictMode, null, children);
}

describe("useOrgSetupSubmission", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useOrgSetupStore.getState().reset();
    for (const mockFn of Object.values(organizationsActionsMock)) {
      mockFn.mockReset();
    }
  });

  it("completes the setup chain and stores selectable accounts", async () => {
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
    expect(state.selectedAccountIds).toEqual(["111111111111"]);
    expect(state.selectableAccountIds).toEqual(["111111111111"]);
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
});
