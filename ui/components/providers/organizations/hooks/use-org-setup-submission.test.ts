import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import {
  DISCOVERY_STATUS,
  ORG_SECRET_TYPE,
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

const GCP_STATIC_SUBMIT_DATA = {
  orgType: ORGANIZATION_TYPE.GCP,
  gcpOrgId: "123456789012",
  credentialMethod: ORG_SECRET_TYPE.STATIC,
  clientId: "client-id",
  clientSecret: "client-secret",
  refreshToken: "refresh-token",
} as const;

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

  it("times out then resumes the same discovery via keep waiting", async () => {
    // Given — a discovery that stays running until the client budget is spent.
    vi.useFakeTimers();
    const onNext = vi.fn();
    const setFieldError = vi.fn(() => true);
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

  it("keeps the retry affordance when the retry itself cannot be triggered", async () => {
    // Given — a failed discovery, so the retry button is showing.
    const onNext = vi.fn();
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
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
        setFieldError: vi.fn(() => true),
      }),
    );

    await act(async () => {
      await result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.AWS,
        awsOrgId: "o-abc123def4",
        roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
      });
    });
    expect(result.current.discoveryFailed).toBe(true);

    // When — the retry's own trigger call fails.
    organizationsActionsMock.triggerDiscovery.mockResolvedValue({
      error: "Rate limited",
    });
    await act(async () => {
      await result.current.retryDiscovery();
    });

    // Then — the affordance the user just clicked is still there.
    expect(result.current.apiError).toBe("Rate limited");
    expect(result.current.discoveryFailed).toBe(true);
  });

  it("reports an unreadable discovery response without blaming credentials", async () => {
    // Given — a 2xx poll response with no body, as handleApiResponse returns it.
    const onNext = vi.fn();
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({ success: true });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError: vi.fn(() => true),
      }),
    );

    await act(async () => {
      await result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.AWS,
        awsOrgId: "o-abc123def4",
        roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
      });
    });

    // Then — the credentials were accepted, so the copy must not blame them.
    expect(result.current.apiError).toContain(
      "discovery result could not be read",
    );
    expect(result.current.apiError).not.toContain("Authentication failed");
    expect(result.current.discoveryFailed).toBe(true);
    expect(onNext).not.toHaveBeenCalled();
  });

  it("reports the chain as pending while a resumed discovery is in flight", async () => {
    // Given — a discovery that times out, leaving a resume context.
    const onNext = vi.fn();
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: { attributes: { status: DISCOVERY_STATUS.RUNNING, result: {} } },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "tenant-external-id",
        onNext,
        setFieldError: vi.fn(() => true),
      }),
    );

    vi.useFakeTimers();
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
    expect(result.current.discoveryTimedOut).toBe(true);
    expect(result.current.isSubmissionPending).toBe(false);

    // When — keep waiting, without letting the resumed poll finish.
    let resumePromise: Promise<void>;
    await act(async () => {
      resumePromise = result.current.keepWaitingForDiscovery();
    });

    // Then — the forms have a flag to hang a spinner on, since react-hook-form's
    // isSubmitting is false for this path.
    expect(result.current.isSubmissionPending).toBe(true);
    expect(result.current.discoveryTimedOut).toBe(false);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000 * 61);
      await resumePromise;
    });
    expect(result.current.isSubmissionPending).toBe(false);
    vi.useRealTimers();
  });

  it("maps external_id server errors to awsOrgId field errors", async () => {
    // Given
    const onNext = vi.fn();
    const setFieldError = vi.fn(() => true);
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

  it("routes a secret field error to the form when the form owns the field", async () => {
    // Given
    const onNext = vi.fn();
    const setFieldError = vi.fn(() => true);
    mockFreshSetupChain();
    organizationsActionsMock.createOrganizationSecret.mockResolvedValue({
      error: "Invalid credentials",
      errors: [
        {
          detail: "Client id is not valid.",
          source: { pointer: "/data/attributes/secret/client_id" },
        },
      ],
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext,
        setFieldError,
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup(GCP_STATIC_SUBMIT_DATA);
    });

    // Then — the field renders it, so the banner stays clear.
    expect(setFieldError).toHaveBeenCalledWith(
      "clientId",
      "Client id is not valid.",
    );
    expect(result.current.apiError).toBeNull();
    expect(onNext).not.toHaveBeenCalled();
  });

  it("falls back to the banner when the form does not own the field", async () => {
    // Given — a form that cannot render the mapped field (reports it unhandled).
    const onNext = vi.fn();
    const setFieldError = vi.fn(() => false);
    mockFreshSetupChain();
    organizationsActionsMock.createOrganizationSecret.mockResolvedValue({
      error: "Invalid credentials",
      errors: [
        {
          detail: "Client id is not valid.",
          source: { pointer: "/data/attributes/secret/client_id" },
        },
      ],
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext,
        setFieldError,
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup(GCP_STATIC_SUBMIT_DATA);
    });

    // Then — the message surfaces in the banner instead of being swallowed.
    expect(setFieldError).toHaveBeenCalledWith(
      "clientId",
      "Client id is not valid.",
    );
    expect(result.current.apiError).toBe("Client id is not valid.");
    expect(onNext).not.toHaveBeenCalled();
  });

  // These endpoints' validation errors carry no `detail`: the message sits under
  // the offending field's own key, and the pointer stops at the attribute above it.
  it("routes a field-keyed secret error to its form field", async () => {
    // Given
    const onNext = vi.fn();
    const setFieldError = vi.fn(() => true);
    mockFreshSetupChain();
    organizationsActionsMock.createOrganizationSecret.mockResolvedValue({
      error: '{"errors":[{"service_account_key":"Invalid key."}]}',
      errors: [
        {
          service_account_key: "Invalid service account key: missing token_uri",
          source: { pointer: "/data/attributes/secret" },
        },
      ],
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext,
        setFieldError,
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup({
        orgType: ORGANIZATION_TYPE.GCP,
        gcpOrgId: "123456789012",
        credentialMethod: ORG_SECRET_TYPE.SERVICE_ACCOUNT,
        serviceAccountKey: '{"type":"service_account"}',
      });
    });

    // Then — field name from the error's own key, message from its value.
    expect(setFieldError).toHaveBeenCalledWith(
      "serviceAccountKey",
      "Service account key: Invalid service account key: missing token_uri",
    );
    expect(result.current.apiError).toBeNull();
  });

  it("never paints an empty banner for a detail-less error", async () => {
    // Given — nothing owns the field, so the banner is what renders it.
    const onNext = vi.fn();
    const setFieldError = vi.fn(() => false);
    mockFreshSetupChain();
    organizationsActionsMock.createOrganization.mockResolvedValue({
      error: '{"errors":[{"alias":"too long"}]}',
      errors: [
        {
          alias: "Ensure this field has no more than 100 characters.",
          source: { pointer: "/data/attributes" },
        },
      ],
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext,
        setFieldError,
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup(AWS_SETUP_DATA);
    });

    // Then — readable copy, not the raw JSON body the request-level message is.
    expect(result.current.apiError).toBe(
      "Alias: Ensure this field has no more than 100 characters.",
    );
    expect(result.current.apiError).not.toContain("{");
  });

  it.each([
    [
      "gcp_invalid_organization_id",
      /organization ID is not valid/,
      "invalid org id",
    ],
    [
      "gcp_service_unavailable",
      /Nothing is wrong with your credentials/,
      "an outage",
    ],
    [
      "gcp_insufficient_permissions",
      /Folder Viewer and Project Viewer/,
      "missing permissions",
    ],
  ])(
    "translates the %s discovery failure code into copy about %s",
    async (code, expectedCopy) => {
      // Given — a failed discovery reporting a machine code.
      const onNext = vi.fn();
      mockFreshSetupChain();
      organizationsActionsMock.getDiscovery.mockResolvedValue({
        data: {
          attributes: {
            status: DISCOVERY_STATUS.FAILED,
            error: code,
            result: {},
          },
        },
      });

      const { result } = renderHook(() =>
        useOrgSetupSubmission({
          stackSetExternalId: "",
          onNext,
          setFieldError: vi.fn(() => true),
        }),
      );

      // When
      await act(async () => {
        await result.current.submitOrganizationSetup(GCP_STATIC_SUBMIT_DATA);
      });

      // Then — human copy, and no snake_case token leaking into the banner.
      expect(result.current.apiError).toMatch(expectedCopy);
      expect(result.current.apiError).not.toContain(code);
      expect(result.current.discoveryFailed).toBe(true);
    },
  );

  it("does not frame a non-credential discovery failure as an auth failure", async () => {
    // Given — a Google outage, with working credentials.
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.FAILED,
          error: "gcp_service_unavailable",
          result: {},
        },
      },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext: vi.fn(),
        setFieldError: vi.fn(() => true),
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup(GCP_STATIC_SUBMIT_DATA);
    });

    // Then
    expect(result.current.apiError).not.toContain("Authentication failed");
  });

  it("keeps the auth-failure copy for an unrecognized failure code", async () => {
    // Given — a code this build has no copy for; the token is a support detail.
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.FAILED,
          error: "gcp_some_future_code",
          result: {},
        },
      },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext: vi.fn(),
        setFieldError: vi.fn(() => true),
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup(GCP_STATIC_SUBMIT_DATA);
    });

    // Then
    expect(result.current.apiError).toContain("Authentication failed");
    expect(result.current.apiError).not.toContain("gcp_some_future_code");
  });

  it("prefers the server message over the auth-failure copy for an unrecognized failure code", async () => {
    // Given — the same unknown code, but the server sent its own wording: it is
    // display-safe and more specific than "check your credentials".
    mockFreshSetupChain();
    organizationsActionsMock.getDiscovery.mockResolvedValue({
      data: {
        attributes: {
          status: DISCOVERY_STATUS.FAILED,
          error: "gcp_some_future_code",
          error_message: "The organization is being migrated. Try again later.",
          result: {},
        },
      },
    });

    const { result } = renderHook(() =>
      useOrgSetupSubmission({
        stackSetExternalId: "",
        onNext: vi.fn(),
        setFieldError: vi.fn(() => true),
      }),
    );

    // When
    await act(async () => {
      await result.current.submitOrganizationSetup(GCP_STATIC_SUBMIT_DATA);
    });

    // Then
    expect(result.current.apiError).toBe(
      "The organization is being migrated. Try again later.",
    );
  });
});
