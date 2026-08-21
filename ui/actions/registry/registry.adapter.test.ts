import { describe, expect, it } from "vitest";

import {
  REGISTRY_ENDPOINT,
  REGISTRY_FAILURE,
  REGISTRY_SUBMISSION,
} from "@/types/registry";

import {
  adaptRegistryCredentialStatus,
  classifyRegistryFailure,
  parseRegistryCredentialSubmission,
} from "./registry.adapter";

const credentialPayload = {
  data: {
    attributes: {
      configured: true,
      is_valid: true,
      scopes: ["catalog:read"],
      last_validated_at: "2026-03-20T12:00:00Z",
      validation_status: "valid",
      validation_pending: false,
      key: "registry-secret-value",
      masked_key: "reg_***",
      pending_key: "queued-secret",
      arbitrary_backend_detail: "do not expose",
    },
  },
};

const activeCredential = adaptRegistryCredentialStatus(credentialPayload);
const jsonError = (status: number, code: string) =>
  new Response(
    JSON.stringify({ errors: [{ code, detail: "private detail" }] }),
    {
      status,
    },
  );

describe("Registry adapter", () => {
  it("maps only documented non-secret credential status fields", () => {
    // Given
    const malformedPayload = { data: { attributes: { configured: true } } };

    // When
    const status = adaptRegistryCredentialStatus(credentialPayload);

    // Then
    expect(status).toEqual({
      configured: true,
      isValid: true,
      scopes: ["catalog:read"],
      lastValidatedAt: "2026-03-20T12:00:00Z",
      validationStatus: "valid",
      validationPending: false,
    });
    expect(adaptRegistryCredentialStatus(malformedPayload)).toBeNull();
  });

  it("accepts only a matching 202 task and fixed Content-Location path", async () => {
    // Given
    const response = new Response(
      JSON.stringify({ data: { type: "tasks", id: "task-123" } }),
      {
        status: 202,
        headers: { "Content-Location": "/api/v1/tasks/task-123" },
      },
    );

    // When
    const result = await parseRegistryCredentialSubmission(response);

    // Then
    expect(result).toEqual({
      status: REGISTRY_SUBMISSION.PENDING,
      taskId: "task-123",
    });
  });

  it("rejects a non-202 response or a mismatched task location", async () => {
    // Given
    const task = JSON.stringify({ data: { type: "tasks", id: "task-123" } });
    const wrongStatus = new Response(task, { status: 201 });
    const wrongLocation = new Response(task, {
      status: 202,
      headers: { "Content-Location": "/api/v1/tasks/other" },
    });

    // When
    const results = await Promise.all([
      parseRegistryCredentialSubmission(wrongStatus),
      parseRegistryCredentialSubmission(wrongLocation),
    ]);

    // Then
    expect(results).toEqual([
      { status: REGISTRY_SUBMISSION.ERROR },
      { status: REGISTRY_SUBMISSION.ERROR },
    ]);
  });

  it("classifies every Registry 401 or 403 as access denied first", async () => {
    // Given
    const responses = [
      [401, REGISTRY_ENDPOINT.CREDENTIAL],
      [403, REGISTRY_ENDPOINT.MUTATION],
      [403, REGISTRY_ENDPOINT.PROVIDERS],
    ] as const;

    // When
    const results = await Promise.all(
      responses.map(([status, endpoint]) =>
        classifyRegistryFailure(
          jsonError(status, "registry_key_rejected"),
          endpoint,
          activeCredential,
        ),
      ),
    );

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.ACCESS_DENIED },
      { status: REGISTRY_FAILURE.ACCESS_DENIED },
      { status: REGISTRY_FAILURE.ACCESS_DENIED },
    ]);
  });

  it("maps only a 409 with an authoritative no-active credential to onboarding", async () => {
    // Given
    const noCredential = adaptRegistryCredentialStatus({
      data: {
        attributes: {
          configured: false,
          is_valid: false,
          scopes: [],
          validation_pending: false,
        },
      },
    });

    // When
    const results = await Promise.all(
      [noCredential, null].map((credential) =>
        classifyRegistryFailure(
          new Response(null, { status: 409 }),
          REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
          credential,
        ),
      ),
    );

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.ONBOARDING },
      { status: REGISTRY_FAILURE.ERROR },
    ]);
  });

  it("maps only exact documented 502 and 503 status-code pairs", async () => {
    // Given
    const rejected = jsonError(502, "registry_key_rejected");
    const unavailable = jsonError(503, "registry_unavailable");

    // When
    const results = await Promise.all([
      classifyRegistryFailure(
        rejected,
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
      classifyRegistryFailure(
        unavailable,
        REGISTRY_ENDPOINT.AVAILABLE_ARTIFACTS,
        activeCredential,
      ),
    ]);

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.RECONNECT },
      { status: REGISTRY_FAILURE.UNAVAILABLE },
    ]);
  });

  it("keeps wrong, malformed, and unrelated failures generic", async () => {
    // Given
    const malformed = new Response("<html>key=private</html>", { status: 503 });

    // When
    const results = await Promise.all([
      classifyRegistryFailure(
        jsonError(502, "other_error"),
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
      classifyRegistryFailure(
        jsonError(502, "registry_unavailable"),
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
      classifyRegistryFailure(
        malformed,
        REGISTRY_ENDPOINT.PROVIDERS,
        activeCredential,
      ),
    ]);

    // Then
    expect(results).toEqual([
      { status: REGISTRY_FAILURE.ERROR },
      { status: REGISTRY_FAILURE.ERROR },
      { status: REGISTRY_FAILURE.ERROR },
    ]);
  });
});
