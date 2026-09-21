import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { AWS_QUICK_ACCESS_METHOD } from "../types";

import { useAwsQuickConnect } from "./use-aws-quick-connect";

const {
  addProvider,
  addCredentialsProvider,
  updateCredentialsProvider,
  testProviderConnection,
} = vi.hoisted(() => ({
  addProvider: vi.fn(),
  addCredentialsProvider: vi.fn(),
  updateCredentialsProvider: vi.fn(),
  testProviderConnection: vi.fn(),
}));

vi.mock("@/actions/providers/providers", () => ({
  addProvider,
  addCredentialsProvider,
  updateCredentialsProvider,
}));

vi.mock("@/lib/provider-helpers", () => ({ testProviderConnection }));

const ROLE_INPUT = {
  method: AWS_QUICK_ACCESS_METHOD.ROLE,
  values: { roleArn: "arn:aws:iam::123456789012:role/ProwlerScan" },
} as const;

const STATIC_INPUT = {
  method: AWS_QUICK_ACCESS_METHOD.STATIC,
  values: {
    accountId: "123456789012",
    awsAccessKeyId: "AKIA",
    awsSecretAccessKey: "secret",
    awsSessionToken: "",
  },
} as const;

const secretPayload = (call: FormData) =>
  Object.fromEntries(call.entries()) as Record<string, string>;

describe("useAwsQuickConnect", () => {
  const onConnected = vi.fn();
  const setFieldError = vi.fn(() => true);

  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    useProviderWizardStore.getState().reset();
    addProvider.mockResolvedValue({ data: { id: "provider-1" } });
    addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    updateCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    testProviderConnection.mockResolvedValue({ connected: true, error: null });
  });

  const renderConnect = () =>
    renderHook(() =>
      useAwsQuickConnect({
        externalId: "tenant-123",
        onConnected,
        setFieldError,
      }),
    );

  it("registers the account from the ARN, stores a role secret and advances", async () => {
    const { result } = renderConnect();

    await act(() => result.current.connect(ROLE_INPUT));

    expect(secretPayload(addProvider.mock.calls[0][0])).toMatchObject({
      providerType: "aws",
      providerUid: "123456789012",
    });
    expect(secretPayload(addCredentialsProvider.mock.calls[0][0])).toEqual({
      providerId: "provider-1",
      providerType: "aws",
      role_arn: "arn:aws:iam::123456789012:role/ProwlerScan",
      external_id: "tenant-123",
      credentials_type: "aws-sdk-default",
    });
    expect(testProviderConnection).toHaveBeenCalledWith("provider-1");
    expect(onConnected).toHaveBeenCalledOnce();
    expect(useProviderWizardStore.getState()).toMatchObject({
      providerId: "provider-1",
      providerUid: "123456789012",
      secretId: "secret-1",
      via: "role",
    });
  });

  it("sends only the access keys for the static method", async () => {
    const { result } = renderConnect();

    await act(() => result.current.connect(STATIC_INPUT));

    expect(secretPayload(addCredentialsProvider.mock.calls[0][0])).toEqual({
      providerId: "provider-1",
      providerType: "aws",
      aws_access_key_id: "AKIA",
      aws_secret_access_key: "secret",
    });
    expect(useProviderWizardStore.getState().via).toBe("credentials");
  });

  it("keeps the failed connection visible and updates the same secret on retry", async () => {
    testProviderConnection
      .mockResolvedValueOnce({ connected: false, error: "AccessDenied" })
      .mockResolvedValueOnce({ connected: true, error: null });
    const { result } = renderConnect();

    await act(() => result.current.connect(ROLE_INPUT));
    expect(result.current.connectionError).toBe("AccessDenied");
    expect(onConnected).not.toHaveBeenCalled();

    await act(() => result.current.connect(ROLE_INPUT));

    expect(addProvider).toHaveBeenCalledOnce();
    expect(addCredentialsProvider).toHaveBeenCalledOnce();
    expect(updateCredentialsProvider).toHaveBeenCalledWith(
      "secret-1",
      expect.any(FormData),
    );
    expect(result.current.connectionError).toBeNull();
    expect(onConnected).toHaveBeenCalledOnce();
  });

  it("attaches a duplicate account error to the ARN field", async () => {
    addProvider.mockResolvedValueOnce({
      errors: [
        {
          detail: "Provider already exists",
          source: { pointer: "/data/attributes/uid" },
        },
      ],
    });
    const { result } = renderConnect();

    await act(() => result.current.connect(ROLE_INPUT));

    expect(setFieldError).toHaveBeenCalledWith(
      "roleArn",
      "Provider already exists",
    );
    expect(addCredentialsProvider).not.toHaveBeenCalled();
    expect(result.current.connectionError).toBeNull();
  });

  it("creates a new provider when the ARN points to another account", async () => {
    addProvider
      .mockResolvedValueOnce({ data: { id: "provider-1" } })
      .mockResolvedValueOnce({ data: { id: "provider-2" } });
    addCredentialsProvider
      .mockResolvedValueOnce({ data: { id: "secret-1" } })
      .mockResolvedValueOnce({ data: { id: "secret-2" } });
    const { result } = renderConnect();

    await act(() => result.current.connect(ROLE_INPUT));
    await act(() =>
      result.current.connect({
        method: AWS_QUICK_ACCESS_METHOD.ROLE,
        values: { roleArn: "arn:aws:iam::210987654321:role/ProwlerScan" },
      }),
    );

    expect(addProvider).toHaveBeenCalledTimes(2);
    expect(updateCredentialsProvider).not.toHaveBeenCalled();
    expect(addCredentialsProvider).toHaveBeenCalledTimes(2);
    expect(useProviderWizardStore.getState()).toMatchObject({
      providerId: "provider-2",
      secretId: "secret-2",
    });
  });
});
