import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";

import { connectAwsAccount } from "./connect-aws-account";
import { AWS_ACCESS_METHOD } from "./types";

const {
  addProvider,
  addCredentialsProvider,
  updateProvider,
  updateCredentialsProvider,
} = vi.hoisted(() => ({
  addProvider: vi.fn(),
  addCredentialsProvider: vi.fn(),
  updateProvider: vi.fn(),
  updateCredentialsProvider: vi.fn(),
}));

vi.mock("@/actions/providers/providers", () => ({
  addProvider,
  addCredentialsProvider,
  updateProvider,
  updateCredentialsProvider,
}));

const ROLE_ARN = "arn:aws:iam::123456789012:role/ProwlerScan";

const roleValues = {
  providerId: "",
  providerType: "aws",
  providerAlias: "Production",
  role_arn: ROLE_ARN,
  external_id: "tenant-1",
  credentials_type: "aws-sdk-default",
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  role_session_name: "",
  session_duration: "3600",
};

const formEntries = (call: number, mock: typeof addProvider) =>
  Object.fromEntries((mock.mock.calls[call][0] as FormData).entries());

describe("connectAwsAccount", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    useProviderWizardStore.getState().reset();
    useUIStore.setState({ hasProviders: false, hasProvidersResolved: true });
    addProvider.mockResolvedValue({ data: { id: "provider-1" } });
    addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    updateProvider.mockResolvedValue({ data: { id: "provider-1" } });
    updateCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
  });

  describe("when connecting through an IAM role", () => {
    it("registers the account read from the ARN and stores its credentials in one go", async () => {
      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-1" });
      expect(formEntries(0, addProvider)).toEqual({
        providerType: "aws",
        providerUid: "123456789012",
        providerAlias: "Production",
      });
      expect(formEntries(0, addCredentialsProvider)).toEqual({
        providerId: "provider-1",
        providerType: "aws",
        role_arn: ROLE_ARN,
        external_id: "tenant-1",
        credentials_type: "aws-sdk-default",
        session_duration: "3600",
      });
    });

    it("leaves the wizard ready for the connection test", async () => {
      // When
      await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(useProviderWizardStore.getState()).toMatchObject({
        providerId: "provider-1",
        providerType: "aws",
        providerUid: "123456789012",
        providerAlias: "Production",
        via: "role",
        secretId: "secret-1",
        mode: "add",
      });
      expect(useUIStore.getState().hasProviders).toBe(true);
    });

    it("rejects a malformed ARN on its field without calling the API", async () => {
      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: { ...roleValues, role_arn: "arn:aws:s3:::bucket" },
      });

      // Then
      expect(result).toEqual({
        ok: false,
        errors: [
          expect.objectContaining({
            source: { pointer: "/data/attributes/uid" },
          }),
        ],
      });
      expect(addProvider).not.toHaveBeenCalled();
    });
  });

  describe("when connecting with access keys", () => {
    it("registers the typed account id and sends only the keys as the secret", async () => {
      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.CREDENTIALS,
        values: {
          providerId: "",
          providerType: "aws",
          providerUid: "210987654321",
          providerAlias: "",
          aws_access_key_id: "AKIAEXAMPLE",
          aws_secret_access_key: "secret",
          aws_session_token: "",
        },
      });

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-1" });
      expect(formEntries(0, addProvider)).toEqual({
        providerType: "aws",
        providerUid: "210987654321",
      });
      expect(formEntries(0, addCredentialsProvider)).toEqual({
        providerId: "provider-1",
        providerType: "aws",
        aws_access_key_id: "AKIAEXAMPLE",
        aws_secret_access_key: "secret",
      });
      expect(useProviderWizardStore.getState().via).toBe("credentials");
    });
  });

  describe("when the API refuses the account", () => {
    it("returns the provider errors and stores nothing", async () => {
      // Given
      const errors = [
        {
          detail: "Provider with this uid already exists.",
          source: { pointer: "/data/attributes/uid" },
        },
      ];
      addProvider.mockResolvedValueOnce({ errors });

      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(result).toEqual({ ok: false, errors });
      expect(addCredentialsProvider).not.toHaveBeenCalled();
      expect(useProviderWizardStore.getState().providerId).toBeNull();
    });
  });

  describe("when the API fails without field errors", () => {
    it("reports the account failure instead of throwing", async () => {
      // Given
      addProvider.mockResolvedValueOnce({ error: "Server is unavailable." });

      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(result).toEqual({
        ok: false,
        errors: [{ detail: "Server is unavailable." }],
      });
      expect(addCredentialsProvider).not.toHaveBeenCalled();
      expect(useProviderWizardStore.getState().providerId).toBeNull();
    });

    it("reports an account response without an id instead of stalling", async () => {
      // Given
      addProvider.mockResolvedValueOnce({ data: {} });

      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(result).toEqual({
        ok: false,
        errors: [{ detail: expect.stringMatching(/try again/i) }],
      });
      expect(addCredentialsProvider).not.toHaveBeenCalled();
    });

    it("reports the credentials failure and keeps the account for a retry", async () => {
      // Given
      addCredentialsProvider.mockResolvedValueOnce({
        error: "Server is unavailable.",
      });

      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(result).toEqual({
        ok: false,
        errors: [{ detail: "Server is unavailable." }],
      });
      expect(useProviderWizardStore.getState()).toMatchObject({
        providerId: "provider-1",
        secretId: null,
      });
    });
  });

  describe("when the credentials are refused after the account was registered", () => {
    it("reuses the registered account on the next attempt instead of creating it twice", async () => {
      // Given
      const errors = [
        {
          detail: "Invalid role ARN.",
          source: { pointer: "/data/attributes/secret/role_arn" },
        },
      ];
      addCredentialsProvider.mockResolvedValueOnce({ errors });

      // When
      const first = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });
      const second = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // Then
      expect(first).toEqual({ ok: false, errors });
      expect(second).toEqual({ ok: true, providerId: "provider-1" });
      expect(addProvider).toHaveBeenCalledOnce();
      expect(addCredentialsProvider).toHaveBeenCalledTimes(2);
      expect(updateProvider).not.toHaveBeenCalled();
    });

    it("renames the registered account when the alias changed before the retry", async () => {
      // Given
      addCredentialsProvider.mockResolvedValueOnce({
        errors: [{ detail: "Invalid role ARN." }],
      });
      await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });

      // When
      const second = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: { ...roleValues, providerAlias: "Production EU" },
      });

      // Then
      expect(second).toEqual({ ok: true, providerId: "provider-1" });
      expect(addProvider).toHaveBeenCalledOnce();
      expect(formEntries(0, updateProvider)).toEqual({
        providerId: "provider-1",
        providerAlias: "Production EU",
      });
      expect(useProviderWizardStore.getState().providerAlias).toBe(
        "Production EU",
      );
    });
  });

  describe("when the account was already connected in this wizard session", () => {
    it("updates the stored credentials instead of creating a second secret", async () => {
      // Given
      await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: roleValues,
      });
      updateCredentialsProvider.mockResolvedValueOnce({
        data: { id: "secret-1" },
      });

      // When
      const result = await connectAwsAccount({
        method: AWS_ACCESS_METHOD.ROLE,
        values: {
          ...roleValues,
          role_arn: "arn:aws:iam::123456789012:role/ProwlerScanV2",
        },
      });

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-1" });
      expect(addProvider).toHaveBeenCalledOnce();
      expect(addCredentialsProvider).toHaveBeenCalledOnce();
      expect(updateCredentialsProvider).toHaveBeenCalledExactlyOnceWith(
        "secret-1",
        expect.any(FormData),
      );
      expect(
        Object.fromEntries(
          (updateCredentialsProvider.mock.calls[0][1] as FormData).entries(),
        ),
      ).toMatchObject({
        providerId: "provider-1",
        providerType: "aws",
        role_arn: "arn:aws:iam::123456789012:role/ProwlerScanV2",
      });
      expect(useProviderWizardStore.getState().secretId).toBe("secret-1");
    });
  });
});
