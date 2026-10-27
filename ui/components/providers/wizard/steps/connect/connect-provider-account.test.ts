import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";

import { connectProviderAccount } from "./connect-provider-account";

const {
  addProvider,
  addCredentialsProvider,
  getProvider,
  updateProvider,
  updateCredentialsProvider,
  addRegistryProvider,
} = vi.hoisted(() => ({
  addProvider: vi.fn(),
  addCredentialsProvider: vi.fn(),
  getProvider: vi.fn(),
  updateProvider: vi.fn(),
  updateCredentialsProvider: vi.fn(),
  addRegistryProvider: vi.fn(),
}));

vi.mock("@/actions/providers/providers", () => ({
  addProvider,
  addCredentialsProvider,
  getProvider,
  updateProvider,
  updateCredentialsProvider,
}));

vi.mock("@/actions/providers/registry-provider", () => ({
  addRegistryProvider,
}));

const ROLE_ARN = "arn:aws:iam::123456789012:role/ProwlerScan";

const awsRoleSecret = {
  providerId: "",
  providerType: "aws",
  role_arn: ROLE_ARN,
  external_id: "tenant-1",
  credentials_type: "aws-sdk-default",
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  role_session_name: "",
  session_duration: "3600",
};

const awsRoleInput = {
  providerType: "aws",
  method: "role",
  uid: "123456789012",
  alias: "Production",
  secretValues: awsRoleSecret,
};

const formEntries = (call: number, mock: typeof addProvider) =>
  Object.fromEntries((mock.mock.calls[call][0] as FormData).entries());

describe("connectProviderAccount", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    useProviderWizardStore.getState().reset();
    useUIStore.setState({ hasProviders: false, hasProvidersResolved: true });
    addProvider.mockResolvedValue({ data: { id: "provider-1" } });
    addRegistryProvider.mockResolvedValue({ data: { id: "provider-r1" } });
    addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    updateProvider.mockResolvedValue({ data: { id: "provider-1" } });
    updateCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    getProvider.mockResolvedValue({
      data: { id: "provider-1", relationships: { secret: { data: null } } },
    });
  });

  describe("when connecting a new account", () => {
    it("registers the account and stores its credentials in one go", async () => {
      // When
      const result = await connectProviderAccount(awsRoleInput);

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
      await connectProviderAccount(awsRoleInput);

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

    it("connects a provider with a single method and no via", async () => {
      // When
      const result = await connectProviderAccount({
        providerType: "azure",
        method: null,
        uid: "fc94207a-d396-4a14-a7fd-12ab34cd56ef",
        alias: "",
        secretValues: {
          providerId: "",
          providerType: "azure",
          client_id: "client",
          client_secret: "secret",
          tenant_id: "tenant",
        },
      });

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-1" });
      expect(formEntries(0, addProvider)).toEqual({
        providerType: "azure",
        providerUid: "fc94207a-d396-4a14-a7fd-12ab34cd56ef",
      });
      expect(formEntries(0, addCredentialsProvider)).toEqual({
        providerId: "provider-1",
        providerType: "azure",
        client_id: "client",
        client_secret: "secret",
        tenant_id: "tenant",
      });
      expect(useProviderWizardStore.getState().via).toBeNull();
    });

    it("copies the account id into the secret of providers that repeat it", async () => {
      // When
      await connectProviderAccount({
        providerType: "oraclecloud",
        method: null,
        uid: "ocid1.tenancy.oc1..aaaa",
        alias: "",
        secretValues: {
          providerId: "",
          providerType: "oraclecloud",
          tenancy: "",
          user: "ocid1.user.oc1..bbbb",
        },
      });

      // Then
      expect(formEntries(0, addCredentialsProvider)).toMatchObject({
        tenancy: "ocid1.tenancy.oc1..aaaa",
        user: "ocid1.user.oc1..bbbb",
      });
    });

    it("registers a Registry provider through the Registry action", async () => {
      // When
      const result = await connectProviderAccount({
        providerType: "openai",
        method: null,
        uid: "org-123",
        alias: "",
        secretValues: {},
        skipSecret: true,
      });

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-r1" });
      expect(addProvider).not.toHaveBeenCalled();
      expect(formEntries(0, addRegistryProvider)).toEqual({
        providerType: "openai",
        providerUid: "org-123",
        providerAlias: "",
      });
      expect(addCredentialsProvider).not.toHaveBeenCalled();
    });

    it("rejects a missing account id on the uid field without calling the API", async () => {
      // When
      const result = await connectProviderAccount({
        ...awsRoleInput,
        uid: null,
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
      const result = await connectProviderAccount(awsRoleInput);

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
      const result = await connectProviderAccount(awsRoleInput);

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
      const result = await connectProviderAccount(awsRoleInput);

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
      const result = await connectProviderAccount(awsRoleInput);

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
      const first = await connectProviderAccount(awsRoleInput);
      const second = await connectProviderAccount(awsRoleInput);

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
      await connectProviderAccount(awsRoleInput);

      // When
      const second = await connectProviderAccount({
        ...awsRoleInput,
        alias: "Production EU",
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

  describe("when a secret was stored but its response was lost", () => {
    it("updates the stored secret on the retry instead of creating a second one", async () => {
      // Given: the create committed server-side but the wizard never heard back.
      addCredentialsProvider.mockResolvedValueOnce({ error: "Network error" });
      await connectProviderAccount(awsRoleInput);
      getProvider.mockResolvedValueOnce({
        data: {
          id: "provider-1",
          relationships: {
            secret: { data: { type: "provider-secrets", id: "secret-lost" } },
          },
        },
      });

      // When
      const result = await connectProviderAccount(awsRoleInput);

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-1" });
      expect(addCredentialsProvider).toHaveBeenCalledOnce();
      expect(updateCredentialsProvider).toHaveBeenCalledExactlyOnceWith(
        "secret-lost",
        expect.any(FormData),
      );
    });

    it("does not read the account back when it was just registered", async () => {
      // When
      await connectProviderAccount(awsRoleInput);

      // Then: a brand-new account cannot hold a secret yet.
      expect(getProvider).not.toHaveBeenCalled();
    });
  });

  describe("when the account was already connected in this wizard session", () => {
    it("updates the stored credentials instead of creating a second secret", async () => {
      // Given
      await connectProviderAccount(awsRoleInput);

      // When
      const result = await connectProviderAccount({
        ...awsRoleInput,
        secretValues: {
          ...awsRoleSecret,
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
    });
  });

  describe("when the wizard was opened on an existing account", () => {
    beforeEach(() => {
      useProviderWizardStore.getState().setProvider({
        id: "provider-9",
        type: "aws",
        uid: "123456789012",
        alias: "Legacy",
      });
      useProviderWizardStore.getState().setSecretId("secret-9");
    });

    it("replaces its credentials without touching the account", async () => {
      // When
      const result = await connectProviderAccount({
        ...awsRoleInput,
        alias: undefined,
        locked: true,
      });

      // Then
      expect(result).toEqual({ ok: true, providerId: "provider-9" });
      expect(addProvider).not.toHaveBeenCalled();
      expect(updateProvider).not.toHaveBeenCalled();
      expect(updateCredentialsProvider).toHaveBeenCalledExactlyOnceWith(
        "secret-9",
        expect.any(FormData),
      );
    });

    it("refuses credentials that belong to another account", async () => {
      // When
      const result = await connectProviderAccount({
        ...awsRoleInput,
        uid: "999999999999",
        alias: undefined,
        locked: true,
      });

      // Then
      expect(result).toEqual({
        ok: false,
        errors: [
          {
            detail: expect.stringMatching(/123456789012/),
            source: { pointer: "/data/attributes/uid" },
          },
        ],
      });
      expect(addProvider).not.toHaveBeenCalled();
      expect(updateCredentialsProvider).not.toHaveBeenCalled();
    });
  });
});
