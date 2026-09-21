"use client";

import { useState } from "react";

import {
  addCredentialsProvider,
  addProvider,
  updateCredentialsProvider,
} from "@/actions/providers/providers";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { testProviderConnection } from "@/lib/provider-helpers";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { ApiError } from "@/types";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import {
  AwsQuickConnectValues,
  resolveAwsQuickAccountId,
} from "../aws-quick.utils";
import { AWS_QUICK_ACCESS_METHOD } from "../types";

export type AwsQuickConnectField =
  | "roleArn"
  | "accountId"
  | "awsAccessKeyId"
  | "awsSecretAccessKey"
  | "awsSessionToken";

interface UseAwsQuickConnectOptions {
  externalId: string;
  onConnected: () => void;
  /** Returns true when the error was attached to a field. */
  setFieldError: (field: AwsQuickConnectField, message: string) => boolean;
}

const SECRET_POINTER_FIELDS = {
  [ProviderCredentialFields.ROLE_ARN]: "roleArn",
  [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "awsAccessKeyId",
  [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "awsSecretAccessKey",
  [ProviderCredentialFields.AWS_SESSION_TOKEN]: "awsSessionToken",
} as const satisfies Record<string, AwsQuickConnectField>;

const isSecretPointerKey = (
  key: string,
): key is keyof typeof SECRET_POINTER_FIELDS => key in SECRET_POINTER_FIELDS;

const secretPointerField = (pointer: string | undefined) => {
  const key = pointer?.split("/").at(-1);
  return key && isSecretPointerKey(key)
    ? SECRET_POINTER_FIELDS[key]
    : undefined;
};

const firstErrorDetail = (errors: ApiError[]) =>
  errors[0]?.detail ?? "Something went wrong. Please try again.";

/** Registers the account, stores its credentials and verifies the connection. */
export function useAwsQuickConnect({
  externalId,
  onConnected,
  setFieldError,
}: UseAwsQuickConnectOptions) {
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const ensureProvider = async (
    uid: string,
    uidField: AwsQuickConnectField,
  ) => {
    const store = useProviderWizardStore.getState();
    if (store.providerId && store.providerUid === uid) {
      return store.providerId;
    }

    const formData = new FormData();
    formData.set(ProviderCredentialFields.PROVIDER_TYPE, "aws");
    formData.set(ProviderCredentialFields.PROVIDER_UID, uid);
    const data = await addProvider(formData);

    if (data?.errors?.length) {
      const errors = data.errors as ApiError[];
      const uidError = errors.find((error) =>
        ["/data/attributes/uid", "/data/attributes/__all__"].includes(
          error.source?.pointer ?? "",
        ),
      );
      if (uidError && setFieldError(uidField, uidError.detail)) {
        return null;
      }
      setConnectionError(firstErrorDetail(errors));
      return null;
    }

    const providerId = data.data.id as string;
    store.setProvider({ id: providerId, type: "aws", uid, alias: null });
    // A fresh provider has no secret yet; never PATCH one from a previous attempt.
    store.setSecretId(null);
    store.setMode(PROVIDER_WIZARD_MODE.ADD);
    return providerId;
  };

  const buildSecretFormData = (
    providerId: string,
    input: AwsQuickConnectValues,
  ) => {
    const formData = new FormData();
    formData.set(ProviderCredentialFields.PROVIDER_ID, providerId);
    formData.set(ProviderCredentialFields.PROVIDER_TYPE, "aws");

    if (input.method === AWS_QUICK_ACCESS_METHOD.ROLE) {
      formData.set(ProviderCredentialFields.ROLE_ARN, input.values.roleArn);
      formData.set(ProviderCredentialFields.EXTERNAL_ID, externalId);
      formData.set(
        ProviderCredentialFields.CREDENTIALS_TYPE,
        ProviderCredentialFields.CREDENTIALS_TYPE_AWS,
      );
      return formData;
    }

    formData.set(
      ProviderCredentialFields.AWS_ACCESS_KEY_ID,
      input.values.awsAccessKeyId,
    );
    formData.set(
      ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
      input.values.awsSecretAccessKey,
    );
    if (input.values.awsSessionToken) {
      formData.set(
        ProviderCredentialFields.AWS_SESSION_TOKEN,
        input.values.awsSessionToken,
      );
    }
    return formData;
  };

  const saveSecret = async (
    providerId: string,
    input: AwsQuickConnectValues,
  ) => {
    const store = useProviderWizardStore.getState();
    const formData = buildSecretFormData(providerId, input);
    const data = store.secretId
      ? await updateCredentialsProvider(store.secretId, formData)
      : await addCredentialsProvider(formData);

    if (data?.errors?.length) {
      const errors = data.errors as ApiError[];
      const attached = errors.some((error) => {
        const field = secretPointerField(error.source?.pointer);
        return field ? setFieldError(field, error.detail) : false;
      });
      if (!attached) {
        setConnectionError(firstErrorDetail(errors));
      }
      return false;
    }

    store.setSecretId(data.data.id as string);
    store.setVia(
      input.method === AWS_QUICK_ACCESS_METHOD.ROLE ? "role" : "credentials",
    );
    return true;
  };

  const connect = async (input: AwsQuickConnectValues) => {
    if (isConnecting) return;

    const uid = resolveAwsQuickAccountId(input);
    if (!uid) {
      setFieldError("roleArn", "Could not read the account id from the ARN");
      return;
    }

    setIsConnecting(true);
    setConnectionError(null);

    try {
      const uidField =
        input.method === AWS_QUICK_ACCESS_METHOD.ROLE ? "roleArn" : "accountId";
      const providerId = await ensureProvider(uid, uidField);
      if (!providerId) return;

      const saved = await saveSecret(providerId, input);
      if (!saved) return;

      const result = await testProviderConnection(providerId);
      if (!result.connected) {
        setConnectionError(
          result.error ?? "Prowler could not connect to the account.",
        );
        return;
      }

      onConnected();
    } catch (error) {
      setConnectionError(
        error instanceof Error
          ? error.message
          : "Something went wrong. Please try again.",
      );
    } finally {
      setIsConnecting(false);
    }
  };

  return {
    connect,
    connectionError,
    isConnecting,
    clearConnectionError: () => setConnectionError(null),
  };
}
