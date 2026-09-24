import {
  addCredentialsProvider,
  addProvider,
  updateCredentialsProvider,
  updateProvider,
} from "@/actions/providers/providers";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";
import type { ApiError } from "@/types";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import {
  AWS_ROLE_ARN_MESSAGE,
  parseAwsAccountIdFromRoleArn,
} from "./aws-role-arn";
import { AWS_ACCESS_METHOD, type AwsAccessMethod } from "./types";

export const AWS_UID_ERROR_POINTER = "/data/attributes/uid";

// Account fields travel with the provider, never with its secret.
const ACCOUNT_FIELDS: readonly string[] = [
  ProviderCredentialFields.PROVIDER_UID,
  ProviderCredentialFields.PROVIDER_ALIAS,
];

export interface AwsConnectInput {
  method: AwsAccessMethod;
  values: Record<string, unknown>;
}

interface AwsConnectSuccess {
  ok: true;
  providerId: string;
}

interface AwsConnectFailure {
  ok: false;
  errors: ApiError[];
}

export type AwsConnectResult = AwsConnectSuccess | AwsConnectFailure;

const asText = (value: unknown) => (typeof value === "string" ? value : "");

// Blank fields are left out, so optional credentials never reach the API as "".
const toFormData = (values: Record<string, unknown>) => {
  const formData = new FormData();
  Object.entries(values).forEach(([key, value]) => {
    const text = asText(value).trim();
    if (text) formData.append(key, text);
  });
  return formData;
};

interface CreatedResource {
  id?: unknown;
}

interface CreateActionResponse {
  data?: CreatedResource;
  error?: string;
  errors?: ApiError[];
}

const UNCONFIRMED_RESPONSE_MESSAGE =
  "The API did not confirm the request. Please try again.";

// Actions resolve { errors } on a refusal and { error } on a crash, never throwing.
// A body with no id is reported too, or the step would stall without feedback.
const readCreatedId = (response: unknown) => {
  const body = response as CreateActionResponse | undefined;
  if (body?.errors?.length) return { id: null, errors: body.errors };
  if (body?.error) return { id: null, errors: [{ detail: body.error }] };
  const id = body?.data?.id;
  if (typeof id !== "string" || !id) {
    return { id: null, errors: [{ detail: UNCONFIRMED_RESPONSE_MESSAGE }] };
  }
  return { id, errors: null };
};

const resolveAccountId = ({ method, values }: AwsConnectInput) =>
  method === AWS_ACCESS_METHOD.ROLE
    ? parseAwsAccountIdFromRoleArn(
        asText(values[ProviderCredentialFields.ROLE_ARN]),
      )
    : asText(values[ProviderCredentialFields.PROVIDER_UID]).trim() || null;

// A retry may carry a new alias; the account registered earlier has to follow it.
const renameProvider = async (providerId: string, alias: string) => {
  const store = useProviderWizardStore.getState();
  if ((store.providerAlias ?? "") === alias)
    return { providerId, errors: null };

  const updated = readCreatedId(
    await updateProvider(
      toFormData({
        [ProviderCredentialFields.PROVIDER_ID]: providerId,
        [ProviderCredentialFields.PROVIDER_ALIAS]: alias,
      }),
    ),
  );
  if (!updated.id) return { providerId: null, errors: updated.errors };

  store.setProvider({
    id: providerId,
    type: "aws",
    uid: store.providerUid ?? "",
    alias: alias || null,
  });
  return { providerId, errors: null };
};

// A retry after a refused secret must not register the same account twice.
const ensureProvider = async (uid: string, alias: string) => {
  const store = useProviderWizardStore.getState();
  if (store.providerId && store.providerUid === uid) {
    return renameProvider(store.providerId, alias);
  }

  const created = readCreatedId(
    await addProvider(
      toFormData({
        [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
        [ProviderCredentialFields.PROVIDER_UID]: uid,
        [ProviderCredentialFields.PROVIDER_ALIAS]: alias,
      }),
    ),
  );
  if (!created.id) return { providerId: null, errors: created.errors };

  const providerId = created.id;
  store.setProvider({
    id: providerId,
    type: "aws",
    uid,
    alias: alias || null,
  });
  store.setSecretId(null);
  store.setMode(PROVIDER_WIZARD_MODE.ADD);
  // The layout only re-counts providers on a server render; flip the shared flag now.
  useUIStore.getState().setHasProviders(true);
  return { providerId, errors: null };
};

/** Registers the AWS account and stores its credentials in a single submit. */
export async function connectAwsAccount(
  input: AwsConnectInput,
): Promise<AwsConnectResult> {
  const uid = resolveAccountId(input);
  if (!uid) {
    return {
      ok: false,
      errors: [
        {
          detail: AWS_ROLE_ARN_MESSAGE,
          source: { pointer: AWS_UID_ERROR_POINTER },
        } as ApiError,
      ],
    };
  }

  const alias = asText(
    input.values[ProviderCredentialFields.PROVIDER_ALIAS],
  ).trim();
  const provider = await ensureProvider(uid, alias);
  if (!provider.providerId) return { ok: false, errors: provider.errors ?? [] };

  const secretValues = Object.fromEntries(
    Object.entries(input.values).filter(
      ([key]) => !ACCOUNT_FIELDS.includes(key),
    ),
  );
  const secretFormData = toFormData({
    ...secretValues,
    [ProviderCredentialFields.PROVIDER_ID]: provider.providerId,
    [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
  });
  // A provider holds one secret: resubmitting a connected account edits it in place.
  const storedSecretId = useProviderWizardStore.getState().secretId;
  const secret = readCreatedId(
    storedSecretId
      ? await updateCredentialsProvider(storedSecretId, secretFormData)
      : await addCredentialsProvider(secretFormData),
  );
  if (!secret.id) return { ok: false, errors: secret.errors ?? [] };

  const store = useProviderWizardStore.getState();
  store.setSecretId(secret.id);
  store.setVia(input.method);
  return { ok: true, providerId: provider.providerId };
}
