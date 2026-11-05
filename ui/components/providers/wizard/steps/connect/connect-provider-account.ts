import {
  addCredentialsProvider,
  addProvider,
  getProvider,
  updateCredentialsProvider,
  updateProvider,
} from "@/actions/providers/providers";
import { addRegistryProvider } from "@/actions/providers/registry-provider";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";
import type { ApiError } from "@/types";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";
import { isKnownProviderType } from "@/types/providers";

export const UID_ERROR_POINTER = "/data/attributes/uid";

// Account fields travel with the provider, never with its secret.
const ACCOUNT_FIELDS: readonly string[] = [
  ProviderCredentialFields.PROVIDER_UID,
  ProviderCredentialFields.PROVIDER_ALIAS,
];

// Secrets that repeat the account id read it from the account, not the form.
export const UID_MIRROR_FIELD: Partial<Record<string, string>> = {
  oraclecloud: ProviderCredentialFields.OCI_TENANCY,
  googleworkspace: ProviderCredentialFields.GOOGLEWORKSPACE_CUSTOMER_ID,
};

export interface ConnectProviderInput {
  providerType: string;
  /** The `via` the account is connected with; null for single-method providers. */
  method: string | null;
  uid: string | null;
  /** Undefined keeps the stored alias (the form does not edit it). */
  alias?: string;
  secretValues: Record<string, unknown>;
  /** The wizard was opened on an existing account: never register another one. */
  locked?: boolean;
  /** The caller stores the secret itself (Registry providers). */
  skipSecret?: boolean;
  missingUidMessage?: string;
}

interface ConnectSuccess {
  ok: true;
  providerId: string;
}

interface ConnectFailure {
  ok: false;
  errors: ApiError[];
}

export type ConnectProviderResult = ConnectSuccess | ConnectFailure;

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

type CreatedIdResult =
  | { id: string; errors: null }
  | { id: null; errors: ApiError[] };

// Actions resolve { errors } on a refusal and { error } on a crash, never throwing.
// A body with no id is reported too, or the step would stall without feedback.
const readCreatedId = (response: unknown): CreatedIdResult => {
  const body = response as CreateActionResponse | undefined;
  if (body?.errors?.length) return { id: null, errors: body.errors };
  if (body?.error)
    return { id: null, errors: [{ detail: body.error } as ApiError] };
  const id = body?.data?.id;
  if (typeof id !== "string" || !id) {
    return {
      id: null,
      errors: [{ detail: UNCONFIRMED_RESPONSE_MESSAGE } as ApiError],
    };
  }
  return { id, errors: null };
};

const uidError = (detail: string): ApiError =>
  ({ detail, source: { pointer: UID_ERROR_POINTER } }) as ApiError;

type EnsureResult =
  // `reused`: the account existed before this submit, so it may hold a secret.
  | { providerId: string; errors: null; reused: boolean }
  | { providerId: null; errors: ApiError[] };

// A retry may carry a new alias; the account registered earlier has to follow it.
const renameProvider = async (
  providerId: string,
  providerType: string,
  alias: string | undefined,
): Promise<EnsureResult> => {
  const store = useProviderWizardStore.getState();
  if (alias === undefined || (store.providerAlias ?? "") === alias)
    return { providerId, errors: null, reused: true };

  const updated = readCreatedId(
    await updateProvider(
      toFormData({
        [ProviderCredentialFields.PROVIDER_ID]: providerId,
        [ProviderCredentialFields.PROVIDER_ALIAS]: alias,
      }),
    ),
  );
  if (updated.id === null) return { providerId: null, errors: updated.errors };

  store.setProvider({
    id: providerId,
    type: providerType,
    uid: store.providerUid ?? "",
    alias: alias || null,
  });
  return { providerId, errors: null, reused: true };
};

const createProvider = (providerType: string, uid: string, alias: string) => {
  if (isKnownProviderType(providerType)) {
    return addProvider(
      toFormData({
        [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
        [ProviderCredentialFields.PROVIDER_UID]: uid,
        [ProviderCredentialFields.PROVIDER_ALIAS]: alias,
      }),
    );
  }
  // The Registry action validates the alias as a present (possibly empty) string.
  const formData = new FormData();
  formData.append(ProviderCredentialFields.PROVIDER_TYPE, providerType);
  formData.append(ProviderCredentialFields.PROVIDER_UID, uid);
  formData.append(ProviderCredentialFields.PROVIDER_ALIAS, alias);
  return addRegistryProvider(formData);
};

/** Registers the account once per wizard, reusing it on retries. */
export async function ensureProviderAccount({
  providerType,
  uid,
  alias,
  locked = false,
}: {
  providerType: string;
  uid: string;
  alias?: string;
  locked?: boolean;
}): Promise<EnsureResult> {
  const store = useProviderWizardStore.getState();
  const isSameAccount =
    store.providerId !== null &&
    store.providerType === providerType &&
    store.providerUid === uid;

  if (isSameAccount && store.providerId) {
    return renameProvider(store.providerId, providerType, alias);
  }

  if (locked) {
    return {
      providerId: null,
      errors: [
        uidError(
          `These credentials belong to ${uid}, not to ${store.providerUid ?? "this provider"}. Use credentials for the account you are updating.`,
        ),
      ],
    };
  }

  const created = readCreatedId(
    await createProvider(providerType, uid, alias ?? ""),
  );
  if (created.id === null) return { providerId: null, errors: created.errors };

  const providerId = created.id;
  store.setProvider({
    id: providerId,
    type: providerType,
    uid,
    alias: alias || null,
  });
  store.setSecretId(null);
  store.setMode(PROVIDER_WIZARD_MODE.ADD);
  // The layout only re-counts providers on a server render; flip the shared flag now.
  useUIStore.getState().setHasProviders(true);
  return { providerId, errors: null, reused: false };
}

interface ProviderSecretRelationship {
  data?: { relationships?: { secret?: { data?: { id?: unknown } | null } } };
}

// The secret an existing account already holds, read back from the API.
const readStoredSecretId = async (providerId: string) => {
  const formData = new FormData();
  formData.append("id", providerId);
  try {
    const response = (await getProvider(
      formData,
    )) as ProviderSecretRelationship;
    const id = response?.data?.relationships?.secret?.data?.id;
    return typeof id === "string" && id ? id : null;
  } catch {
    return null;
  }
};

/** Registers the account (or reuses it) and stores its credentials in a single submit. */
export async function connectProviderAccount(
  input: ConnectProviderInput,
): Promise<ConnectProviderResult> {
  const { providerType, method, uid, alias, locked, skipSecret } = input;
  if (!uid) {
    return {
      ok: false,
      errors: [uidError(input.missingUidMessage ?? "Account ID is required.")],
    };
  }

  const provider = await ensureProviderAccount({
    providerType,
    uid,
    alias: alias?.trim(),
    locked,
  });
  if (provider.providerId === null)
    return { ok: false, errors: provider.errors };
  if (skipSecret) return { ok: true, providerId: provider.providerId };

  const secretValues = Object.fromEntries(
    Object.entries(input.secretValues).filter(
      ([key]) => !ACCOUNT_FIELDS.includes(key),
    ),
  );
  const mirrorField = UID_MIRROR_FIELD[providerType];
  const secretFormData = toFormData({
    ...secretValues,
    ...(mirrorField ? { [mirrorField]: uid } : {}),
    [ProviderCredentialFields.PROVIDER_ID]: provider.providerId,
    [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
  });
  // A provider holds one secret: resubmitting a connected account edits it in
  // place, including one whose create committed although its response was lost.
  const storedSecretId =
    useProviderWizardStore.getState().secretId ??
    (provider.reused ? await readStoredSecretId(provider.providerId) : null);
  const secret = readCreatedId(
    storedSecretId
      ? await updateCredentialsProvider(storedSecretId, secretFormData)
      : await addCredentialsProvider(secretFormData),
  );
  if (secret.id === null) return { ok: false, errors: secret.errors };

  const store = useProviderWizardStore.getState();
  store.setSecretId(secret.id);
  store.setVia(method);
  return { ok: true, providerId: provider.providerId };
}
