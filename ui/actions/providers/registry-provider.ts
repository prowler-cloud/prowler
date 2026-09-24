"use server";

import { getInstalledRegistryProviderOptions } from "@/actions/registry/registry";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { REGISTRY_PROVIDER_DISCOVERY } from "@/lib/registry/provider-options";
import { createAddProviderFormSchema } from "@/types/formSchemas";
import { isKnownProviderType } from "@/types/providers";

import { addProvider, getProviders, updateProvider } from "./providers";

export async function addRegistryProvider(formData: FormData) {
  const unavailable = {
    errors: [
      {
        detail:
          "This Registry provider is no longer available. Check your permissions and installed artifacts, then try again.",
        source: { pointer: "/data/attributes/provider" },
      },
    ],
  };
  try {
    const discovery = await getInstalledRegistryProviderOptions();
    if (discovery.status !== REGISTRY_PROVIDER_DISCOVERY.READY)
      return unavailable;
    const values = createAddProviderFormSchema(
      discovery.options.map((option) => option.type),
    ).safeParse(Object.fromEntries(formData));
    if (!values.success || isKnownProviderType(values.data.providerType))
      return unavailable;
    const { providerType, providerUid } = values.data;
    const existing = await getProviders({
      filters: { "filter[provider]": providerType, "filter[uid]": providerUid },
      pageSize: 100,
    });
    // A previous request may have created the account before its response was
    // lost. Reuse that identity when returning to the credential step.
    if (!existing?.data) return unavailable;
    const account = existing.data.find(
      (provider) =>
        provider.attributes.provider === providerType &&
        provider.attributes.uid === providerUid,
    );
    if (account) {
      const alias = values.data.providerAlias.trim();
      if ((account.attributes.alias ?? "") === alias) return { data: account };
      const update = new FormData();
      update.set(ProviderCredentialFields.PROVIDER_ID, account.id);
      update.set(ProviderCredentialFields.PROVIDER_ALIAS, alias);
      return await updateProvider(update);
    }
    const validated = new FormData();
    Object.entries(values.data).forEach(([key, value]) => {
      if (value !== undefined) validated.set(key, value);
    });
    return await addProvider(validated);
  } catch {
    return unavailable;
  }
}
