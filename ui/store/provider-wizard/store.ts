import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  PROVIDER_WIZARD_MODE,
  ProviderWizardIdentity,
  ProviderWizardMode,
} from "@/types/provider-wizard";
import { ProviderType } from "@/types/providers";

interface ProviderWizardState {
  providerId: string | null;
  providerType: ProviderType | null;
  providerUid: string | null;
  providerAlias: string | null;
  via: string | null;
  secretId: string | null;
  mode: ProviderWizardMode;
  setProvider: (provider: ProviderWizardIdentity) => void;
  setVia: (via: string | null) => void;
  setSecretId: (secretId: string | null) => void;
  setMode: (mode: ProviderWizardMode) => void;
  reset: () => void;
}

const initialState = {
  providerId: null,
  providerType: null,
  providerUid: null,
  providerAlias: null,
  via: null,
  secretId: null,
  mode: PROVIDER_WIZARD_MODE.ADD,
};

export const useProviderWizardStore = create<ProviderWizardState>()(
  persist(
    (set) => ({
      ...initialState,
      setProvider: (provider) =>
        set({
          providerId: provider.id,
          providerType: provider.type,
          providerUid: provider.uid,
          providerAlias: provider.alias,
        }),
      setVia: (via) => set({ via }),
      setSecretId: (secretId) => set({ secretId }),
      setMode: (mode) => set({ mode }),
      reset: () => set(initialState),
    }),
    {
      name: "provider-wizard-store",
      storage: createJSONStorage(() => sessionStorage),
    },
  ),
);
