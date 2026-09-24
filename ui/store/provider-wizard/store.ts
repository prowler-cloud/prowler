import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  AwsConnectDraft,
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
  awsConnectDraft: AwsConnectDraft | null;
  setProvider: (provider: ProviderWizardIdentity) => void;
  setVia: (via: string | null) => void;
  setSecretId: (secretId: string | null) => void;
  setMode: (mode: ProviderWizardMode) => void;
  setAwsConnectDraft: (patch: Partial<AwsConnectDraft>) => void;
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
  awsConnectDraft: null,
};

const EMPTY_AWS_CONNECT_DRAFT: AwsConnectDraft = {
  method: "role",
  roleValues: {},
  keysValues: {},
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
      setAwsConnectDraft: (patch) =>
        set((state) => ({
          awsConnectDraft: {
            ...EMPTY_AWS_CONNECT_DRAFT,
            ...state.awsConnectDraft,
            ...patch,
          },
        })),
      reset: () => set(initialState),
    }),
    {
      name: "provider-wizard-store",
      storage: createJSONStorage(() => sessionStorage),
      // The draft may hold access keys: it never leaves memory.
      partialize: ({ awsConnectDraft: _draft, ...persisted }) => persisted,
    },
  ),
);
