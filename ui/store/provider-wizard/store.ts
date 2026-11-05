import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  CONNECT_PANEL,
  ConnectDraft,
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
  connectDraft: ConnectDraft | null;
  setProvider: (provider: ProviderWizardIdentity) => void;
  setVia: (via: string | null) => void;
  setSecretId: (secretId: string | null) => void;
  setMode: (mode: ProviderWizardMode) => void;
  /** Merges into the draft of `providerType`; another provider starts a blank one. */
  setConnectDraft: (
    providerType: string,
    patch: Partial<Omit<ConnectDraft, "providerType">>,
  ) => void;
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
  connectDraft: null,
};

const emptyConnectDraft = (providerType: string): ConnectDraft => ({
  providerType,
  method: null,
  panel: CONNECT_PANEL.ACCESS,
  values: {},
});

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
      setConnectDraft: (providerType, patch) =>
        set((state) => ({
          connectDraft: {
            ...(state.connectDraft?.providerType === providerType
              ? state.connectDraft
              : emptyConnectDraft(providerType)),
            ...patch,
          },
        })),
      reset: () => set(initialState),
    }),
    {
      name: "provider-wizard-store",
      storage: createJSONStorage(() => sessionStorage),
      // The draft may hold access keys: it never leaves memory.
      partialize: ({ connectDraft: _draft, ...persisted }) => persisted,
    },
  ),
);
