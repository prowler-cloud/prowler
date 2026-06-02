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
  // Whether the provider wizard modal is currently open. The layout-level
  // onboarding checkpoint watcher reads this so it can DEFER its dialog while
  // the wizard is open (the provider record is created on the wizard's first
  // step, which flips `hasProviders` mid-flow). Deliberately NOT persisted: a
  // mid-wizard refresh must not leave the flag stuck open.
  isOpen: boolean;
  setProvider: (provider: ProviderWizardIdentity) => void;
  setVia: (via: string | null) => void;
  setSecretId: (secretId: string | null) => void;
  setMode: (mode: ProviderWizardMode) => void;
  setIsOpen: (isOpen: boolean) => void;
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
  isOpen: false,
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
      setIsOpen: (isOpen) => set({ isOpen }),
      reset: () => set(initialState),
    }),
    {
      name: "provider-wizard-store",
      storage: createJSONStorage(() => sessionStorage),
      // Exclude the transient `isOpen` flag from persistence so a refresh while
      // the wizard is open never rehydrates it as open.
      partialize: ({ isOpen: _isOpen, ...rest }) => rest,
    },
  ),
);
