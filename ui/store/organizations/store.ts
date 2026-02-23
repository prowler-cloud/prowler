import { create } from "zustand";
import { persist } from "zustand/middleware";

import { ConnectionTestStatus, DiscoveryResult } from "@/types/organizations";

interface OrgSetupState {
  // Identity
  organizationId: string | null;
  organizationName: string | null;
  organizationExternalId: string | null;
  discoveryId: string | null;

  // Discovery
  discoveryResult: DiscoveryResult | null;

  // Selection + aliases
  selectedAccountIds: string[];
  accountAliases: Record<string, string>;

  // Apply result
  createdProviderIds: string[];

  // Connection test results
  connectionResults: Record<string, ConnectionTestStatus>;
  connectionErrors: Record<string, string>;

  // Actions
  setOrganization: (id: string, name: string, externalId: string) => void;
  setDiscovery: (id: string, result: DiscoveryResult) => void;
  setSelectedAccountIds: (ids: string[]) => void;
  setAccountAlias: (accountId: string, alias: string) => void;
  setCreatedProviderIds: (ids: string[]) => void;
  clearValidationState: () => void;
  setConnectionError: (providerId: string, error: string | null) => void;
  setConnectionResult: (
    providerId: string,
    status: ConnectionTestStatus,
  ) => void;
  reset: () => void;
}

const initialState = {
  organizationId: null,
  organizationName: null,
  organizationExternalId: null,
  discoveryId: null,
  discoveryResult: null,
  selectedAccountIds: [],
  accountAliases: {},
  createdProviderIds: [],
  connectionResults: {},
  connectionErrors: {},
};

export const useOrgSetupStore = create<OrgSetupState>()(
  persist(
    (set) => ({
      ...initialState,

      setOrganization: (id, name, externalId) =>
        set({
          organizationId: id,
          organizationName: name,
          organizationExternalId: externalId,
        }),

      setDiscovery: (id, result) =>
        set({ discoveryId: id, discoveryResult: result }),

      setSelectedAccountIds: (ids) => set({ selectedAccountIds: ids }),

      setAccountAlias: (accountId, alias) =>
        set((state) => ({
          accountAliases: { ...state.accountAliases, [accountId]: alias },
        })),

      setCreatedProviderIds: (ids) => set({ createdProviderIds: ids }),

      clearValidationState: () =>
        set({
          createdProviderIds: [],
          connectionResults: {},
          connectionErrors: {},
        }),

      setConnectionError: (providerId, error) =>
        set((state) => {
          if (!error) {
            const { [providerId]: _, ...rest } = state.connectionErrors;
            return { connectionErrors: rest };
          }

          return {
            connectionErrors: {
              ...state.connectionErrors,
              [providerId]: error,
            },
          };
        }),

      setConnectionResult: (providerId, status) =>
        set((state) => ({
          connectionResults: {
            ...state.connectionResults,
            [providerId]: status,
          },
        })),

      reset: () => set(initialState),
    }),
    {
      name: "org-setup-store",
    },
  ),
);
