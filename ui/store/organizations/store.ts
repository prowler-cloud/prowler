import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  buildAccountLookup,
  buildOrgTreeData,
  getSelectableAccountIds,
} from "@/actions/organizations/organizations.adapter";
import {
  ConnectionTestStatus,
  DiscoveredAccount,
  DiscoveryResult,
} from "@/types/organizations";
import { TreeDataItem } from "@/types/tree";

interface DerivedDiscoveryState {
  treeData: TreeDataItem[];
  accountLookup: Map<string, DiscoveredAccount>;
  selectableAccountIds: string[];
  selectableAccountIdSet: Set<string>;
}

function buildDerivedDiscoveryState(
  discoveryResult: DiscoveryResult | null,
): DerivedDiscoveryState {
  if (!discoveryResult) {
    return {
      treeData: [],
      accountLookup: new Map<string, DiscoveredAccount>(),
      selectableAccountIds: [],
      selectableAccountIdSet: new Set<string>(),
    };
  }

  const selectableAccountIds = getSelectableAccountIds(discoveryResult);
  return {
    treeData: buildOrgTreeData(discoveryResult),
    accountLookup: buildAccountLookup(discoveryResult),
    selectableAccountIds,
    selectableAccountIdSet: new Set(selectableAccountIds),
  };
}

interface OrgSetupState {
  // Identity
  organizationId: string | null;
  organizationName: string | null;
  organizationExternalId: string | null;
  discoveryId: string | null;

  // Discovery
  discoveryResult: DiscoveryResult | null;
  treeData: TreeDataItem[];
  accountLookup: Map<string, DiscoveredAccount>;
  selectableAccountIds: string[];
  selectableAccountIdSet: Set<string>;

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
  treeData: [],
  accountLookup: new Map<string, DiscoveredAccount>(),
  selectableAccountIds: [],
  selectableAccountIdSet: new Set<string>(),
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
        set((state) => {
          const derivedState = buildDerivedDiscoveryState(result);
          return {
            discoveryId: id,
            discoveryResult: result,
            ...derivedState,
            selectedAccountIds: state.selectedAccountIds.filter((accountId) =>
              derivedState.selectableAccountIdSet.has(accountId),
            ),
          };
        }),

      setSelectedAccountIds: (ids) =>
        set((state) => ({
          selectedAccountIds: ids.filter((accountId) =>
            state.selectableAccountIdSet.has(accountId),
          ),
        })),

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
      storage: createJSONStorage(() => sessionStorage),
      merge: (persistedState, currentState) => {
        const mergedState = {
          ...currentState,
          ...(persistedState as Partial<OrgSetupState>),
        };
        const derivedState = buildDerivedDiscoveryState(
          mergedState.discoveryResult,
        );

        return {
          ...mergedState,
          ...derivedState,
          selectedAccountIds: mergedState.selectedAccountIds.filter(
            (accountId) => derivedState.selectableAccountIdSet.has(accountId),
          ),
        };
      },
      partialize: (state) => ({
        organizationId: state.organizationId,
        organizationName: state.organizationName,
        organizationExternalId: state.organizationExternalId,
        discoveryId: state.discoveryId,
        discoveryResult: state.discoveryResult,
        selectedAccountIds: state.selectedAccountIds,
        accountAliases: state.accountAliases,
      }),
    },
  ),
);
