import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  buildCandidateLookup,
  buildOrgTreeData,
  getSelectableCandidateIds,
} from "@/actions/organizations/organizations.adapter";
import {
  ConnectionTestStatus,
  DiscoveryStatus,
  OrgCandidate,
  OrgFlowType,
  OrgHierarchy,
  ORGANIZATION_TYPE,
  toOrgFlowType,
} from "@/types/organizations";
import { TreeDataItem } from "@/types/tree";

interface DerivedDiscoveryState {
  treeData: TreeDataItem[];
  candidateLookup: Map<string, OrgCandidate>;
  selectableCandidateIds: string[];
  selectableCandidateIdSet: Set<string>;
}

function buildDerivedDiscoveryState(
  hierarchy: OrgHierarchy | null,
): DerivedDiscoveryState {
  if (!hierarchy) {
    return {
      treeData: [],
      candidateLookup: new Map<string, OrgCandidate>(),
      selectableCandidateIds: [],
      selectableCandidateIdSet: new Set<string>(),
    };
  }

  const selectableCandidateIds = getSelectableCandidateIds(hierarchy);
  return {
    treeData: buildOrgTreeData(hierarchy),
    candidateLookup: buildCandidateLookup(hierarchy),
    selectableCandidateIds,
    selectableCandidateIdSet: new Set(selectableCandidateIds),
  };
}

interface OrgSetupState {
  // Discriminant.
  organizationType: OrgFlowType;

  // Identity
  organizationId: string | null;
  organizationName: string | null;
  organizationExternalId: string | null;

  // Discovery
  discoveryId: string | null;
  discoveryStatus: DiscoveryStatus | null;
  hierarchy: OrgHierarchy | null;
  treeData: TreeDataItem[];
  candidateLookup: Map<string, OrgCandidate>;
  selectableCandidateIds: string[];
  selectableCandidateIdSet: Set<string>;

  // Selection + aliases
  selectedCandidateIds: string[];
  candidateAliases: Record<string, string>;

  // Apply result
  createdProviderIds: string[];

  // Connection test results
  connectionResults: Record<string, ConnectionTestStatus>;
  connectionErrors: Record<string, string>;

  // Actions
  setOrganizationType: (organizationType: OrgFlowType) => void;
  setOrganization: (id: string, name: string, externalId: string) => void;
  // Persists the discovery id + status at trigger time so an interrupted
  // discovery can be resumed on wizard re-entry (resume read is Phase 2).
  setDiscoveryTriggered: (discoveryId: string) => void;
  setDiscovery: (id: string, hierarchy: OrgHierarchy) => void;
  setSelectedCandidateIds: (ids: string[]) => void;
  setCandidateAlias: (candidateId: string, alias: string) => void;
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
  organizationType: ORGANIZATION_TYPE.AWS as OrgFlowType,
  organizationId: null,
  organizationName: null,
  organizationExternalId: null,
  discoveryId: null,
  discoveryStatus: null,
  hierarchy: null,
  treeData: [],
  candidateLookup: new Map<string, OrgCandidate>(),
  selectableCandidateIds: [],
  selectableCandidateIdSet: new Set<string>(),
  selectedCandidateIds: [],
  candidateAliases: {},
  createdProviderIds: [],
  connectionResults: {},
  connectionErrors: {},
};

export const useOrgSetupStore = create<OrgSetupState>()(
  persist(
    (set) => ({
      ...initialState,

      setOrganizationType: (organizationType) => set({ organizationType }),

      setOrganization: (id, name, externalId) =>
        set({
          organizationId: id,
          organizationName: name,
          organizationExternalId: externalId,
        }),

      setDiscoveryTriggered: (discoveryId) =>
        set({ discoveryId, discoveryStatus: "pending" }),

      setDiscovery: (id, hierarchy) =>
        set((state) => {
          const derivedState = buildDerivedDiscoveryState(hierarchy);
          return {
            discoveryId: id,
            discoveryStatus: "succeeded",
            hierarchy,
            ...derivedState,
            selectedCandidateIds: state.selectedCandidateIds.filter(
              (candidateId) =>
                derivedState.selectableCandidateIdSet.has(candidateId),
            ),
          };
        }),

      setSelectedCandidateIds: (ids) =>
        set((state) => ({
          selectedCandidateIds: ids.filter((candidateId) =>
            state.selectableCandidateIdSet.has(candidateId),
          ),
        })),

      setCandidateAlias: (candidateId, alias) =>
        set((state) => ({
          candidateAliases: { ...state.candidateAliases, [candidateId]: alias },
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
      // Deliberately migration-free: a snapshot from the previous version is
      // discarded, resetting an onboarding session that was in flight when the
      // release landed. The persisted shape changed (normalized hierarchy,
      // organization type, discovery-resume fields) and this is per-tab
      // sessionStorage holding only wizard progress, so re-entering the flow is
      // cheaper and safer than migrating a shape we removed. Bumped to 2 to also
      // discard GCP hierarchies normalized by the pre-fix mapper, whose folder ids
      // came from a field the wire never had and cannot nest.
      version: 2,
      storage: createJSONStorage(() => sessionStorage),
      merge: (persistedState, currentState) => {
        const mergedState = {
          ...currentState,
          ...(persistedState as Partial<OrgSetupState>),
        };
        const derivedState = buildDerivedDiscoveryState(mergedState.hierarchy);

        return {
          ...mergedState,
          ...derivedState,
          organizationType:
            toOrgFlowType(mergedState.organizationType) ??
            currentState.organizationType,
          selectedCandidateIds: mergedState.selectedCandidateIds.filter(
            (candidateId) =>
              derivedState.selectableCandidateIdSet.has(candidateId),
          ),
        };
      },
      partialize: (state) => ({
        organizationType: state.organizationType,
        organizationId: state.organizationId,
        organizationName: state.organizationName,
        organizationExternalId: state.organizationExternalId,
        discoveryId: state.discoveryId,
        discoveryStatus: state.discoveryStatus,
        hierarchy: state.hierarchy,
        selectedCandidateIds: state.selectedCandidateIds,
        candidateAliases: state.candidateAliases,
      }),
    },
  ),
);
