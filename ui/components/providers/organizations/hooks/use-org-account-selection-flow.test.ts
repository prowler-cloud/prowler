import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  CONNECTION_TEST_STATUS,
  type GcpOrgHierarchy,
  ORGANIZATION_TYPE,
} from "@/types/organizations";

import { useOrgAccountSelectionFlow } from "./use-org-account-selection-flow";

const organizationsActionsMock = vi.hoisted(() => ({
  applyDiscovery: vi.fn(),
}));
const providersActionsMock = vi.hoisted(() => ({
  getProviderUidsByIds: vi.fn(),
  revalidateProviders: vi.fn(),
  startProviderConnectionChecks: vi.fn(),
}));
const tasksActionsMock = vi.hoisted(() => ({
  getTasksByIds: vi.fn(),
}));

vi.mock(
  "@/actions/organizations/organizations",
  () => organizationsActionsMock,
);
vi.mock("@/actions/providers/providers", () => providersActionsMock);
vi.mock("@/actions/task/tasks", () => tasksActionsMock);

const ORGANIZATION_UID = "organizations/123456789012";
const PROJECT_UID = "projects/acme-prod";
const PROVIDER_ID = "provider-1";

const GCP_HIERARCHY: GcpOrgHierarchy = {
  orgType: ORGANIZATION_TYPE.GCP,
  organization: { uid: ORGANIZATION_UID, name: "Acme" },
  nodes: [],
  candidates: [
    { uid: PROJECT_UID, label: "Acme Prod", parentId: ORGANIZATION_UID },
  ],
};

/** Seeds the store as the discovery step leaves it, with the project selected. */
function seedAppliedSelection() {
  const store = useOrgSetupStore.getState();
  store.setOrganizationType(ORGANIZATION_TYPE.GCP);
  store.setOrganization("org-1", "Acme", ORGANIZATION_UID);
  store.setDiscovery("discovery-1", GCP_HIERARCHY);
  store.setSelectedCandidateIds([PROJECT_UID]);
}

interface RenderedFlow {
  onNext: ReturnType<typeof vi.fn>;
  startTesting: () => Promise<void>;
}

function renderFlow(): RenderedFlow {
  const onNext = vi.fn();
  let footerConfig: WizardFooterConfig | null = null;

  renderHook(() =>
    useOrgAccountSelectionFlow({
      onBack: vi.fn(),
      onNext,
      onSkip: vi.fn(),
      onFooterChange: (config) => {
        footerConfig = config;
      },
    }),
  );

  return {
    onNext,
    startTesting: async () => {
      await act(async () => {
        footerConfig?.onAction?.();
      });
    },
  };
}

describe("useOrgAccountSelectionFlow", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useOrgSetupStore.getState().reset();
    for (const mockFn of [
      ...Object.values(organizationsActionsMock),
      ...Object.values(providersActionsMock),
      ...Object.values(tasksActionsMock),
    ]) {
      mockFn.mockReset();
    }

    organizationsActionsMock.applyDiscovery.mockResolvedValue({
      data: {
        relationships: { providers: { data: [{ id: PROVIDER_ID }] } },
      },
    });
    providersActionsMock.getProviderUidsByIds.mockResolvedValue({
      [PROVIDER_ID]: PROJECT_UID,
    });
    providersActionsMock.revalidateProviders.mockResolvedValue(undefined);
  });

  describe("connection test outcomes", () => {
    it("fails a provider whose check was dispatched without a task id", async () => {
      // Given a 2xx dispatch that carried no task, so nothing was ever tested.
      seedAppliedSelection();
      providersActionsMock.startProviderConnectionChecks.mockResolvedValue({
        [PROVIDER_ID]: {},
      });
      const { onNext, startTesting } = renderFlow();

      // When
      await startTesting();

      // Then
      await waitFor(() => {
        expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
          CONNECTION_TEST_STATUS.ERROR,
        );
      });
      expect(
        useOrgSetupStore.getState().connectionErrors[PROVIDER_ID],
      ).toBeTruthy();
      expect(onNext).not.toHaveBeenCalled();
    });

    it("advances once every dispatched task reports a connection", async () => {
      // Given
      seedAppliedSelection();
      providersActionsMock.startProviderConnectionChecks.mockResolvedValue({
        [PROVIDER_ID]: { taskId: "task-1" },
      });
      tasksActionsMock.getTasksByIds.mockResolvedValue({
        "task-1": {
          data: {
            attributes: { state: "completed", result: { connected: true } },
          },
        },
      });
      const { onNext, startTesting } = renderFlow();

      // When
      await startTesting();

      // Then
      await waitFor(() => {
        expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
          CONNECTION_TEST_STATUS.SUCCESS,
        );
      });
      expect(onNext).toHaveBeenCalledTimes(1);
    });
  });
});
