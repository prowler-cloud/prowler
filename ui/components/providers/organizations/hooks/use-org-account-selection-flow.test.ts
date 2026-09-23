import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  CONNECTION_TEST_STATUS,
  type GcpOrgHierarchy,
  ORGANIZATION_TYPE,
} from "@/types/organizations";
import { CONNECTION_CHECK_STATUS } from "@/types/providers";

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
const providerHelpersMock = vi.hoisted(() => ({
  resolveProviderConnectionState: vi.fn(),
}));
const pollConnectionTasksMock = vi.hoisted(() => vi.fn());
// Mutable holder for the real `pollConnectionTasks`, captured once the module
// mock factory below runs, and re-applied in `beforeEach` since
// `mockReset: true` clears `pollConnectionTasksMock`'s implementation before
// every test.
const realPollConnectionTasksHolder = vi.hoisted(
  () => ({}) as { current?: (...args: unknown[]) => unknown },
);

vi.mock(
  "@/actions/organizations/organizations",
  () => organizationsActionsMock,
);
vi.mock("@/actions/providers/providers", () => providersActionsMock);
vi.mock("@/actions/task/tasks", () => tasksActionsMock);
vi.mock("@/lib/provider-helpers", () => providerHelpersMock);
vi.mock("../org-account-selection.utils", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../org-account-selection.utils")>();
  realPollConnectionTasksHolder.current = actual.pollConnectionTasks as (
    ...args: unknown[]
  ) => unknown;
  return { ...actual, pollConnectionTasks: pollConnectionTasksMock };
});

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
      ...Object.values(providerHelpersMock),
    ]) {
      mockFn.mockReset();
    }
    pollConnectionTasksMock.mockReset();
    pollConnectionTasksMock.mockImplementation((...args: unknown[]) =>
      realPollConnectionTasksHolder.current?.(...args),
    );

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

    it("resolves a still-pending task from the provider's persisted state once the wait is exhausted", async () => {
      // Given the batch poll never settles the task before retries run out.
      seedAppliedSelection();
      providersActionsMock.startProviderConnectionChecks.mockResolvedValue({
        [PROVIDER_ID]: { taskId: "task-1" },
      });
      providerHelpersMock.resolveProviderConnectionState.mockResolvedValue({
        status: CONNECTION_CHECK_STATUS.SUCCESS,
        error: null,
      });
      pollConnectionTasksMock.mockImplementation(
        async (taskIds: string[], { onSettled, resolveExhausted }) => {
          for (const taskId of taskIds) {
            const resolved = resolveExhausted
              ? await resolveExhausted(taskId)
              : null;
            onSettled(
              taskId,
              resolved ?? {
                status: CONNECTION_CHECK_STATUS.FAILED,
                error: "Connection test timed out.",
              },
            );
          }
        },
      );
      const { onNext, startTesting } = renderFlow();

      // When
      await startTesting();

      // Then: read from the provider's own record, not reported as a timeout.
      await waitFor(() => {
        expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
          CONNECTION_TEST_STATUS.SUCCESS,
        );
      });
      expect(
        providerHelpersMock.resolveProviderConnectionState,
      ).toHaveBeenCalledWith(PROVIDER_ID, expect.any(String));
      expect(onNext).toHaveBeenCalledTimes(1);
    });

    it("does not report a still-running fallback as a connection failure", async () => {
      // Given: the wait exhausts and the provider's own record cannot confirm
      // an outcome either (the backend check is genuinely still running).
      seedAppliedSelection();
      providersActionsMock.startProviderConnectionChecks.mockResolvedValue({
        [PROVIDER_ID]: { taskId: "task-1" },
      });
      providerHelpersMock.resolveProviderConnectionState.mockResolvedValue({
        status: CONNECTION_CHECK_STATUS.PENDING,
        error: "The connection test is still running.",
      });
      pollConnectionTasksMock.mockImplementation(
        async (taskIds: string[], { onSettled, resolveExhausted }) => {
          for (const taskId of taskIds) {
            const resolved = resolveExhausted
              ? await resolveExhausted(taskId)
              : null;
            onSettled(
              taskId,
              resolved ?? {
                status: CONNECTION_CHECK_STATUS.FAILED,
                error: "Connection test timed out.",
              },
            );
          }
        },
      );
      const { onNext, startTesting } = renderFlow();

      // When
      await startTesting();

      // Then: neither a success (does not auto-advance) nor an error.
      await waitFor(() => {
        expect(
          providerHelpersMock.resolveProviderConnectionState,
        ).toHaveBeenCalled();
      });
      expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
        CONNECTION_TEST_STATUS.PENDING,
      );
      expect(onNext).not.toHaveBeenCalled();
    });
  });
});
