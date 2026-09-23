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
  getProviderConnectionBaselines: vi.fn(),
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
  getFooterConfig: () => WizardFooterConfig | null;
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
    getFooterConfig: () => footerConfig,
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
    providersActionsMock.getProviderConnectionBaselines.mockResolvedValue({});
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
      providersActionsMock.getProviderConnectionBaselines.mockResolvedValue({
        [PROVIDER_ID]: "2025-01-01T00:00:00Z",
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

      // Then: read from the provider's own record, not reported as a timeout,
      // using the baseline captured for this provider before dispatch.
      await waitFor(() => {
        expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
          CONNECTION_TEST_STATUS.SUCCESS,
        );
      });
      expect(
        providersActionsMock.getProviderConnectionBaselines,
      ).toHaveBeenCalledWith([PROVIDER_ID]);
      expect(
        providerHelpersMock.resolveProviderConnectionState,
      ).toHaveBeenCalledWith(PROVIDER_ID, "2025-01-01T00:00:00Z");
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

    it("keeps the retry control available when every unresolved account is pending, not failed", async () => {
      // Given: no confirmed error, only a wait exhausted with no verdict --
      // `hasConnectionErrors` alone would hide "Test Connections" here.
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
      const { startTesting, getFooterConfig } = renderFlow();

      // When
      await startTesting();

      // Then: the action stays visible and enabled for a retry.
      await waitFor(() => {
        expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
          CONNECTION_TEST_STATUS.PENDING,
        );
      });
      const footerConfig = getFooterConfig();
      expect(footerConfig?.showAction).toBe(true);
      expect(footerConfig?.actionDisabled).toBe(false);
    });

    it("retries only the still-pending account, not one that already succeeded", async () => {
      // Given: two accounts selected, one project and one folder-scoped project
      // under the same GCP org so both resolve from a single apply.
      const OTHER_UID = "projects/acme-staging";
      const hierarchyWithTwoProjects: GcpOrgHierarchy = {
        ...GCP_HIERARCHY,
        candidates: [
          ...GCP_HIERARCHY.candidates,
          { uid: OTHER_UID, label: "Acme Staging", parentId: ORGANIZATION_UID },
        ],
      };
      const OTHER_PROVIDER_ID = "provider-2";
      const store = useOrgSetupStore.getState();
      store.setOrganizationType(ORGANIZATION_TYPE.GCP);
      store.setOrganization("org-1", "Acme", ORGANIZATION_UID);
      store.setDiscovery("discovery-1", hierarchyWithTwoProjects);
      store.setSelectedCandidateIds([PROJECT_UID, OTHER_UID]);

      organizationsActionsMock.applyDiscovery.mockResolvedValue({
        data: {
          relationships: {
            providers: {
              data: [{ id: PROVIDER_ID }, { id: OTHER_PROVIDER_ID }],
            },
          },
        },
      });
      providersActionsMock.getProviderUidsByIds.mockResolvedValue({
        [PROVIDER_ID]: PROJECT_UID,
        [OTHER_PROVIDER_ID]: OTHER_UID,
      });
      providersActionsMock.startProviderConnectionChecks.mockResolvedValue({
        [PROVIDER_ID]: { taskId: "task-1" },
        [OTHER_PROVIDER_ID]: { taskId: "task-2" },
      });
      tasksActionsMock.getTasksByIds.mockResolvedValue({
        "task-1": {
          data: {
            attributes: { state: "completed", result: { connected: true } },
          },
        },
        "task-2": { data: { attributes: { state: "executing" } } },
      });
      providerHelpersMock.resolveProviderConnectionState.mockImplementation(
        async (providerId: string) =>
          providerId === OTHER_PROVIDER_ID
            ? {
                status: CONNECTION_CHECK_STATUS.PENDING,
                error: "The connection test is still running.",
              }
            : { status: CONNECTION_CHECK_STATUS.SUCCESS, error: null },
      );
      pollConnectionTasksMock.mockImplementation(
        async (taskIds: string[], { onSettled, resolveExhausted }) => {
          for (const taskId of taskIds) {
            if (taskId === "task-1") {
              onSettled(taskId, { status: CONNECTION_CHECK_STATUS.SUCCESS });
              continue;
            }
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
      const { startTesting } = renderFlow();

      // First pass: one account succeeds, the other is left pending.
      await startTesting();
      await waitFor(() => {
        expect(
          useOrgSetupStore.getState().connectionResults[OTHER_PROVIDER_ID],
        ).toBe(CONNECTION_TEST_STATUS.PENDING);
      });
      expect(useOrgSetupStore.getState().connectionResults[PROVIDER_ID]).toBe(
        CONNECTION_TEST_STATUS.SUCCESS,
      );
      providersActionsMock.startProviderConnectionChecks.mockClear();

      // When: pressing "Test Connections" again to retry.
      await startTesting();

      // Then: only the still-pending account is re-dispatched.
      await waitFor(() => {
        expect(
          providersActionsMock.startProviderConnectionChecks,
        ).toHaveBeenCalled();
      });
      expect(
        providersActionsMock.startProviderConnectionChecks,
      ).toHaveBeenCalledWith([OTHER_PROVIDER_ID]);
    });
  });
});
