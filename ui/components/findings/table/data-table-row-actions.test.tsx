import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { MuteFindingsModalMock } = vi.hoisted(() => ({
  MuteFindingsModalMock: vi.fn(() => null),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: MuteFindingsModalMock,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
}));

vi.mock("@/components/icons/services/IconServices", () => ({
  JiraIcon: () => null,
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownItem: ({
    label,
    onSelect,
    disabled,
  }: {
    label: string;
    onSelect: () => void;
    disabled?: boolean;
  }) => (
    <button onClick={onSelect} disabled={disabled}>
      {label}
    </button>
  ),
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => <span>Loading</span>,
}));

import { DataTableRowActions } from "./data-table-row-actions";
import { FindingsSelectionContext } from "./findings-selection-context";

function deferredPromise<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

describe("DataTableRowActions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("opens the mute modal immediately in preparing state for finding groups", async () => {
    // Given
    const deferred = deferredPromise<string[]>();
    const resolveMuteIds = vi.fn().mockReturnValue(deferred.promise);
    const user = userEvent.setup();

    render(
      <FindingsSelectionContext.Provider
        value={{
          selectedFindingIds: [],
          selectedFindings: [],
          clearSelection: vi.fn(),
          isSelected: vi.fn(),
          resolveMuteIds,
        }}
      >
        <DataTableRowActions
          row={
            {
              original: {
                id: "group-row-1",
                rowType: "group",
                checkId: "ecs_task_definitions_no_environment_secrets",
                checkTitle: "ECS task definitions no environment secrets",
                mutedCount: 0,
                resourcesFail: 475,
                resourcesTotal: 475,
              },
            } as never
          }
        />
      </FindingsSelectionContext.Provider>,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Mute Finding Group" }),
    );

    // Then
    const preparingCall = (
      MuteFindingsModalMock.mock.calls as unknown as Array<
        [
          {
            isOpen: boolean;
            isPreparing?: boolean;
            findingIds: string[];
          },
        ]
      >
    ).at(-1);

    expect(preparingCall?.[0]).toMatchObject({
      isOpen: true,
      isPreparing: true,
      findingIds: [],
    });

    // And when the resolver finishes
    deferred.resolve(["finding-1", "finding-2"]);

    await waitFor(() => {
      const resolvedCall = (
        MuteFindingsModalMock.mock.calls as unknown as Array<
          [
            {
              isOpen: boolean;
              isPreparing?: boolean;
              findingIds: string[];
            },
          ]
        >
      ).at(-1);

      expect(resolvedCall?.[0]).toMatchObject({
        isOpen: true,
        isPreparing: false,
        findingIds: ["finding-1", "finding-2"],
      });
    });
  });

  it("disables the mute action for groups without impacted resources", () => {
    render(
      <FindingsSelectionContext.Provider
        value={{
          selectedFindingIds: [],
          selectedFindings: [],
          clearSelection: vi.fn(),
          isSelected: vi.fn(),
          resolveMuteIds: vi.fn(),
        }}
      >
        <DataTableRowActions
          row={
            {
              original: {
                id: "group-row-2",
                rowType: "group",
                checkId: "check-with-zero-failures",
                checkTitle: "Check with zero failures",
                mutedCount: 0,
                resourcesFail: 0,
                resourcesTotal: 42,
              },
            } as never
          }
        />
      </FindingsSelectionContext.Provider>,
    );

    expect(
      screen.getByRole("button", { name: "Mute Finding Group" }),
    ).toBeDisabled();
  });
});
