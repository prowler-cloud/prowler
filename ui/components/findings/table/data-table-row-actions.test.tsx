import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { MuteFindingsModalMock, isGroupedJiraDispatchEnabledMock } = vi.hoisted(
  () => ({
    MuteFindingsModalMock: vi.fn(() => null),
    isGroupedJiraDispatchEnabledMock: vi.fn(() => true),
  }),
);

const { SendToJiraModalMock } = vi.hoisted(() => ({
  SendToJiraModalMock: vi.fn(() => null),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: MuteFindingsModalMock,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: SendToJiraModalMock,
}));

vi.mock("@/lib/deployment", () => ({
  isGroupedJiraDispatchEnabled: isGroupedJiraDispatchEnabledMock,
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
    disabledTooltip,
  }: {
    label: string;
    onSelect?: () => void;
    disabled?: boolean;
    disabledTooltip?: string;
  }) => (
    <button onClick={onSelect} disabled={disabled} title={disabledTooltip}>
      {label}
    </button>
  ),
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => <span>Loading</span>,
}));

vi.mock("./finding-note-modal", () => ({
  FindingNoteModal: ({
    open,
    triage,
  }: {
    open: boolean;
    triage: {
      noteBody: string;
      canEdit: boolean;
      disabledReason?: string;
      billingHref: string;
    };
  }) =>
    open ? (
      <div role="dialog" aria-label="Note">
        <textarea
          aria-label="Note text"
          value={triage.noteBody}
          disabled={!triage.canEdit}
          readOnly
        />
        {triage.disabledReason === "cloud_only" && (
          <a href={triage.billingHref}>Available in Prowler Cloud</a>
        )}
        <button disabled={!triage.canEdit}>Save changes</button>
      </div>
    ) : null,
}));

import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import {
  DataTableRowActions,
  type FindingRowData,
} from "./data-table-row-actions";
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

function makeTriageSummary(
  overrides?: Partial<FindingTriageSummary>,
): FindingTriageSummary {
  return {
    findingId: "finding-1",
    findingUid: "prowler-finding-uid-1",
    triageId: "triage-1",
    notesCount: 0,
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: false,
    isMuted: false,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    ...overrides,
  };
}

function makeFindingRow(overrides?: Partial<FindingRowData>) {
  return {
    original: {
      id: "finding-1",
      attributes: {
        muted: false,
        check_metadata: {
          checktitle: "S3 public access",
        },
      },
      triage: makeTriageSummary(),
      ...overrides,
    },
  } as never;
}

describe("DataTableRowActions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
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

  it("allows choosing Jira dispatch mode for a group with multiple failing resources", async () => {
    // Given
    const user = userEvent.setup();
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
                id: "group-row-1",
                rowType: "group",
                checkId: "s3_bucket_public_access",
                checkTitle: "S3 bucket public access",
                mutedCount: 0,
                resourcesFail: 2,
                resourcesTotal: 2,
              },
            } as never
          }
        />
      </FindingsSelectionContext.Provider>,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Send Finding Group to Jira" }),
    );

    // Then
    expect(SendToJiraModalMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        targetIds: ["s3_bucket_public_access"],
        targetType: "check_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: true,
        selectedResourceCount: 2,
      }),
      undefined,
    );
  });

  it("shows disabled Cloud-only Jira action for finding groups outside cloud", async () => {
    // Given
    isGroupedJiraDispatchEnabledMock.mockReturnValue(false);
    const user = userEvent.setup();
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
                id: "group-row-1",
                rowType: "group",
                checkId: "s3_bucket_public_access",
                checkTitle: "S3 bucket public access",
                mutedCount: 0,
                resourcesFail: 2,
                resourcesTotal: 2,
              },
            } as never
          }
        />
      </FindingsSelectionContext.Provider>,
    );

    // When
    const jiraButton = screen.getByRole("button", {
      name: "Send Finding Group to Jira",
    });
    await user.click(jiraButton);

    // Then
    expect(jiraButton).toBeVisible();
    expect(jiraButton).toBeDisabled();
    expect(jiraButton).toHaveAttribute(
      "title",
      "Available only in Prowler Cloud",
    );
    expect(SendToJiraModalMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ isOpen: true }),
      undefined,
    );
  });

  it("does not offer Jira dispatch mode choice for a group with one failing resource", async () => {
    // Given
    const user = userEvent.setup();
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
                id: "group-row-1",
                rowType: "group",
                checkId: "s3_bucket_public_access",
                checkTitle: "S3 bucket public access",
                mutedCount: 0,
                resourcesFail: 1,
                resourcesTotal: 1,
              },
            } as never
          }
        />
      </FindingsSelectionContext.Provider>,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Send Finding Group to Jira" }),
    );

    // Then
    expect(SendToJiraModalMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        targetIds: ["s3_bucket_public_access"],
        targetType: "check_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: false,
        selectedResourceCount: 1,
      }),
      undefined,
    );
  });

  it("uses grouped Jira dispatch for mixed selected finding groups", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingsSelectionContext.Provider
        value={{
          selectedFindingIds: ["check-a", "check-b"],
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
                id: "group-row-1",
                rowType: "group",
                checkId: "check-a",
                checkTitle: "Check A",
                mutedCount: 0,
                resourcesFail: 2,
                resourcesTotal: 2,
              },
            } as never
          }
        />
      </FindingsSelectionContext.Provider>,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Send 2 Finding Groups to Jira" }),
    );

    // Then
    expect(SendToJiraModalMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        targetIds: ["check-a", "check-b"],
        targetType: "check_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: false,
      }),
      undefined,
    );
  });

  it("allows choosing Jira dispatch mode for multiple selected findings", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingsSelectionContext.Provider
        value={{
          selectedFindingIds: ["finding-1", "finding-2"],
          selectedFindings: [],
          clearSelection: vi.fn(),
          isSelected: vi.fn(),
        }}
      >
        <DataTableRowActions row={makeFindingRow()} />
      </FindingsSelectionContext.Provider>,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Send 2 Findings to Jira" }),
    );

    // Then
    expect(SendToJiraModalMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        targetIds: ["finding-1", "finding-2"],
        targetType: "finding_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: true,
      }),
      undefined,
    );
  });

  it("keeps single finding Jira dispatch enabled when other rows are selected outside cloud", async () => {
    // Given
    isGroupedJiraDispatchEnabledMock.mockReturnValue(false);
    const user = userEvent.setup();
    render(
      <FindingsSelectionContext.Provider
        value={{
          selectedFindingIds: ["finding-2", "finding-3"],
          selectedFindings: [],
          clearSelection: vi.fn(),
          isSelected: vi.fn(),
        }}
      >
        <DataTableRowActions row={makeFindingRow()} />
      </FindingsSelectionContext.Provider>,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: "Send 1 Finding to Jira" }),
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Send 1 Finding to Jira" }),
    ).toBeEnabled();
    expect(SendToJiraModalMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        isOpen: true,
        targetIds: ["finding-1"],
        targetType: "finding_id",
        defaultDispatchMode: "individual",
        canChooseGroupedDispatch: false,
      }),
      undefined,
    );
  });

  it("shows Add Triage Note for editable findings without a note", () => {
    // Given / When
    render(
      <DataTableRowActions
        row={makeFindingRow()}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Add Triage Note" }),
    ).toBeEnabled();
  });

  it("loads an existing note before opening the note modal", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageNoteLoadAction = vi.fn().mockResolvedValue({
      noteId: "note-1",
      noteBody: "Loaded existing note",
    });
    render(
      <DataTableRowActions
        row={makeFindingRow({
          triage: makeTriageSummary({ hasVisibleNote: true, notesCount: 1 }),
        })}
        onTriageUpdateAction={vi.fn()}
        onTriageNoteLoadAction={onTriageNoteLoadAction}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Open note" }));

    // Then
    expect(onTriageNoteLoadAction).toHaveBeenCalledWith(
      expect.objectContaining({ triageId: "triage-1", notesCount: 1 }),
    );
    expect(await screen.findByRole("dialog", { name: "Note" })).toBeVisible();
    expect(screen.getByLabelText("Note text")).toHaveValue(
      "Loaded existing note",
    );
  });

  it("opens a disabled Cloud-only note modal from finding actions", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={makeFindingRow({
          triage: makeTriageSummary({
            canEdit: false,
            hasVisibleNote: false,
            disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
          }),
        })}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Add Triage Note" }));

    // Then
    expect(screen.getByRole("dialog", { name: "Note" })).toBeVisible();
    expect(screen.getByLabelText("Note text")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(
      screen.getByRole("link", { name: "Available in Prowler Cloud" }),
    ).toHaveAttribute("href", "https://prowler.com/pricing");
  });
});
