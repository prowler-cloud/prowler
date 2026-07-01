import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: ReactNode;
    open: boolean;
    title?: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    ) : null,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
  }),
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdownItem: ({
    label,
    onSelect,
    disabled,
  }: {
    label: ReactNode;
    onSelect?: () => void;
    disabled?: boolean;
  }) => (
    <button disabled={disabled} onClick={onSelect}>
      {label}
    </button>
  ),
}));

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import {
  FindingNoteActionItem,
  FindingTriageStatusCell,
} from "./finding-triage-cells";

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

describe("finding triage cells", () => {
  it("should open the Note modal from the note action with the current status preselected", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNoteActionItem
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.REMEDIATING,
          label: "Remediating",
        })}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    // When
    const addNoteButton = screen.getByRole("button", { name: "Add note" });
    expect(addNoteButton).toHaveTextContent("Add note");
    await user.click(addNoteButton);

    // Then
    expect(
      screen.getByRole("dialog", { name: "Triage Note" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
  });

  it("should not propagate table status clicks to the row", async () => {
    // Given
    const user = userEvent.setup();
    const onRowClick = vi.fn();
    render(
      <div onClick={onRowClick}>
        <FindingTriageStatusCell
          triage={makeTriageSummary({
            status: FINDING_TRIAGE_STATUS.OPEN,
            label: "Open",
          })}
          onTriageUpdateAction={vi.fn()}
        />
      </div>,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));

    // Then
    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("should render status picker with fixed width and colored options", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.REMEDIATING,
          label: "Remediating",
        })}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    const statusControl = screen.getByRole("combobox", {
      name: "Triage status",
    });

    // When
    await user.click(statusControl);

    // Then
    expect(statusControl.parentElement).toHaveClass("w-20");
    expect(within(statusControl).getByText("Remediating")).toHaveClass(
      "text-bg-data-info",
    );
    expect(
      within(screen.getByRole("option", { name: "Open" })).getByText("Open"),
    ).toHaveClass("text-text-error-primary");
    expect(
      within(screen.getByRole("option", { name: "Under Review" })).getByText(
        "Under Review",
      ),
    ).toHaveClass("text-bg-data-kubernetes");
    expect(
      within(screen.getByRole("option", { name: "Remediating" })).getByText(
        "Remediating",
      ),
    ).toHaveClass("text-bg-data-info");
    expect(
      within(screen.getByRole("option", { name: "Risk Accepted" })).getByText(
        "Risk Accepted",
      ),
    ).toHaveClass("text-bg-pass");
    expect(
      within(screen.getByRole("option", { name: "False Positive" })).getByText(
        "False Positive",
      ),
    ).toHaveClass("text-text-neutral-secondary");
  });

  it("should disable table status mutation when no update handler is wired", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
          canEdit: true,
        })}
      />,
    );

    const statusControl = screen.getByRole("combobox", {
      name: "Triage status",
    });

    // When
    await user.click(statusControl);

    // Then
    expect(statusControl).toBeDisabled();
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  });

  it("should not open an editable empty-note modal for an existing note without a loader", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNoteActionItem
        triage={makeTriageSummary({ hasVisibleNote: true })}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    const existingNoteButton = screen.getByRole("button", {
      name: "Open note",
    });

    // When
    await user.click(existingNoteButton);

    // Then
    expect(existingNoteButton).toBeDisabled();
    expect(
      screen.queryByRole("dialog", { name: "Triage Note" }),
    ).not.toBeInTheDocument();
  });

  it("should load an existing note before opening the modal", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageNoteLoadAction = vi.fn().mockResolvedValue({
      noteId: "note-1",
      noteBody: "Loaded existing note",
    });
    render(
      <FindingNoteActionItem
        triage={makeTriageSummary({ hasVisibleNote: true, notesCount: 1 })}
        findingContext={{ title: "S3 bucket allows public reads" }}
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
    expect(
      await screen.findByRole("dialog", { name: "Triage Note" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Note text")).toHaveValue(
      "Loaded existing note",
    );
  });

  it("should open a disabled billing upsell modal for Cloud-only Add note", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNoteActionItem
        triage={makeTriageSummary({
          canEdit: false,
          hasVisibleNote: false,
          disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
        })}
        findingContext={{ title: "S3 bucket allows public reads" }}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Add note" }));

    // Then
    expect(screen.getByRole("dialog", { name: "Triage Note" })).toBeVisible();
    expect(screen.getByLabelText("Note text")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(
      screen.getByRole("link", { name: "Available in Prowler Cloud" }),
    ).toHaveAttribute("href", "https://prowler.com/pricing");
  });

  it("should disable Add note when no update handler is wired", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNoteActionItem
        triage={makeTriageSummary({ hasVisibleNote: false, canEdit: true })}
        findingContext={{ title: "S3 bucket allows public reads" }}
      />,
    );

    const addNoteButton = screen.getByRole("button", { name: "Add note" });

    // When
    await user.click(addNoteButton);

    // Then
    expect(addNoteButton).toBeDisabled();
    expect(
      screen.queryByRole("dialog", { name: "Triage Note" }),
    ).not.toBeInTheDocument();
  });

  it("should expose a screen-reader error when an existing note cannot load", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageNoteLoadAction = vi
      .fn()
      .mockRejectedValue(new Error("load failed"));
    render(
      <FindingNoteActionItem
        triage={makeTriageSummary({ hasVisibleNote: true, notesCount: 1 })}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
        onTriageNoteLoadAction={onTriageNoteLoadAction}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Open note" }));

    // Then
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load the existing note.",
    );
    expect(
      screen.queryByRole("dialog", { name: "Triage Note" }),
    ).not.toBeInTheDocument();
  });

  it("should keep the optimistic table status while stale props are rendered during update", async () => {
    // Given
    const user = userEvent.setup();
    let resolveUpdate: () => void = () => {};
    const onTriageUpdateAction = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveUpdate = resolve;
        }),
    );
    const { rerender } = render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    const statusControl = screen.getByRole("combobox", {
      name: "Triage status",
    });

    // When: user selects a new status.
    await user.click(statusControl);
    await user.click(screen.getByRole("option", { name: "Under Review" }));

    // Then: the optimistic status is visible immediately.
    expect(statusControl).toHaveTextContent("Under Review");

    // When: the parent renders stale data while the request is still pending.
    rerender(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    // Then: the control must not flicker back to Open.
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Under Review");

    // When: backend completes and fresh props arrive.
    resolveUpdate();
    await waitFor(() => expect(onTriageUpdateAction).toHaveBeenCalled());
    rerender(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
          label: "Under Review",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    // Then
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Under Review");
  });

  it("should refresh the visible table status when triage props change", () => {
    // Given
    const { rerender } = render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
        })}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Open");

    // When
    rerender(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.REMEDIATING,
          label: "Remediating",
        })}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
  });

  it("should not submit when table status selection matches the current status", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Open" }));

    // Then
    expect(onTriageUpdateAction).not.toHaveBeenCalled();
  });

  it("should rollback table status and expose an error when update fails", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn().mockRejectedValue(new Error("fail"));
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    const statusControl = screen.getByRole("combobox", {
      name: "Triage status",
    });

    // When
    await user.click(statusControl);
    await user.click(screen.getByRole("option", { name: "Remediating" }));

    // Then
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not update triage status.",
    );
    expect(statusControl).toHaveTextContent("Open");
  });

  it("should not confirm when moving between Mutelist shortcut statuses", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
          label: "Risk Accepted",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "False Positive" }));

    // Then
    expect(screen.queryByRole("dialog", { name: "Mute finding?" })).toBeNull();
    await waitFor(() =>
      expect(onTriageUpdateAction).toHaveBeenCalledWith(
        expect.objectContaining({
          status: FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
          previousStatus: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
          isMuted: false,
        }),
      ),
    );
  });

  it("should not confirm or mute again when an already muted finding enters a shortcut status", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
          isMuted: true,
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Risk Accepted" }));

    // Then
    expect(screen.queryByRole("dialog", { name: "Mute finding?" })).toBeNull();
    await waitFor(() =>
      expect(onTriageUpdateAction).toHaveBeenCalledWith(
        expect.objectContaining({
          status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
          previousStatus: FINDING_TRIAGE_STATUS.OPEN,
          isMuted: true,
        }),
      ),
    );
  });

  it("should confirm before applying Mutelist shortcut statuses from the table", async () => {
    // Given
    const user = userEvent.setup();
    let resolveUpdate: () => void = () => {};
    const onTriageUpdateAction = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveUpdate = resolve;
        }),
    );
    render(
      <FindingTriageStatusCell
        triage={makeTriageSummary({
          status: FINDING_TRIAGE_STATUS.OPEN,
          label: "Open",
        })}
        onTriageUpdateAction={onTriageUpdateAction}
      />,
    );

    const statusControl = screen.getByRole("combobox", {
      name: "Triage status",
    });

    // When: user selects a Mutelist shortcut.
    await user.click(statusControl);
    await user.click(screen.getByRole("option", { name: "False Positive" }));

    // Then: the user is warned before the server action handles muting.
    expect(screen.getByRole("dialog", { name: "Mute finding?" })).toBeVisible();
    expect(onTriageUpdateAction).not.toHaveBeenCalled();

    // When
    await user.click(screen.getByRole("button", { name: "Mute finding" }));

    // Then
    await waitFor(() =>
      expect(onTriageUpdateAction).toHaveBeenCalledWith({
        findingId: "finding-1",
        findingUid: "prowler-finding-uid-1",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
        previousStatus: FINDING_TRIAGE_STATUS.OPEN,
        isMuted: false,
      }),
    );
    expect(statusControl).toHaveTextContent("False Positive");

    resolveUpdate();
  });
});
