import { render, screen, waitFor } from "@testing-library/react";
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
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

import {
  FindingNotesCell,
  FindingTriageStatusCell,
} from "./finding-triage-cells";

function makeTriageSummary(
  overrides?: Partial<FindingTriageSummary>,
): FindingTriageSummary {
  return {
    findingId: "finding-1",
    findingUid: "prowler-finding-uid-1",
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: false,
    hasPersistedStatus: true,
    canEdit: true,
    billingHref: "/billing",
    mutelistShortcutStatuses: [
      FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
    ],
    ...overrides,
  };
}

describe("finding triage cells", () => {
  it("should open the Note modal from table notes with the current status preselected", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNotesCell
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
    expect(screen.getByRole("dialog", { name: "Note" })).toBeInTheDocument();
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

  it("should not open an editable empty-note modal for an existing note without detail", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNotesCell
        triage={makeTriageSummary({ hasVisibleNote: true })}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    const existingNoteButton = screen.getByRole("button", {
      name: "Note exists",
    });

    // When
    await user.click(existingNoteButton);

    // Then
    expect(existingNoteButton).toBeDisabled();
    expect(
      screen.queryByRole("dialog", { name: "Note" }),
    ).not.toBeInTheDocument();
  });

  it("should disable Add note when no update handler is wired", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingNotesCell
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
      screen.queryByRole("dialog", { name: "Note" }),
    ).not.toBeInTheDocument();
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

  it("should keep Mutelist status pending until accepted and restore the previous status on cancel", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction =
      vi.fn<(input: UpdateFindingTriageInput) => void>();
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

    // When: user selects a Mutelist shortcut but cancels the confirmation.
    await user.click(statusControl);
    await user.click(screen.getByRole("option", { name: "False Positive" }));

    // Then: the update has not fired and the visible status remains Open.
    await waitFor(() =>
      expect(screen.queryByRole("listbox")).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("dialog", { name: /mutelist/i })).toBeVisible();
    expect(screen.getByText(/will be muted/i)).toBeVisible();
    expect(onTriageUpdateAction).not.toHaveBeenCalled();
    expect(statusControl).toHaveTextContent("Open");

    // When: user cancels.
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    // Then: previous status is restored and no update happened.
    expect(
      screen.queryByRole("dialog", { name: /mutelist/i }),
    ).not.toBeInTheDocument();
    expect(statusControl).toHaveTextContent("Open");
    expect(onTriageUpdateAction).not.toHaveBeenCalled();

    // When: user selects again and accepts.
    await user.click(statusControl);
    await user.click(screen.getByRole("option", { name: "False Positive" }));
    await waitFor(() =>
      expect(screen.queryByRole("listbox")).not.toBeInTheDocument(),
    );
    await user.click(screen.getByRole("button", { name: "Accept" }));

    // Then: the pending status is committed.
    await waitFor(() =>
      expect(onTriageUpdateAction).toHaveBeenCalledWith({
        findingId: "finding-1",
        status: FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
        origin: "table",
      }),
    );
    expect(statusControl).toHaveTextContent("False Positive");
  });
});
