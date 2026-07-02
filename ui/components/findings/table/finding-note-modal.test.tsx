import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIcon: ({ type }: { type: string }) => (
    <span data-testid={`${type}-provider-badge`}>{type} icon</span>
  ),
}));

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
  FINDING_TRIAGE_NOTE_PRIVACY_COPY,
  FINDING_TRIAGE_STATUS,
  type FindingTriageDetail,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

import {
  FindingNoteModal,
  type FindingTriageContext,
} from "./finding-note-modal";

function makeTriageDetail(
  overrides?: Partial<FindingTriageDetail>,
): FindingTriageDetail {
  return {
    findingId: "finding-1",
    findingUid: "prowler-finding-uid-1",
    triageId: "triage-1",
    notesCount: 1,
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: true,
    isMuted: false,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    noteId: "note-1",
    noteBody: "Existing investigation note",
    maxNoteLength: 500,
    privacyCopy: FINDING_TRIAGE_NOTE_PRIVACY_COPY,
    ...overrides,
  };
}

function renderNoteModal({
  triage = makeTriageDetail(),
  onTriageUpdateAction = vi.fn(),
  onOpenChange = vi.fn(),
  findingContext = {
    title: "S3 bucket allows public reads",
    resource: "production-bucket",
    provider: "production-account",
  },
}: {
  triage?: FindingTriageDetail;
  onTriageUpdateAction?: (input: UpdateFindingTriageInput) => void;
  onOpenChange?: (open: boolean) => void;
  findingContext?: FindingTriageContext;
} = {}) {
  render(
    <FindingNoteModal
      open
      onOpenChange={onOpenChange}
      triage={triage}
      findingContext={findingContext}
      onTriageUpdateAction={onTriageUpdateAction}
    />,
  );

  return { onTriageUpdateAction, onOpenChange };
}

describe("FindingNoteModal", () => {
  it("should render the provider badge from the row provider type", () => {
    // Given / When
    renderNoteModal({
      findingContext: {
        title: "Azure finding",
        provider: "azure-subscription",
        providerType: "azure",
      },
    });

    // Then
    expect(screen.getByTestId("azure-provider-badge")).toBeVisible();
    expect(screen.queryByText("AWS")).not.toBeInTheDocument();
  });

  it("should open with title Add Triage Note and current status preselected", () => {
    // Given / When
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
      }),
    });

    // Then
    const dialog = screen.getByRole("dialog", { name: "Add Triage Note" });
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText("S3 bucket allows public reads"));
    expect(
      within(dialog).getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
    expect(
      within(dialog).getByText(/automatically changed to Resolved/i),
    ).toBeVisible();
  });

  it("should send existing note changes with noteId and without duplicate-note status payload", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({ onTriageUpdateAction });

    // When
    const textarea = screen.getByLabelText("Note text");
    await user.clear(textarea);
    await user.type(textarea, "Documented owner follow-up.");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // Then
    expect(onTriageUpdateAction).toHaveBeenCalledWith({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      isMuted: false,
      note: "Documented owner follow-up.",
    });
  });

  it("should send status plus note only when creating the first note", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({
      triage: makeTriageDetail({
        triageId: null,
        notesCount: 0,
        noteId: null,
        noteBody: "",
        hasVisibleNote: false,
      }),
      onTriageUpdateAction,
    });

    // When
    const textarea = screen.getByLabelText("Note text");
    await user.type(textarea, " Initial triage note. ");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // Then
    expect(onTriageUpdateAction).toHaveBeenCalledWith({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: null,
      notesCount: 0,
      noteId: null,
      isMuted: false,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      note: "Initial triage note.",
    });
  });

  it("should send an empty body when an existing note is cleared", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({ onOpenChange, onTriageUpdateAction });

    // When
    await user.clear(screen.getByLabelText("Note text"));
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // Then
    expect(onTriageUpdateAction).toHaveBeenCalledWith({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      isMuted: false,
      note: "",
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("should keep the modal open and show an error when note update fails", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const onTriageUpdateAction = vi.fn().mockRejectedValue(new Error("fail"));
    renderNoteModal({ onOpenChange, onTriageUpdateAction });

    // When
    await user.clear(screen.getByLabelText("Note text"));
    await user.type(screen.getByLabelText("Note text"), "Changed note");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // Then
    expect(
      await screen.findByText("Could not update the note. Please try again."),
    ).toBeVisible();
    expect(
      screen.getByRole("dialog", { name: "Add Triage Note" }),
    ).toBeInTheDocument();
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  it("should render counter, privacy copy, and cancel/update actions", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    renderNoteModal({ onOpenChange });

    // When
    await user.clear(screen.getByLabelText("Note text"));
    await user.type(screen.getByLabelText("Note text"), "abc");

    // Then
    expect(screen.getByText("3/500")).toBeInTheDocument();
    expect(screen.getByText(FINDING_TRIAGE_NOTE_PRIVACY_COPY)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(
      screen.getByRole("button", { name: "Save changes" }),
    ).toBeInTheDocument();
  });

  it("should disable controls and show the Cloud upsell badge for non-paying users", () => {
    // Given
    renderNoteModal({
      triage: makeTriageDetail({
        canEdit: false,
        disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
      }),
    });

    // Then
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveAttribute("data-disabled", "");
    expect(screen.getByLabelText("Note text")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(
      screen.getByRole("link", { name: "Available in Prowler Cloud" }),
    ).toHaveAttribute("href", "https://prowler.com/pricing");
    expect(screen.queryByText(/will be muted/i)).not.toBeInTheDocument();
  });

  it("should show modal-origin Mutelist info and still save accepted-risk statuses", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.OPEN,
        label: "Open",
        noteBody: "",
      }),
      onTriageUpdateAction,
    });

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Risk Accepted" }));

    // Then
    expect(screen.getByText(/will be muted/i)).toBeVisible();
    await waitFor(() =>
      expect(screen.queryByRole("listbox")).not.toBeInTheDocument(),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    // Then
    await waitFor(() =>
      expect(onTriageUpdateAction).toHaveBeenCalledWith({
        findingId: "finding-1",
        findingUid: "prowler-finding-uid-1",
        triageId: "triage-1",
        notesCount: 1,
        noteId: "note-1",
        isMuted: false,
        status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        previousStatus: FINDING_TRIAGE_STATUS.OPEN,
      }),
    );
  });
});
