import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeAll, describe, expect, it, vi } from "vitest";

const { routerPushMock } = vi.hoisted(() => ({
  routerPushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: routerPushMock,
  }),
}));

vi.mock("@/components/icons/providers-badge", () => ({
  PROVIDER_BADGE_BY_NAME: {
    AWS: () => <span data-testid="aws-provider-badge">AWS icon</span>,
    Azure: () => <span data-testid="azure-provider-badge">Azure icon</span>,
  },
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
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: true,
    hasPersistedStatus: true,
    canEdit: true,
    billingHref: "/billing",
    mutelistShortcutStatuses: [
      FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
    ],
    noteBody: "Existing investigation note",
    maxNoteLength: 300,
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

  it("should open with title Note and current status preselected", () => {
    // Given / When
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
      }),
    });

    // Then
    const dialog = screen.getByRole("dialog", { name: "Note" });
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText("S3 bucket allows public reads"));
    expect(
      within(dialog).getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
  });

  it("should preserve the current status in the update payload when only the note changes", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({ onTriageUpdateAction });

    // When
    const textarea = screen.getByLabelText("Note text");
    await user.clear(textarea);
    await user.type(textarea, "Documented owner follow-up.");
    await user.click(screen.getByRole("button", { name: "Update note" }));

    // Then
    expect(onTriageUpdateAction).toHaveBeenCalledWith({
      findingId: "finding-1",
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      note: "Documented owner follow-up.",
      origin: "modal",
    });
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
    expect(screen.getByText("3/300")).toBeInTheDocument();
    expect(screen.getByText(FINDING_TRIAGE_NOTE_PRIVACY_COPY)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(
      screen.getByRole("button", { name: "Update note" }),
    ).toBeInTheDocument();
  });

  it("should disable controls and route the primary action to Billing for non-paying users", async () => {
    // Given
    const user = userEvent.setup();
    routerPushMock.mockClear();
    renderNoteModal({
      triage: makeTriageDetail({
        canEdit: false,
        disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
      }),
    });

    // When
    await user.click(screen.getByRole("button", { name: "Only in Cloud" }));

    // Then
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveAttribute("data-disabled", "");
    expect(screen.getByLabelText("Note text")).toBeDisabled();
    expect(routerPushMock).toHaveBeenCalledWith("/billing");
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
    await user.click(screen.getByRole("button", { name: "Update note" }));

    // Then
    await waitFor(() =>
      expect(onTriageUpdateAction).toHaveBeenCalledWith({
        findingId: "finding-1",
        status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        note: "",
        origin: "modal",
      }),
    );
  });
});
