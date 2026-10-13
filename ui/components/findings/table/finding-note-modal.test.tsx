import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useEffect } from "react";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const { toastMock } = vi.hoisted(() => ({
  toastMock: vi.fn(),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/shadcn")>()),
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIcon: ({ type }: { type: string }) => (
    <span data-testid={`${type}-provider-badge`}>{type} icon</span>
  ),
}));

// CustomLink pulls the "@/lib" barrel (and next-auth with it) into the unit env.
vi.mock("@/components/shadcn/custom/custom-link", () => ({
  CustomLink: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
    onOpenAutoFocus,
  }: {
    children: ReactNode;
    open: boolean;
    title?: string;
    onOpenAutoFocus?: (event: Event) => void;
  }) => {
    useEffect(() => {
      if (open) {
        onOpenAutoFocus?.(new Event("openAutoFocus"));
      }
    }, [onOpenAutoFocus, open]);

    return open ? (
      <div role="dialog" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    ) : null;
  },
}));

const originalTimezone = process.env.TZ;

beforeAll(() => {
  process.env.TZ = "UTC";
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

afterAll(() => {
  if (originalTimezone === undefined) {
    delete process.env.TZ;
  } else {
    process.env.TZ = originalTimezone;
  }
});

import { DOCS_URLS } from "@/lib/external-urls";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_STATUS,
  type FindingTriageDetail,
  type FindingTriageContext,
  type FindingTriageModalStatus,
  type FindingTriageUpdateHandler,
} from "@/types/findings-triage";

import {
  FINDING_NOTE_MODAL_MODE,
  FindingNoteModal,
  type FindingNoteModalMode,
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
    rawFindingStatus: FINDING_STATUS.FAIL,
    manualPassActive: null,
    manualPassEvidence: null,
    manualPassCreatedByName: null,
    manualPassCreatedAt: null,
    manualPassExpiresAt: null,
    manualPassDeactivatedAt: null,
    ...overrides,
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
  useCloudUpgradeStore.getState().closeCloudUpgrade();
});

function renderNoteModal({
  triage = makeTriageDetail(),
  onTriageUpdateAction = vi.fn(),
  onOpenChange = vi.fn(),
  findingContext = {
    title: "S3 bucket allows public reads",
    resource: "production-bucket",
    provider: "production-account",
  },
  mode,
  initialStatus,
}: {
  triage?: FindingTriageDetail;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onOpenChange?: (open: boolean) => void;
  findingContext?: FindingTriageContext;
  mode?: FindingNoteModalMode;
  initialStatus?: FindingTriageModalStatus;
} = {}) {
  render(
    <FindingNoteModal
      open
      onOpenChange={onOpenChange}
      triage={triage}
      findingContext={findingContext}
      mode={mode}
      initialStatus={initialStatus}
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
    expect(
      within(dialog).getByText("S3 bucket allows public reads"),
    ).toBeVisible();
    expect(
      within(dialog).getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
    expect(
      within(dialog).getByText(/automatically changed to Resolved/i),
    ).toBeVisible();
  });

  it("should render a documentation link without requiring Remediating status", () => {
    // Given / When
    renderNoteModal();

    // Then
    const docsLink = screen.getByRole("link", {
      name: /triage documentation/i,
    });
    expect(docsLink).toHaveAttribute("href", DOCS_URLS.FINDINGS_TRIAGE);
    expect(docsLink).toHaveAttribute("target", "_blank");
    expect(
      screen.queryByText(/automatically changed to Resolved/i),
    ).not.toBeInTheDocument();
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
    await user.click(screen.getByRole("button", { name: "Save" }));

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
    await user.click(screen.getByRole("button", { name: "Save" }));

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
    await user.click(screen.getByRole("button", { name: "Save" }));

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
    const onTriageUpdateAction = vi
      .fn()
      .mockRejectedValue(
        new Error("Manual pass evidence must describe the verification."),
      );
    renderNoteModal({ onOpenChange, onTriageUpdateAction });

    // When
    await user.clear(screen.getByLabelText("Note text"));
    await user.type(screen.getByLabelText("Note text"), "Changed note");
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    expect(
      await screen.findByText(
        "Manual pass evidence must describe the verification.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("dialog", { name: "Add Triage Note" }),
    ).toBeInTheDocument();
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    expect(toastMock).not.toHaveBeenCalled();
  });

  it("should expose a pending manual pass submission and keep controls disabled", async () => {
    // Given
    const user = userEvent.setup();
    let resolveUpdate: () => void = () => {};
    const onTriageUpdateAction = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveUpdate = resolve;
        }),
    );
    renderNoteModal({
      triage: makeTriageDetail({
        rawFindingStatus: FINDING_STATUS.MANUAL,
      }),
      onTriageUpdateAction,
    });
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));
    await user.type(
      screen.getByLabelText("Manual pass evidence"),
      "Verified by the control owner.",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    expect(screen.getByRole("button", { name: "Saving..." })).toBeDisabled();
    expect(screen.getByLabelText("Manual pass evidence")).toBeDisabled();
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toBeDisabled();

    resolveUpdate();
    await waitFor(() =>
      expect(screen.queryByText("Saving...")).not.toBeInTheDocument(),
    );
  });

  it("should lock the status picker for resolved findings while keeping the note editable", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.RESOLVED,
        label: "Resolved",
      }),
      onTriageUpdateAction,
    });

    // Then — automation owns the transition out of Resolved.
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toBeDisabled();
    expect(
      screen.getByText(
        "Triage status is managed automatically once the finding is resolved.",
      ),
    ).toBeVisible();
    expect(screen.getByLabelText("Note text")).toBeEnabled();

    // When — the note itself can still be updated.
    const textarea = screen.getByLabelText("Note text");
    await user.clear(textarea);
    await user.type(textarea, "Documenting the resolution.");
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    expect(onTriageUpdateAction).toHaveBeenCalledWith(
      expect.objectContaining({ note: "Documenting the resolution." }),
    );
    expect(onTriageUpdateAction).toHaveBeenCalledWith(
      expect.not.objectContaining({ status: expect.anything() }),
    );
  });

  it("should render counter and cancel/update actions without privacy copy", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    renderNoteModal({ onOpenChange });

    // When
    await user.clear(screen.getByLabelText("Note text"));
    await user.type(screen.getByLabelText("Note text"), "abc");

    // Then
    expect(screen.getByText("3/500")).toBeInTheDocument();
    expect(
      screen.queryByText("This note is only visible to your team."),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });

  it("should keep controls read-only and open the finding triage upgrade", async () => {
    // Given
    const user = userEvent.setup();
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
    const saveUpgrade = screen.getByRole("button", {
      name: "Save - available in Prowler Cloud",
    });
    expect(saveUpgrade).not.toBeDisabled();

    await user.click(saveUpgrade);

    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE,
    );
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
    expect(
      screen.getByText(
        "Changing triage to Risk Accepted will mute the finding",
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(screen.queryByRole("listbox")).not.toBeInTheDocument(),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Save" }));

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

  it("should offer Resolved only for an authoritative MANUAL finding without duration controls", async () => {
    // Given
    const user = userEvent.setup();
    renderNoteModal({
      triage: makeTriageDetail({
        rawFindingStatus: FINDING_STATUS.MANUAL,
      }),
    });

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));

    // Then
    expect(screen.getByRole("option", { name: "Resolved" })).toBeVisible();

    // When
    await user.click(screen.getByRole("option", { name: "Resolved" }));

    // Then
    expect(screen.getByLabelText("Manual pass evidence")).toHaveValue("");
    expect(screen.getByLabelText("Manual pass evidence")).toBeRequired();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("should label, explain, and focus required manual pass evidence", () => {
    // Given / When
    renderNoteModal({
      triage: makeTriageDetail({
        rawFindingStatus: FINDING_STATUS.MANUAL,
      }),
      initialStatus: FINDING_TRIAGE_STATUS.RESOLVED,
    });

    // Then
    const evidence = screen.getByRole("textbox", {
      name: "Manual pass evidence",
    });
    expect(evidence).toHaveFocus();
    expect(evidence).toHaveAccessibleDescription(
      "Add a Triage Note explaining why this finding passes.",
    );
  });

  it("should not offer Resolved when the authoritative raw finding status is not MANUAL", async () => {
    // Given
    const user = userEvent.setup();
    renderNoteModal({
      triage: makeTriageDetail({
        rawFindingStatus: FINDING_STATUS.FAIL,
      }),
    });

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));

    // Then
    expect(screen.queryByRole("option", { name: "Resolved" })).toBeNull();
  });

  it("should submit Resolved with fresh evidence instead of the editable note", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn();
    renderNoteModal({
      triage: makeTriageDetail({
        rawFindingStatus: FINDING_STATUS.MANUAL,
      }),
      onTriageUpdateAction,
    });
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));

    // When
    await user.type(
      screen.getByLabelText("Manual pass evidence"),
      "The control owner verified this requirement.",
    );
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    expect(onTriageUpdateAction).toHaveBeenCalledWith({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      isMuted: false,
      status: FINDING_TRIAGE_STATUS.RESOLVED,
      previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      manualPassEvidence: "The control owner verified this requirement.",
    });
  });

  it("should clear manual pass evidence when the modal closes before reopening", async () => {
    // Given
    const user = userEvent.setup();
    const triage = makeTriageDetail({
      rawFindingStatus: FINDING_STATUS.MANUAL,
    });
    const onOpenChange = vi.fn();
    const { rerender } = render(
      <FindingNoteModal
        open
        onOpenChange={onOpenChange}
        triage={triage}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));
    await user.type(
      screen.getByLabelText("Manual pass evidence"),
      "Evidence that must not leak.",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    rerender(
      <FindingNoteModal
        open
        onOpenChange={onOpenChange}
        triage={triage}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByLabelText("Note text")).toHaveValue(
      "Existing investigation note",
    );
    expect(screen.queryByLabelText("Manual pass evidence")).toBeNull();
  });

  it("should reset manual pass evidence when an unchanged update closes", async () => {
    // Given
    const user = userEvent.setup();
    const triage = makeTriageDetail({
      rawFindingStatus: FINDING_STATUS.MANUAL,
    });
    const onOpenChange = vi.fn();
    const { rerender } = render(
      <FindingNoteModal
        open
        onOpenChange={onOpenChange}
        triage={triage}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));
    await user.type(
      screen.getByRole("textbox", { name: "Manual pass evidence" }),
      "Evidence that must not leak.",
    );
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Under Review" }));

    // When
    await user.click(screen.getByRole("button", { name: "Save" }));
    rerender(
      <FindingNoteModal
        open
        onOpenChange={onOpenChange}
        triage={triage}
        findingContext={{ title: "S3 bucket allows public reads" }}
        onTriageUpdateAction={vi.fn()}
      />,
    );
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));

    // Then
    expect(
      screen.getByRole("textbox", { name: "Manual pass evidence" }),
    ).toHaveValue("");
  });

  it("should show one manual pass success toast with the authoritative mutation expiry", async () => {
    // Given
    const user = userEvent.setup();
    const triage = makeTriageDetail({
      rawFindingStatus: FINDING_STATUS.MANUAL,
    });
    const onTriageUpdateAction = vi.fn().mockResolvedValue({
      manualPassExpiresAt: "2026-10-28T12:00:00Z",
    });
    renderNoteModal({ triage, onTriageUpdateAction });
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));
    await user.type(
      screen.getByLabelText("Manual pass evidence"),
      "The control owner verified this requirement.",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    await waitFor(() => expect(toastMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith({
      title: "Finding manually verified as Pass",
      description: "Triage: Resolved · Valid until Oct 28, 2026",
    });
  });

  it("should omit an invalid manual pass expiry from the success toast", async () => {
    // Given
    const user = userEvent.setup();
    const onTriageUpdateAction = vi.fn().mockResolvedValue({
      manualPassExpiresAt: "invalid-expiry",
    });
    renderNoteModal({
      triage: makeTriageDetail({
        rawFindingStatus: FINDING_STATUS.MANUAL,
      }),
      onTriageUpdateAction,
    });
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));
    await user.type(
      screen.getByRole("textbox", { name: "Manual pass evidence" }),
      "The control owner verified this requirement.",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    await waitFor(() => expect(toastMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith({
      title: "Finding manually verified as Pass",
      description: "Triage: Resolved",
    });
  });

  it("should not show the manual pass toast for an ordinary update", async () => {
    // Given
    const user = userEvent.setup();
    renderNoteModal({ onTriageUpdateAction: vi.fn() });
    const textarea = screen.getByLabelText("Note text");
    await user.clear(textarea);
    await user.type(textarea, "Documented owner follow-up.");

    // When
    await user.click(screen.getByRole("button", { name: "Save" }));

    // Then
    await waitFor(() =>
      expect(screen.queryByText("Saving...")).not.toBeInTheDocument(),
    );
    expect(toastMock).not.toHaveBeenCalled();
  });

  it("should show existing manual pass provenance and preserve note editing", () => {
    // Given / When
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.RESOLVED,
        label: "Resolved",
        rawFindingStatus: FINDING_STATUS.MANUAL,
        manualPassActive: true,
        manualPassEvidence: "The active control evidence was reviewed.",
        manualPassCreatedByName: "Alex Security",
        manualPassCreatedAt: "2026-06-03T10:00:00Z",
        manualPassExpiresAt: "2026-06-17T10:00:00Z",
      }),
    });

    // Then
    expect(
      screen.getByText(/Manually verified by Alex Security/i),
    ).toBeVisible();
    expect(screen.getByText("Jun 03, 2026")).toBeVisible();
    expect(screen.getByText("Jun 17, 2026")).toBeVisible();
    expect(
      screen.getByText("The active control evidence was reviewed."),
    ).toBeVisible();
    expect(screen.queryByText("Expired")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Note text")).toHaveValue(
      "Existing investigation note",
    );
    expect(screen.queryByLabelText("Manual pass evidence")).toBeNull();
  });

  it("should show expired Manual Pass provenance separately from required renewal evidence", async () => {
    // Given
    const user = userEvent.setup();
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.OPEN,
        label: "Open",
        rawFindingStatus: FINDING_STATUS.MANUAL,
        manualPassActive: false,
        manualPassEvidence: "The control owner verified the requirement.",
        manualPassCreatedByName: "Alex Security",
        manualPassCreatedAt: "2026-06-03T10:00:00Z",
        manualPassExpiresAt: "2026-06-17T10:00:00Z",
        manualPassDeactivatedAt: null,
      }),
    });

    // Then
    expect(
      screen.getByText(/Previous Manual Pass by Alex Security/i),
    ).toBeVisible();
    expect(screen.getByText("Expired")).toBeVisible();
    expect(
      screen.getByText("The control owner verified the requirement."),
    ).toBeVisible();
    expect(
      screen.queryByDisplayValue("The control owner verified the requirement."),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Jun 03, 2026")).toBeVisible();
    expect(screen.getByText("Jun 17, 2026")).toBeVisible();

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Resolved" }));

    // Then
    expect(screen.getByLabelText("Manual pass evidence")).toHaveValue("");
    expect(screen.getByLabelText("Manual pass evidence")).toBeRequired();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(
      screen.getByText("The control owner verified the requirement."),
    ).toBeVisible();
  });

  it("should show expired provenance safely when prior evidence is missing", () => {
    // Given / When
    renderNoteModal({
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.OPEN,
        label: "Open",
        rawFindingStatus: FINDING_STATUS.MANUAL,
        manualPassActive: false,
        manualPassEvidence: null,
        manualPassCreatedAt: "2026-06-03T10:00:00Z",
        manualPassExpiresAt: "2026-06-17T10:00:00Z",
      }),
    });

    // Then
    expect(screen.getByText(/Previous Manual Pass/i)).toBeVisible();
    expect(screen.getByText("Expired")).toBeVisible();
    expect(screen.queryByText("Evidence")).not.toBeInTheDocument();
  });

  it("should show inactive Manual Pass details without edit or submit controls", () => {
    // Given / When
    renderNoteModal({
      mode: FINDING_NOTE_MODAL_MODE.MANUAL_PASS_DETAILS,
      triage: makeTriageDetail({
        status: FINDING_TRIAGE_STATUS.RESOLVED,
        label: "Resolved",
        rawFindingStatus: FINDING_STATUS.MANUAL,
        manualPassActive: false,
        manualPassEvidence: null,
        manualPassCreatedByName: "Alex Security",
        manualPassCreatedAt: "2026-06-03T10:00:00Z",
        manualPassExpiresAt: "2026-06-17T10:00:00Z",
        manualPassDeactivatedAt: "2026-06-10T10:00:00Z",
      }),
    });

    // Then
    const dialog = screen.getByRole("dialog", { name: "Manual Pass Details" });
    expect(within(dialog).getByText("Inactive")).toBeVisible();
    expect(within(dialog).getByText("Inactive on")).toBeVisible();
    expect(within(dialog).getByText("Jun 10, 2026")).toBeVisible();
    expect(within(dialog).queryByText("Evidence")).not.toBeInTheDocument();
    expect(
      within(dialog).getByRole("combobox", { name: "Triage status" }),
    ).toBeDisabled();
    expect(
      within(dialog).queryByLabelText("Note text"),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).queryByLabelText("Manual pass evidence"),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).queryByRole("button", { name: "Save" }),
    ).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Close" })).toBeVisible();
  });
});
