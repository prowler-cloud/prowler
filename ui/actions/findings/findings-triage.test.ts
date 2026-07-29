import { beforeEach, describe, expect, it, vi } from "vitest";

import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

const {
  createMuteRuleMock,
  fetchMock,
  getAuthHeadersMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  createMuteRuleMock: vi.fn(),
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
}));

vi.mock("@/actions/mute-rules", () => ({
  createMuteRule: createMuteRuleMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

const importActions = async () => import("./findings-triage");

describe("findings triage actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    createMuteRuleMock.mockResolvedValue({ success: "muted" });
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
  });

  it("should load notes through the persisted triage route when triageId exists", async () => {
    // Given
    const { loadLatestFindingTriageNote } = await importActions();
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "note-1",
          type: "finding-triage-notes",
          attributes: { body: "Existing note" },
        },
      ],
    });

    // When
    const result = await loadLatestFindingTriageNote({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 1,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      label: "Under Review",
      hasVisibleNote: true,
      isMuted: false,
      canEdit: true,
      billingHref: "https://prowler.com/pricing",
    });

    // Then
    expect(result).toEqual({ noteId: "note-1", noteBody: "Existing note" });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/finding-triages/triage-1/notes",
      expect.objectContaining({
        headers: { Authorization: "Bearer token" },
      }),
    );
  });

  it("should load notes through the finding UID route when triageId is virtual", async () => {
    // Given
    const { loadLatestFindingTriageNote } = await importActions();
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "note-1",
          type: "finding-triage-notes",
          attributes: { body: "Existing note" },
        },
      ],
    });

    // When
    await loadLatestFindingTriageNote({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: null,
      notesCount: 1,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      label: "Under Review",
      hasVisibleNote: true,
      isMuted: false,
      canEdit: true,
      billingHref: "https://prowler.com/pricing",
    });

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage/notes",
      expect.any(Object),
    );
  });

  it("should resolve findingUid from findingId before loading virtual triage notes", async () => {
    // Given
    const { loadLatestFindingTriageNote } = await importActions();
    handleApiResponseMock
      .mockResolvedValueOnce({
        data: { attributes: { uid: "finding/stable/uid" } },
      })
      .mockResolvedValueOnce({
        data: [
          {
            id: "note-1",
            type: "finding-triage-notes",
            attributes: { body: "Existing note" },
          },
        ],
      });

    // When
    await loadLatestFindingTriageNote({
      findingId: "finding-snapshot-id",
      findingUid: "",
      triageId: null,
      notesCount: 1,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      label: "Under Review",
      hasVisibleNote: true,
      isMuted: false,
      canEdit: true,
      billingHref: "https://prowler.com/pricing",
    });

    // Then
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/findings/finding-snapshot-id",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage/notes",
      expect.any(Object),
    );
  });

  it("should send the first note with the status update through the triage route", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "note-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      note: "First note",
    });

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/finding-triages/triage-1",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triages",
            attributes: {
              status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
              note: "First note",
            },
          },
        }),
      }),
    );
  });

  it("should update an existing note through its note id", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "note-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      note: "Updated note",
    });

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/finding-triages/triage-1/notes/note-1",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triage-notes",
            attributes: {
              body: "Updated note",
            },
          },
        }),
      }),
    );
  });

  it("should delete an existing persisted note when it is cleared", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "note-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      note: "",
    });

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/finding-triages/triage-1/notes/note-1",
      {
        method: "DELETE",
        headers: { Authorization: "Bearer token" },
      },
    );
    expect(fetchMock).not.toHaveBeenCalledWith(
      "https://api.test/api/v1/finding-triages/triage-1/notes/note-1",
      expect.objectContaining({ method: "PATCH" }),
    );
  });

  it("should update an existing note and send status-only triage patch", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      status: FINDING_TRIAGE_STATUS.REMEDIATING,
      note: "Updated note",
    });

    // Then
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/finding-triages/triage-1/notes/note-1",
      expect.objectContaining({ method: "PATCH" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/finding-triages/triage-1",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triages",
            attributes: {
              status: FINDING_TRIAGE_STATUS.REMEDIATING,
            },
          },
        }),
      }),
    );
  });

  it("should update a virtual existing note through the finding UID note route", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: null,
      notesCount: 1,
      noteId: "note-1",
      status: FINDING_TRIAGE_STATUS.REMEDIATING,
      previousStatus: FINDING_TRIAGE_STATUS.OPEN,
      note: "Updated note",
    });

    // Then
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage/notes/note-1",
      expect.objectContaining({ method: "PATCH" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triages",
            attributes: {
              status: FINDING_TRIAGE_STATUS.REMEDIATING,
            },
          },
        }),
      }),
    );
  });

  it("should not patch virtual triage route for virtual existing-note-only updates", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "note-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: null,
      notesCount: 1,
      noteId: "note-1",
      note: "Updated note",
    });

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage/notes/note-1",
      expect.objectContaining({ method: "PATCH" }),
    );
  });

  it("should delete a virtual existing note when it is cleared", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "note-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: null,
      notesCount: 1,
      noteId: "note-1",
      note: "",
    });

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage/notes/note-1",
      expect.objectContaining({
        method: "DELETE",
        headers: { Authorization: "Bearer token" },
      }),
    );
  });

  it("should create a mute rule when status is Risk Accepted", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      previousStatus: FINDING_TRIAGE_STATUS.OPEN,
    });

    // Then
    expect(createMuteRuleMock).toHaveBeenCalledOnce();
    const formData = createMuteRuleMock.mock.calls[0][1] as FormData;
    expect(formData.get("finding_ids")).toBe(
      JSON.stringify(["finding-snapshot-id"]),
    );
    expect(formData.get("name")).toBe(
      "Finding triage: Risk Accepted - finding-snapshot-id",
    );
    expect(formData.get("reason")).toBe(
      "Finding triage status changed to Risk Accepted.",
    );
  });

  it("should reject and skip muting when triage patch returns an action error", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({
      error: "Triage failed",
      status: 400,
    });

    // When / Then
    await expect(
      updateFindingTriage({
        findingId: "finding-snapshot-id",
        findingUid: "finding/stable/uid",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        previousStatus: FINDING_TRIAGE_STATUS.OPEN,
      }),
    ).rejects.toThrow("Triage failed");
    expect(createMuteRuleMock).not.toHaveBeenCalled();
  });

  it("should rollback triage status when automatic muting fails", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });
    createMuteRuleMock.mockResolvedValue({
      errors: { general: "Mute failed" },
    });

    // When / Then
    await expect(
      updateFindingTriage({
        findingId: "finding-snapshot-id",
        findingUid: "finding/stable/uid",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        previousStatus: FINDING_TRIAGE_STATUS.OPEN,
      }),
    ).rejects.toThrow("Mute failed");

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/finding-triages/triage-1",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triages",
            attributes: {
              status: FINDING_TRIAGE_STATUS.OPEN,
            },
          },
        }),
      }),
    );
  });

  it("should rollback virtual triage status through encoded finding UID when automatic muting fails", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });
    createMuteRuleMock.mockResolvedValue({
      errors: { general: "Mute failed" },
    });

    // When / Then
    await expect(
      updateFindingTriage({
        findingId: "finding-snapshot-id",
        findingUid: "finding/stable/uid",
        triageId: null,
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
        previousStatus: FINDING_TRIAGE_STATUS.OPEN,
      }),
    ).rejects.toThrow("Mute failed");

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triages",
            attributes: {
              status: FINDING_TRIAGE_STATUS.OPEN,
            },
          },
        }),
      }),
    );
  });

  it("should not create a mute rule when the finding is already muted", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      previousStatus: FINDING_TRIAGE_STATUS.OPEN,
      isMuted: true,
    });

    // Then
    expect(createMuteRuleMock).not.toHaveBeenCalled();
  });

  it("should not create a mute rule when moving between shortcut statuses", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
      previousStatus: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
    });

    // Then
    expect(createMuteRuleMock).not.toHaveBeenCalled();
  });

  it("should not create a mute rule when shortcut status did not change", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      previousStatus: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      note: "First note",
    });

    // Then
    expect(createMuteRuleMock).not.toHaveBeenCalled();
  });

  it("should not create a mute rule for regular triage statuses", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    });

    // Then
    expect(createMuteRuleMock).not.toHaveBeenCalled();
  });

  it("should update virtual triage through the finding UID route, not the snapshot id", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock.mockResolvedValue({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "finding/stable/uid",
      triageId: null,
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    });

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage",
      expect.objectContaining({ method: "PATCH" }),
    );
  });

  it("should resolve findingUid from findingId before creating virtual triage", async () => {
    // Given
    const { updateFindingTriage } = await importActions();
    handleApiResponseMock
      .mockResolvedValueOnce({
        data: { attributes: { uid: "finding/stable/uid" } },
      })
      .mockResolvedValueOnce({ data: { id: "triage-1" } });

    // When
    await updateFindingTriage({
      findingId: "finding-snapshot-id",
      findingUid: "",
      triageId: null,
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      note: "First note",
    });

    // Then
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.test/api/v1/findings/finding-snapshot-id",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.test/api/v1/findings/finding%2Fstable%2Fuid/triage",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "finding-triages",
            attributes: {
              status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
              note: "First note",
            },
          },
        }),
      }),
    );
  });
});
