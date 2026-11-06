import { beforeEach, describe, expect, it, vi } from "vitest";

import { UsageLimitError } from "@/lib/action-errors";
import {
  FINDING_TRIAGE_STATUS,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

const { updateFindingTriageMock } = vi.hoisted(() => ({
  updateFindingTriageMock: vi.fn(),
}));

vi.mock("@/actions/findings", () => ({
  updateFindingTriage: updateFindingTriageMock,
}));

import { updateFindingTriageOrThrow } from "./finding-triage-update";

const input: UpdateFindingTriageInput = {
  findingId: "finding-1",
  findingUid: "finding/uid",
  triageId: "triage-1",
  notesCount: 0,
  status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
  previousStatus: FINDING_TRIAGE_STATUS.OPEN,
};

describe("updateFindingTriageOrThrow", () => {
  beforeEach(() => {
    updateFindingTriageMock.mockReset();
  });

  it("throws a usage-limit error when the plan refuses the update", async () => {
    updateFindingTriageMock.mockResolvedValue({ usageLimited: true });

    await expect(updateFindingTriageOrThrow(input)).rejects.toBeInstanceOf(
      UsageLimitError,
    );
  });

  it("returns the update result otherwise", async () => {
    updateFindingTriageMock.mockResolvedValue({ manualPassExpiresAt: null });

    await expect(updateFindingTriageOrThrow(input)).resolves.toEqual({
      manualPassExpiresAt: null,
    });
  });
});
