import { describe, expect, it } from "vitest";

import { adaptLatestFindingTriageNote } from "./findings-triage-notes.adapter";

describe("adaptLatestFindingTriageNote", () => {
  it("should adapt the newest note from a JSON:API collection", () => {
    // Given
    const response = {
      data: [
        {
          id: "note-latest",
          type: "finding-triage-notes",
          attributes: {
            body: "Latest investigation note",
          },
        },
      ],
    };

    // When
    const result = adaptLatestFindingTriageNote(response);

    // Then
    expect(result).toEqual({
      noteId: "note-latest",
      noteBody: "Latest investigation note",
    });
  });

  it("should return null when the response has no usable note", () => {
    expect(adaptLatestFindingTriageNote({ data: [] })).toBeNull();
    expect(
      adaptLatestFindingTriageNote({ data: [{ id: "note-1" }] }),
    ).toBeNull();
  });
});
