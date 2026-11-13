import { describe, expect, it } from "vitest";

import { toSentInvitation } from "./invitation.adapter";

const created = {
  data: {
    id: "inv-1",
    type: "invitations",
    attributes: {
      email: "teammate@company.com",
      token: "abc123DEF45678",
      state: "pending",
      expires_at: "2026-10-07T10:00:00Z",
    },
  },
};

describe("toSentInvitation", () => {
  it("reads the id, email and token of a created invitation", () => {
    expect(toSentInvitation(created)).toEqual({
      id: "inv-1",
      email: "teammate@company.com",
      token: "abc123DEF45678",
    });
  });

  it("returns null when the action resolved without a value", () => {
    // A 5xx makes `sendInvite` resolve undefined.
    expect(toSentInvitation(undefined)).toBeNull();
  });

  it("returns null on a rejection, with or without an errors array", () => {
    expect(
      toSentInvitation({ errors: [{ detail: "Invalid email" }] }),
    ).toBeNull();
    expect(toSentInvitation({ error: "Something went wrong" })).toBeNull();
  });

  it("returns null when the record is missing any of the fields the link needs", () => {
    expect(
      toSentInvitation({
        data: { id: "inv-1", attributes: { email: "a@b.com" } },
      }),
    ).toBeNull();
    expect(
      toSentInvitation({
        data: { id: "inv-1", attributes: { token: "abc123DEF45678" } },
      }),
    ).toBeNull();
  });
});
