import { describe, expect, it } from "vitest";

import { buildInvitationAcceptLink } from "./accept-link";

describe("buildInvitationAcceptLink", () => {
  it("points the invitee at the accept page of the given origin", () => {
    expect(
      buildInvitationAcceptLink("abc123DEF45678", "https://app.example.com"),
    ).toBe(
      "https://app.example.com/invitation/accept?invitation_token=abc123DEF45678",
    );
  });

  it("keeps the token safe inside the query string", () => {
    expect(buildInvitationAcceptLink("a b&c", "https://app.example.com")).toBe(
      "https://app.example.com/invitation/accept?invitation_token=a%20b%26c",
    );
  });
});
