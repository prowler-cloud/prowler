import { describe, expect, it } from "vitest";

import {
  appendCallbackState,
  getInvitationTokenFromCallbackPath,
  getSafeCallbackPath,
} from "@/lib/auth-callback-url";

describe("auth callback URL helpers", () => {
  describe("when appending OAuth state", () => {
    it("should add a relative callback path as provider state", () => {
      const authUrl = "https://accounts.example.com/oauth?client_id=client";
      const callbackPath = "/invitation/accept?invitation_token=test-token";

      const result = appendCallbackState(authUrl, callbackPath);

      expect(new URL(result).searchParams.get("state")).toBe(callbackPath);
    });

    it("should not add state for the default callback path", () => {
      const authUrl = "https://accounts.example.com/oauth?client_id=client";

      const result = appendCallbackState(authUrl, "/");

      expect(new URL(result).searchParams.has("state")).toBe(false);
    });
  });

  describe("when reading callback paths", () => {
    it("should return relative callback paths", () => {
      const params = new URLSearchParams({
        state: "/invitation/accept?invitation_token=test-token",
      });

      const result = getSafeCallbackPath(params);

      expect(result).toBe("/invitation/accept?invitation_token=test-token");
    });

    it("should reject external callback URLs", () => {
      const params = new URLSearchParams({
        state: "https://attacker.example/phishing",
      });

      const result = getSafeCallbackPath(params);

      expect(result).toBe("/");
    });
  });

  describe("when reading invitation tokens", () => {
    it("should return invitation tokens from safe callback paths", () => {
      const callbackPath = "/invitation/accept?invitation_token=test-token";

      const result = getInvitationTokenFromCallbackPath(callbackPath);

      expect(result).toBe("test-token");
    });
  });
});
