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

    it("should reject protocol-relative callback URLs", () => {
      const params = new URLSearchParams({
        state: "//attacker.example/phishing",
      });

      const result = getSafeCallbackPath(params);

      expect(result).toBe("/");
    });

    it("should reject backslash-normalized callback URLs", () => {
      const params = new URLSearchParams({ state: "/\\attacker.example" });

      const result = getSafeCallbackPath(params);

      expect(result).toBe("/");
    });

    it("should reject callback URLs with control characters before the host", () => {
      const params = new URLSearchParams({ state: "/\t/attacker.example" });

      const result = getSafeCallbackPath(params);

      expect(result).toBe("/");
    });

    it("should preserve the query string of relative callback paths", () => {
      const params = new URLSearchParams({
        state: "/invitation/accept?invitation_token=test-token&foo=bar",
      });

      const result = getSafeCallbackPath(params);

      expect(result).toBe(
        "/invitation/accept?invitation_token=test-token&foo=bar",
      );
    });
  });

  describe("when appending OAuth state for unsafe paths", () => {
    it("should not add a backslash-normalized path as provider state", () => {
      const authUrl = "https://accounts.example.com/oauth?client_id=client";

      const result = appendCallbackState(authUrl, "/\\attacker.example");

      expect(new URL(result).searchParams.has("state")).toBe(false);
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
