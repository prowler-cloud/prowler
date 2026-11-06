import { describe, expect, it } from "vitest";

import {
  appendAttributionToCallbackPath,
  appendCallbackState,
  getAttributionParamsFromCallbackPath,
  getInvitationTokenFromCallbackPath,
  getSafeCallbackPath,
  isSelfRegistrationDisabledResponse,
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

  describe("when carrying campaign attribution", () => {
    it("should append attribution params to the callback path", () => {
      const result = appendAttributionToCallbackPath("/", {
        promo_code: "black-hat-2026",
        utm_source: "blackhat",
      });

      expect(result).toBe("/?promo_code=black-hat-2026&utm_source=blackhat");
    });

    it("should not override params already present in the path", () => {
      const result = appendAttributionToCallbackPath("/?promo_code=original", {
        promo_code: "other",
      });

      expect(result).toBe("/?promo_code=original");
    });

    it("should return the path untouched without attribution", () => {
      expect(appendAttributionToCallbackPath("/scans", {})).toBe("/scans");
    });

    it("should read attribution params back from a callback path", () => {
      const result = getAttributionParamsFromCallbackPath(
        "/?promo_code=black-hat-2026&utm_source=blackhat&foo=bar",
      );

      expect(result).toEqual({
        promo_code: "black-hat-2026",
        utm_source: "blackhat",
      });
    });

    it("should return no attribution for unsafe callback paths", () => {
      expect(
        getAttributionParamsFromCallbackPath(
          "https://attacker.example/?promo_code=x",
        ),
      ).toEqual({});
    });
  });
});

describe("isSelfRegistrationDisabledResponse", () => {
  it("is true for a 403 carrying the self_registration_disabled code", async () => {
    const response = Response.json(
      { errors: [{ code: "self_registration_disabled", status: "403" }] },
      { status: 403 },
    );

    await expect(isSelfRegistrationDisabledResponse(response)).resolves.toBe(
      true,
    );
  });

  it("is false for a 403 with another code", async () => {
    const response = Response.json(
      { errors: [{ code: "partner_provisioned", status: "403" }] },
      { status: 403 },
    );

    await expect(isSelfRegistrationDisabledResponse(response)).resolves.toBe(
      false,
    );
  });

  it("is false for non-403 responses and unparsable bodies", async () => {
    await expect(
      isSelfRegistrationDisabledResponse(
        new Response("self_registration_disabled", { status: 400 }),
      ),
    ).resolves.toBe(false);
    await expect(
      isSelfRegistrationDisabledResponse(
        new Response("not json", { status: 403 }),
      ),
    ).resolves.toBe(false);
  });
});
