import { beforeEach, describe, expect, it, vi } from "vitest";

const { headersMock, redirectMock } = vi.hoisted(() => ({
  headersMock: vi.fn(),
  redirectMock: vi.fn((url: string) => {
    throw new Error(`NEXT_REDIRECT:${url}`);
  }),
}));

vi.mock("server-only", () => ({}));

vi.mock("next/headers", () => ({
  headers: headersMock,
}));

vi.mock("next/navigation", () => ({
  redirect: redirectMock,
}));

import {
  getAuthHeadersIfAvailable,
  getRequiredAuthHeaders,
  redirectToSignIn,
} from "./server-auth";

describe("server authentication", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    headersMock.mockResolvedValue(
      new Headers({ "x-prowler-current-path": "/providers?page=2" }),
    );
  });

  it("redirects a missing access token without creating an undefined bearer token", async () => {
    // Given
    const accessToken = undefined;

    // When / Then
    await expect(getRequiredAuthHeaders(accessToken)).rejects.toThrow(
      "NEXT_REDIRECT:/sign-in?callbackUrl=%2Fproviders%3Fpage%3D2",
    );
    expect(redirectMock).toHaveBeenCalledOnce();
  });

  it("redirects a failed refresh session even when it still contains an access token", async () => {
    // Given
    const accessToken = "stale-access-token";

    // When / Then
    await expect(
      getRequiredAuthHeaders(accessToken, undefined, "RefreshAccessTokenError"),
    ).rejects.toThrow(
      "NEXT_REDIRECT:/sign-in?callbackUrl=%2Fproviders%3Fpage%3D2",
    );
    expect(redirectMock).toHaveBeenCalledOnce();
  });

  it("returns no headers for a terminal session without redirecting", () => {
    // Given
    const accessToken = "stale-access-token";

    // When
    const result = getAuthHeadersIfAvailable(
      accessToken,
      undefined,
      "RefreshAccessTokenError",
    );

    // Then
    expect(result).toBeNull();
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it("returns no headers for a missing session without redirecting", () => {
    // When
    const result = getAuthHeadersIfAvailable(undefined);

    // Then
    expect(result).toBeNull();
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it("creates bearer headers only when an access token is present", async () => {
    // Given
    const accessToken = "access-token";

    // When
    const result = await getRequiredAuthHeaders(accessToken, {
      contentType: true,
    });

    // Then
    expect(result).toEqual({
      Accept: "application/vnd.api+json",
      Authorization: "Bearer access-token",
      "Content-Type": "application/vnd.api+json",
    });
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it("preserves the protected path when redirecting an authentication failure", async () => {
    // When / Then
    await expect(redirectToSignIn()).rejects.toThrow(
      "NEXT_REDIRECT:/sign-in?callbackUrl=%2Fproviders%3Fpage%3D2",
    );
  });

  it("falls back to the root callback when the current path is unavailable", async () => {
    // Given
    headersMock.mockResolvedValue(new Headers());

    // When / Then
    await expect(redirectToSignIn()).rejects.toThrow(
      "NEXT_REDIRECT:/sign-in?callbackUrl=%2F",
    );
  });
});
