import { afterEach, describe, expect, it, vi } from "vitest";

import {
  isCloud,
  isLocalDevelopment,
  shouldRequireEmailVerification,
} from "./env";

describe("shared environment helpers", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("detects cloud mode from the public environment flag", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    expect(isCloud()).toBe(true);
  });

  it("detects local development from NODE_ENV", () => {
    vi.stubEnv("NODE_ENV", "development");

    expect(isLocalDevelopment()).toBe(true);
  });

  it("does not require email verification in local cloud-mode development", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    vi.stubEnv("NODE_ENV", "development");

    expect(shouldRequireEmailVerification()).toBe(false);
  });

  it("requires email verification for hosted cloud mode", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    vi.stubEnv("NODE_ENV", "production");

    expect(shouldRequireEmailVerification()).toBe(true);
  });

  it("does not require email verification outside cloud mode", () => {
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    vi.stubEnv("NODE_ENV", "production");

    expect(shouldRequireEmailVerification()).toBe(false);
  });
});
