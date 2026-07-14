import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PublicAuthShell } from "./public-auth-shell";

describe("PublicAuthShell", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("should brand every Local Server public page", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(
      <PublicAuthShell>
        <main>Public page</main>
      </PublicAuthShell>,
    );

    // Then
    expect(
      screen.getByRole("img", { name: "Prowler Local Server" }),
    ).toBeVisible();
    expect(screen.getByRole("main")).toHaveTextContent("Public page");
  });

  it("should brand every Prowler Cloud public page", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(
      <PublicAuthShell>
        <main>Public page</main>
      </PublicAuthShell>,
    );

    // Then
    expect(screen.getByRole("img", { name: "Prowler Cloud" })).toBeVisible();
  });
});
