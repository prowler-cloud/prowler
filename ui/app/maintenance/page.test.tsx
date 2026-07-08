import { render, screen } from "@testing-library/react";
import { headers } from "next/headers";
import { describe, expect, it, vi } from "vitest";

import MaintenancePage from "./page";

vi.mock("next/headers", () => ({
  headers: vi.fn(),
}));

const mockHeaders = (entries: Record<string, string>) => {
  vi.mocked(headers).mockResolvedValue(
    new Headers(entries) as unknown as Awaited<ReturnType<typeof headers>>,
  );
};

describe("MaintenancePage", () => {
  it("renders the message forwarded by the proxy gate via x-maintenance-message", async () => {
    // Given
    mockHeaders({ "x-maintenance-message": "Scheduled DB maintenance." });

    // When
    render(await MaintenancePage());

    // Then
    expect(screen.getByText("Scheduled DB maintenance.")).toBeInTheDocument();
  });

  it("falls back to the default message when the header is missing", async () => {
    // Given
    mockHeaders({});

    // When
    render(await MaintenancePage());

    // Then
    expect(
      screen.getByText(
        "Prowler is currently undergoing scheduled maintenance. We will be back shortly.",
      ),
    ).toBeInTheDocument();
  });

  it("falls back to the default message when the header is empty", async () => {
    // Given
    mockHeaders({ "x-maintenance-message": "" });

    // When
    render(await MaintenancePage());

    // Then
    expect(
      screen.getByText(
        "Prowler is currently undergoing scheduled maintenance. We will be back shortly.",
      ),
    ).toBeInTheDocument();
  });
});
