import { render, screen } from "@testing-library/react";
import { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getIssue, notFound } = vi.hoisted(() => ({
  getIssue: vi.fn(),
  notFound: vi.fn(() => {
    throw new Error("NOT_FOUND");
  }),
}));
vi.mock("next/navigation", () => ({ notFound }));
vi.mock("@/actions/issues", () => ({ getIssue }));
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/shared/feature-flag-route", () => ({
  FeatureFlagRoute: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/issues/issue-detail", () => ({
  IssueDetail: ({ scanId }: { scanId?: string }) => (
    <div data-testid="issue-detail">{scanId}</div>
  ),
}));

import IssuePage from "./page";

const params = Promise.resolve({ id: "issue-1" });

describe("IssuePage", () => {
  beforeEach(() => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    getIssue.mockReset();
  });

  it("returns not found in Local Server without asking the API", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    await expect(IssuePage({ params })).rejects.toThrow("NOT_FOUND");
    expect(getIssue).not.toHaveBeenCalled();
  });

  it("returns not found when the API has no such issue", async () => {
    getIssue.mockResolvedValue({ error: "Not found", status: 404 });
    await expect(IssuePage({ params })).rejects.toThrow("NOT_FOUND");
  });

  it("shows the issue with the detail the list opens in place", async () => {
    getIssue.mockResolvedValue({
      data: {
        type: "issues",
        id: "issue-1",
        attributes: {
          pattern: "aws_public_bucket",
          cloud: "aws",
          account: "prod",
          title: "Public bucket",
          verdict: "likely",
        },
        relationships: { scan: { data: { type: "scans", id: "scan-1" } } },
      },
    });

    render(await IssuePage({ params }));

    expect(getIssue).toHaveBeenCalledWith("issue-1");
    expect(
      screen.getByRole("heading", { name: "Public bucket" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Likely")).toBeInTheDocument();
    expect(screen.getByTestId("issue-detail")).toHaveTextContent("scan-1");
    expect(screen.getByRole("link", { name: "← All issues" })).toHaveAttribute(
      "href",
      "/issues",
    );
  });
});
