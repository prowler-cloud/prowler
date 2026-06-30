import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
  default: ({
    children,
    href,
    ...rest
  }: {
    children: ReactNode;
    href: string;
    "aria-label"?: string;
    className?: string;
  }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

import { LinkToFindings } from "./link-to-findings";

describe("LinkToFindings", () => {
  it("should link to findings sorted by severity (desc) then last_seen_at (desc), filtered to FAIL + new delta", () => {
    render(<LinkToFindings />);

    const link = screen.getByRole("link", { name: "Go to Findings page" });
    const href = link.getAttribute("href") ?? "";
    const [, query = ""] = href.split("?");
    const params = new URLSearchParams(query);

    expect(params.get("sort")).toBe("-severity,-last_seen_at");
    expect(params.get("filter[status__in]")).toBe("FAIL");
    // filter[delta] must be singular — the finding-groups filter does not
    // register `delta__in`, so the plural form is silently dropped by the API.
    expect(params.get("filter[delta]")).toBe("new");
    expect(params.has("filter[delta__in]")).toBe(false);
  });

  it("should render as a tertiary text link (not a solid button) to match the overview Card pattern", () => {
    render(<LinkToFindings />);

    const link = screen.getByRole("link", { name: "Go to Findings page" });
    expect(link.className).toContain("text-button-tertiary");
    expect(link.className).toContain("hover:text-button-tertiary-hover");
  });
});
