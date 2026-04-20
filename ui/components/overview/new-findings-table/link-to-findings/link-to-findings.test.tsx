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
  }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

vi.mock("@/components/shadcn/button/button", () => ({
  Button: ({
    children,
    asChild,
  }: {
    children?: ReactNode;
    asChild?: boolean;
    variant?: string;
    size?: string;
  }) => <>{asChild ? children : <button>{children}</button>}</>,
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
});
