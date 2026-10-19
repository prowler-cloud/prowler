import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { page, userEvent } from "vitest/browser";

import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import { ExploitabilityChart } from "@/app/(prowler)/_overview/exploitability/_components/exploitability-chart";
import { TopIssues } from "@/app/(prowler)/_overview/exploitability/_components/top-issues";
import { IssuesList } from "@/app/(prowler)/issues/_components/issues-list";
import { IssueResource, IssuesOverviewAttributes } from "@/types/issues";

const resource = `arn:aws:s3:::production-customer-data-${"long-resource-name-".repeat(8)}`;
const issue: IssueResource = {
  type: "issues",
  id: "issue-1",
  attributes: {
    pattern: "aws_public_bucket",
    cloud: "aws",
    account: "Production",
    title: "Public bucket exposes customer data",
    verdict: "likely",
    severity: "high",
    findings_count: 3,
    fix: "Enable S3 Block Public Access and review the bucket policy.",
    inserted_at: "",
    updated_at: "",
    legs: {
      reachability: {
        state: "yes",
        text: "Public access is enabled.",
        evidence: [`s3_public · ${resource}`],
      },
      access: {
        state: "partial",
        text: "Some access controls are in place.",
        evidence: [],
      },
      target: {
        state: "unknown",
        text: "Data sensitivity has not been verified.",
        evidence: [],
      },
      controls: {
        state: "no",
        text: "Block Public Access is disabled.",
        evidence: [],
      },
      verification: {
        state: "unknown",
        text: "Logging has not been verified.",
        evidence: [],
      },
    },
  },
  relationships: {
    provider: { data: { type: "providers", id: "provider-1" } },
    scan: { data: { type: "scans", id: "scan-1" } },
  },
};
const summary: IssuesOverviewAttributes = {
  exploitable: 0,
  likely: 1,
  conditional: 0,
  not_exploitable: 0,
  unknown: 0,
  findings: 3,
  issues: 1,
  actionable: 1,
  not_exploitable_findings: 0,
};

const setup = () => {
  window.history.replaceState(
    null,
    "",
    "/issues?filter[pattern]=aws_public_bucket",
  );
  worker.use(
    http.get("*/issues/overview", () =>
      HttpResponse.json({
        data: { type: "issues-overview", attributes: summary },
      }),
    ),
    http.get("*/issues", () => HttpResponse.json({ data: [issue] })),
    http.get("*/issues/issue-1", () =>
      HttpResponse.json({
        data: {
          ...issue,
          attributes: {
            ...issue.attributes,
            resource_uids: [resource],
            finding_uids: ["f1"],
          },
        },
      }),
    ),
    http.get("*/findings", () =>
      HttpResponse.json({
        data: [
          {
            type: "findings",
            id: "f1",
            attributes: {
              check_id: "s3_public",
              severity: "critical",
              check_metadata: { checktitle: "S3 bucket is public" },
            },
            relationships: {
              resources: { data: [{ type: "resources", id: "r1" }] },
            },
          },
        ],
        included: [
          { type: "resources", id: "r1", attributes: { uid: resource } },
        ],
      }),
    ),
  );
};

describe("Issues responsive layout", () => {
  afterEach(async () => {
    localStorage.removeItem("theme");
    await page.viewport(1280, 800);
  });

  it.each([
    { width: 375, theme: "light" },
    { width: 768, theme: "light" },
    { width: 1440, theme: "light" },
    { width: 375, theme: "dark" },
    { width: 1440, theme: "dark" },
  ])(
    "keeps the filters and expanded detail usable at $width px in $theme mode",
    async ({ width, theme }) => {
      await page.viewport(width, 1000);
      localStorage.setItem("theme", theme);
      setup();
      const content = await IssuesList({
        searchParams: { "filter[pattern]": "aws_public_bucket" },
      });
      const screen = await render(
        <main className="min-w-0 p-4">
          <h1 className="mb-6 text-2xl font-semibold">Issues</h1>
          {content}
        </main>,
      );
      await expect
        .element(screen.getByRole("button", { name: "Remove Pattern filter" }))
        .toBeVisible();
      await screen
        .getByRole("button", {
          name: "Expand Public bucket exposes customer data",
        })
        .click();
      await expect
        .element(screen.getByRole("region", { name: "Affected resources" }))
        .toBeVisible();
      await expect
        .element(screen.getByText("Partly", { exact: true }))
        .toBeVisible();
      await expect
        .element(
          screen.getByRole("img", { name: "Critical finding risk icon" }),
        )
        .toBeVisible();
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(width);
      const detailBounds = screen
        .getByRole("region", { name: "Affected resources" })
        .element()
        .getBoundingClientRect();
      expect(detailBounds.right).toBeLessThanOrEqual(width);
      if (width < 640) {
        await expect
          .poll(() => {
            const node = screen
              .getByTestId("attack-path-finding-node")
              .element();
            const canvas = node.closest(".react-flow")!.getBoundingClientRect();
            const bounds = node.getBoundingClientRect();
            return bounds.left >= canvas.left && bounds.right <= canvas.right;
          })
          .toBe(true);
      }

      // Long resource identifiers and evidence must wrap within the detail.
      for (const snippet of screen
        .getByText(resource, { exact: true })
        .elements()) {
        expect(snippet.scrollWidth).toBeLessThanOrEqual(
          snippet.clientWidth + 1,
        );
      }
      await page.viewport(
        width,
        Math.max(1000, document.documentElement.scrollHeight),
      );
      await screen.getByRole("main").screenshot();
      await screen
        .getByRole("button", {
          name: "Collapse Public bucket exposes customer data",
        })
        .click();
      await expect
        .element(screen.getByRole("region", { name: "Affected resources" }))
        .not.toBeInTheDocument();
    },
  );

  it("keeps keyboard focus on the expansion control", async () => {
    setup();
    const screen = await render(await IssuesList({ searchParams: {} }));
    const toggle = screen.getByRole("button", {
      name: "Expand Public bucket exposes customer data",
    });
    toggle.element().focus();
    await userEvent.keyboard("{Enter}");
    await expect
      .element(
        screen.getByRole("button", {
          name: "Collapse Public bucket exposes customer data",
        }),
      )
      .toHaveFocus();
    await userEvent.keyboard(" ");
    await expect.element(toggle).toHaveFocus();
  });

  it.each([375, 768, 1440])(
    "contains overview cards at %s px",
    async (width) => {
      await page.viewport(width, 1000);
      const screen = await render(
        <main className="flex min-w-0 flex-col gap-6 p-4 lg:flex-row">
          <ExploitabilityChart
            counts={summary}
            issues={1}
            findings={3}
            actionable={1}
            scope={{}}
          />
          <TopIssues issues={[issue]} scope={{}} />
        </main>,
      );
      await expect
        .element(
          screen.getByRole("link", { name: "1 exploitable or likely issues" }),
        )
        .toBeVisible();
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(width);
      await screen.getByRole("main").screenshot();
    },
  );
});
