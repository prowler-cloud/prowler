import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { page } from "vitest/browser";

import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import { ExploitabilityChart } from "@/app/(prowler)/_overview/exploitability/_components/exploitability-chart";
import { TopIssues } from "@/app/(prowler)/_overview/exploitability/_components/top-issues";
import { IssuesList } from "@/app/(prowler)/issues/_components/issues-list";
import { GlobalSidePanel } from "@/components/side-panel/global-side-panel";
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
    outcome: "data_exposure",
    attacker_start: "internet",
    findings_count: 3,
    triage_status: "open",
    notes_count: 0,
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
    http.get("*/issues/issue-1/triage/notes", () =>
      HttpResponse.json({
        data: [
          {
            type: "issue-triage-notes",
            id: "note-1",
            attributes: {
              body: "Public by design.",
              inserted_at: "2026-10-20T10:00:00Z",
            },
          },
        ],
      }),
    ),
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
              uid: "finding-uid-1",
              check_id: "s3_public",
              severity: "critical",
              triage_status: "risk_accepted",
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

  it("opens a folded finding inside the panel and comes back to the issue", async () => {
    // Given: the list next to the real side panel host the app shell mounts.
    setup();
    worker.use(
      http.get("*/findings/f1", () =>
        HttpResponse.json({
          data: {
            type: "findings",
            id: "f1",
            attributes: {
              uid: "finding-uid-1",
              check_id: "s3_public",
              status: "FAIL",
              severity: "critical",
              check_metadata: { checktitle: "S3 bucket is public" },
            },
            relationships: { resources: { data: [] } },
          },
        }),
      ),
    );
    const content = await IssuesList({ searchParams: {} });
    const screen = await render(
      <>
        {content}
        <GlobalSidePanel />
      </>,
    );
    await screen
      .getByRole("row", { name: /Public bucket exposes customer data/ })
      .getByText("Production")
      .click();
    await screen.getByRole("tab", { name: "Findings" }).click();

    // When
    await screen.getByRole("button", { name: "S3 bucket is public" }).click();

    // Then: the finding takes the panel without closing the issue
    const back = screen.getByRole("button", { name: "Issue details" });
    await expect.element(back).toBeVisible();
    await expect
      .element(screen.getByRole("tab", { name: "Exploitability" }))
      .not.toBeInTheDocument();

    // When
    await back.click();

    // Then
    await expect
      .element(screen.getByRole("tab", { name: "Findings" }))
      .toHaveAttribute("aria-selected", "true");
  });

  it("opens a clicked row in the app's Details side panel", async () => {
    // Given: the list next to the real side panel host the app shell mounts.
    setup();
    const content = await IssuesList({ searchParams: {} });
    const screen = await render(
      <>
        {content}
        <GlobalSidePanel />
      </>,
    );

    // When: a plain cell of the row is clicked, not the title button.
    await screen
      .getByRole("row", { name: /Public bucket exposes customer data/ })
      .getByText("Production")
      .click();

    // Then
    await expect
      .element(screen.getByText("Block Public Access is disabled."))
      .toBeVisible();

    // When: the attack path tab asks for the graph
    await screen.getByRole("tab", { name: "Attack path" }).click();

    // Then
    await expect
      .element(screen.getByRole("region", { name: "Finding evidence" }))
      .toBeVisible();
    await expect
      .element(screen.getByTestId("attack-path-finding-node"))
      .toBeVisible();
  });

  it("resets the Details tab when another row opens", async () => {
    // Given: the first issue's panel is open on the Remediation tab. The
    // panel overlays the right edge here (no app shell pushes the page), so
    // rows are clicked on their leftmost cell.
    await page.viewport(1440, 900);
    setup();
    const secondIssue: IssueResource = {
      ...issue,
      id: "issue-2",
      attributes: {
        ...issue.attributes,
        title: "Admin role assumable from any account",
        account: "Staging",
      },
    };
    worker.use(
      http.get("*/issues", () =>
        HttpResponse.json({ data: [issue, secondIssue] }),
      ),
      // The panel loads the evidence of whichever issue it opens.
      http.get("*/issues/issue-2", () =>
        HttpResponse.json({
          data: {
            ...secondIssue,
            attributes: { ...secondIssue.attributes, resource_uids: [] },
          },
        }),
      ),
    );
    const content = await IssuesList({ searchParams: {} });
    const screen = await render(
      <>
        {content}
        <GlobalSidePanel />
      </>,
    );
    await screen
      .getByRole("row", { name: /Public bucket exposes customer data/ })
      .getByText("Production")
      .click();
    await screen.getByRole("tab", { name: "Remediation" }).click();
    await expect
      .element(screen.getByRole("tab", { name: "Remediation" }))
      .toHaveAttribute("aria-selected", "true");

    // When
    await screen
      .getByRole("row", { name: /Admin role assumable from any account/ })
      .getByText("Likely")
      .click();

    // Then: the panel remounted on the new issue, back on its first tab
    await expect
      .element(
        screen.getByRole("heading", {
          level: 3,
          name: "Admin role assumable from any account",
        }),
      )
      .toBeVisible();
    await expect
      .element(screen.getByRole("tab", { name: "Exploitability" }))
      .toHaveAttribute("aria-selected", "true");
  });

  it.each([
    { width: 375, theme: "light" },
    { width: 768, theme: "light" },
    { width: 1440, theme: "light" },
    { width: 375, theme: "dark" },
    { width: 1440, theme: "dark" },
  ])(
    "keeps the list and the issue panel usable at $width px in $theme mode",
    async ({ width, theme }) => {
      await page.viewport(width, 1000);
      localStorage.setItem("theme", theme);
      setup();
      const content = await IssuesList({
        searchParams: { "filter[pattern]": "aws_public_bucket" },
      });
      const screen = await render(
        <>
          <main className="flex min-w-0 flex-col gap-6 p-4">
            <h1 className="text-2xl font-semibold">Issues</h1>
            {content}
          </main>
          <GlobalSidePanel />
        </>,
      );
      await expect
        .element(screen.getByRole("button", { name: "Remove Pattern filter" }))
        .toBeVisible();
      await expect
        .element(
          screen.getByText("The internet → Data exposure · aws_public_bucket"),
        )
        .toBeVisible();

      // When: the row opens in the panel
      await screen
        .getByRole("row", { name: /Public bucket exposes customer data/ })
        .getByRole("button", { name: "Public bucket exposes customer data" })
        .click();

      // Then: every tab fits the viewport, long identifiers wrap
      await expect
        .element(screen.getByText("Partly", { exact: true }))
        .toBeVisible();
      const fits = (element: Element) =>
        element.getBoundingClientRect().right <= width;
      for (const snippet of screen
        .getByText(resource, { exact: true })
        .elements()) {
        expect(snippet.scrollWidth).toBeLessThanOrEqual(
          snippet.clientWidth + 1,
        );
      }

      await screen.getByRole("tab", { name: "Findings" }).click();
      await expect
        .element(screen.getByRole("button", { name: "S3 bucket is public" }))
        .toBeVisible();

      await screen.getByRole("tab", { name: "Resources" }).click();
      const resources = screen.getByRole("region", {
        name: "Affected resources",
      });
      await expect.element(resources).toBeVisible();
      expect(fits(resources.element())).toBe(true);
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(width);
      await page.screenshot();

      await screen.getByRole("tab", { name: "Triage" }).click();
      await expect.element(screen.getByText("Public by design.")).toBeVisible();

      if (width < 640) {
        await screen.getByRole("tab", { name: "Attack path" }).click();
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
    },
  );

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
            coveredFindings={0}
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
