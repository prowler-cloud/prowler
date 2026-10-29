import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { page } from "vitest/browser";

import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import {
  getFindingGroups,
  getFindingGroupResources,
} from "@/actions/finding-groups";
import { getScan } from "@/actions/scans";
import { ExploitabilityChart } from "@/app/(prowler)/_overview/exploitability/_components/exploitability-chart";
import { TopIssues } from "@/app/(prowler)/_overview/exploitability/_components/top-issues";
import { IssuesList } from "@/app/(prowler)/issues/_components/issues-list";
import { IssueDetail } from "@/components/issues/issue-detail";
import { GlobalSidePanel } from "@/components/side-panel/global-side-panel";
import { applyDefaultMutedFilter, extractFiltersAndQuery } from "@/lib";
import { resolveFindingScanDateFilters } from "@/lib/findings-scan-filters";
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

  it("opens the selected finding's group and muted resource through the destination actions", async () => {
    // Given: the destination returns the finding only for its supported filters.
    setup();
    worker.use(
      http.get("*/scans/scan-1", () =>
        HttpResponse.json({
          data: {
            id: "scan-1",
            type: "scans",
            attributes: {
              inserted_at: "2026-10-20T10:00:00Z",
              completed_at: "2026-10-20T11:00:00Z",
            },
          },
        }),
      ),
      http.get("*/finding-groups", ({ request }) => {
        const params = new URL(request.url).searchParams;
        const matches =
          params.get("filter[check_id__in]") === "s3_public" &&
          params.get("filter[resource_uid]") === resource &&
          params.get("filter[scan__in]") === "scan-1" &&
          params.get("filter[inserted_at]") === "2026-10-20" &&
          params.get("filter[muted]") === "include";
        return HttpResponse.json({
          data: matches ? [{ id: "s3_public", type: "finding-groups" }] : [],
        });
      }),
      http.get("*/finding-groups/s3_public/resources", ({ request }) => {
        const params = new URL(request.url).searchParams;
        const matches =
          params.get("filter[resource_uid]") === resource &&
          params.get("filter[muted]") === "include";
        return HttpResponse.json({
          data: matches
            ? [{ id: "r1", attributes: { finding_id: "f1", muted: true } }]
            : [],
        });
      }),
    );
    const screen = await render(
      <IssueDetail
        id={issue.id}
        issue={issue.attributes}
        scanId="scan-1"
        providerId="provider-1"
      />,
    );
    const link = screen.getByRole("link", { name: "S3 bucket is public" });
    await expect.element(link).toBeVisible();

    // When: resolve the same filters used by the Findings page and drill-down.
    const destination = new URL(
      link.element().getAttribute("href")!,
      window.location.origin,
    );
    const { filters } = extractFiltersAndQuery(
      Object.fromEntries(destination.searchParams),
    );
    const resolvedFilters = applyDefaultMutedFilter(
      await resolveFindingScanDateFilters({
        filters,
        scans: [],
        loadScan: async (id) => (await getScan(id))?.data,
      }),
    );
    const groups = await getFindingGroups({ filters: resolvedFilters });

    // Then
    expect(groups.data).toEqual([{ id: "s3_public", type: "finding-groups" }]);
    expect(destination.searchParams.get("expandedCheckId")).toBe("s3_public");
    const resources = await getFindingGroupResources({
      checkId: "s3_public",
      filters: resolvedFilters,
    });
    expect(resources.data).toEqual([
      { id: "r1", attributes: { finding_id: "f1", muted: true } },
    ]);
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
      .element(screen.getByRole("link", { name: "Open the full path" }))
      .toHaveAttribute("href", "/issues/issue-1");
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
      .element(screen.getByRole("link", { name: "Open the full path" }))
      .toHaveAttribute("href", "/issues/issue-2");
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
    "keeps the list and the issue detail usable at $width px in $theme mode",
    async ({ width, theme }) => {
      await page.viewport(width, 1000);
      localStorage.setItem("theme", theme);
      setup();
      const content = await IssuesList({
        searchParams: { "filter[pattern]": "aws_public_bucket" },
      });
      const screen = await render(
        <main className="flex min-w-0 flex-col gap-6 p-4">
          <h1 className="text-2xl font-semibold">Issues</h1>
          {content}
          <IssueDetail
            id={issue.id}
            issue={issue.attributes}
            scanId="scan-1"
            providerId="provider-1"
          />
        </main>,
      );
      await expect
        .element(screen.getByRole("button", { name: "Remove Pattern filter" }))
        .toBeVisible();
      await expect
        .element(
          screen.getByText("The internet → Data exposure · aws_public_bucket"),
        )
        .toBeVisible();
      await expect
        .element(screen.getByRole("region", { name: "Affected resources" }))
        .toBeVisible();
      await expect
        .element(screen.getByText("Partly", { exact: true }))
        .toBeVisible();
      await expect.element(screen.getByText("Public by design.")).toBeVisible();
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
