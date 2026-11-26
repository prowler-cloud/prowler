import { expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";
import { GlobalSidePanel } from "@/components/side-panel/global-side-panel";
import { SAMPLE_ISSUES } from "@/lib/sample-preview/sample-issues";

import { IssuesList } from "./issues-list";

it("opens a sample issue and its findings without fetching tenant data", async () => {
  const fetchSpy = vi.spyOn(globalThis, "fetch");
  const issue = SAMPLE_ISSUES[0];
  const content = await IssuesList({ searchParams: {}, sample: true });
  const screen = await render(
    <>
      {content}
      <GlobalSidePanel />
    </>,
  );

  await screen
    .getByRole("button", { name: issue.attributes.title, exact: true })
    .click();
  await screen.getByRole("tab", { name: "Findings", exact: true }).click();

  await expect
    .element(
      screen.getByRole("button", {
        name: "Ensure S3 buckets are not publicly accessible",
        exact: true,
      }),
    )
    .toBeVisible();
  expect(fetchSpy).not.toHaveBeenCalled();
});
