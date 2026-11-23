import { expect, it } from "vitest";

import { render } from "@/__tests__/render-browser";
import {
  SAMPLE_NEW_FINDINGS,
  SAMPLE_RADAR_DATA,
} from "@/lib/sample-preview/sample-graphs";

import { SampleGraphsTabs } from "./sample-graphs-tabs";

it("offers each latest new failed finding as a drawer trigger", async () => {
  const screen = await render(<SampleGraphsTabs />);
  const [finding] = SAMPLE_NEW_FINDINGS;

  // The trigger opens the finding drawer, which resolves sample ids locally.
  await expect
    .element(
      screen
        .getByRole("button", {
          name: finding.attributes.check_metadata.checktitle,
        })
        .first(),
    )
    .toBeEnabled();
});

it("lets users explore sample categories without opening live findings", async () => {
  const screen = await render(<SampleGraphsTabs />);
  const category = SAMPLE_RADAR_DATA[0];

  await screen.getByRole("tab", { name: "Risk Radar" }).click();
  await screen.getByRole("combobox").click();
  await screen
    .getByRole("option", { name: category.category, exact: true })
    .click();

  await expect
    .element(screen.getByText(`${category.value} Total Findings`))
    .toBeVisible();
  await expect
    .element(screen.getByRole("button", { name: /Critical/ }))
    .not.toBeInTheDocument();
});
