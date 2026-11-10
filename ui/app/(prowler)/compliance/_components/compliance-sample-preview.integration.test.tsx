import { expect, it } from "vitest";

import { render } from "@/__tests__/render-browser";
import { SAMPLE_THREAT_SCORE } from "@/lib/sample-preview/sample-overview";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";

import { ComplianceSamplePreview } from "./compliance-sample-preview";

it("opens sample framework details without offering report exports", async () => {
  // Given / When
  const screen = await render(
    <ComplianceSamplePreview
      state={{
        active: true,
        stage: SAMPLE_PREVIEW_STAGE.NO_PROVIDER,
        runningScan: null,
      }}
    />,
  );

  // Then: frameworks open their sample detail; reports stay unavailable.
  await expect
    .element(screen.getByRole("heading", { name: "CIS - 5.0", exact: true }))
    .toBeVisible();
  await expect
    .element(
      screen.getByRole("button", { name: "Open CIS - 5.0 compliance details" }),
    )
    .toBeEnabled();
  await expect
    .element(screen.getByRole("progressbar", { name: "ThreatScore progress" }))
    .toHaveAttribute("aria-valuenow", String(SAMPLE_THREAT_SCORE.score));
  await expect
    .element(screen.getByRole("button", { name: /export/i }))
    .not.toBeInTheDocument();
});
