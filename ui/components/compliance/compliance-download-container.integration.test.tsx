import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";

import { ComplianceDownloadContainer } from "./compliance-download-container";

// Like <main>: a marked size container, so sm: follows its width.
function renderInPage(width: number) {
  return render(
    <div data-responsive-container className="@container" style={{ width }}>
      <ComplianceDownloadContainer
        compact
        scanId="scan-1"
        complianceId="compliance-1"
        reportType="threatscore"
      />
    </div>,
  );
}

// sr-only text keeps a 1px box, so its width tells whether it takes room.
function labelWidth(screen: Awaited<ReturnType<typeof renderInPage>>) {
  return screen
    .getByText("CSV", { exact: true })
    .element()
    .getBoundingClientRect().width;
}

describe("compact compliance downloads", () => {
  it("shows only the icons on a narrow page", async () => {
    // When
    const screen = await renderInPage(400);

    // Then
    await expect
      .element(
        screen.getByRole("button", { name: "Download compliance CSV report" }),
      )
      .toBeVisible();
    expect(labelWidth(screen)).toBeLessThanOrEqual(1);
  });

  it("names each format beside its icon from sm up", async () => {
    // When
    const screen = await renderInPage(800);

    // Then
    expect(labelWidth(screen)).toBeGreaterThan(1);
  });
});
