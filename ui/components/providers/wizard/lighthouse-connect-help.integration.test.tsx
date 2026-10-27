import { describe, expect, vi } from "vitest";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";

import { LighthouseConnectHelp } from "./lighthouse-connect-help";

vi.mock(import("@/lib/shared/env"), async (importOriginal) => ({
  ...(await importOriginal()),
  isCloud: () => true,
}));
vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  getLighthouseV2Configurations: () =>
    Promise.resolve({ data: [{ id: "config-1", connected: true }] }),
}));

const DESCRIPTION =
  "Lighthouse AI walks you through it with Prowler's docs, right beside this form.";

// Like the modal frame: a marked size container, so lg: follows its width.
function renderInWizardFrame(width: number) {
  return render(
    <div data-responsive-container className="@container" style={{ width }}>
      <LighthouseConnectHelp
        docsLink="https://goto.prowler.com/provider-aws"
        docsDestination="Provider"
        providerType={null}
        mode="add"
        stepName="connect"
        stepLabel="Link a Provider"
        isOrganizationsFlow={false}
      />
    </div>,
  );
}

describe("Lighthouse help in the wizard header", () => {
  it("keeps to a single line while the wizard stacks its steps", async () => {
    // When
    const screen = await renderInWizardFrame(720);

    // Then
    const callout = screen.getByRole("region", {
      name: "Help from Lighthouse AI",
    });
    await expect
      .element(screen.getByRole("button", { name: "Ask Lighthouse AI" }))
      .toBeVisible();
    await expect
      .element(screen.getByText("Not sure how to connect your cloud?"))
      .toBeVisible();
    await expect.element(screen.getByText(DESCRIPTION)).not.toBeVisible();
    expect(
      callout.element().getBoundingClientRect().height,
    ).toBeLessThanOrEqual(72);
  });

  it("explains what Lighthouse AI does beside a wide wizard", async () => {
    // When
    const screen = await renderInWizardFrame(1200);

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Ask Lighthouse AI" }))
      .toBeVisible();
    await expect.element(screen.getByText(DESCRIPTION)).toBeVisible();
  });
});
