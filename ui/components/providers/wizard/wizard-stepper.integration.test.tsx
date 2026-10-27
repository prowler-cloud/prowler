import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";

import { WizardStepper } from "./wizard-stepper";

// Like the modal frame: a marked size container, so lg: follows its width.
function renderInWizardFrame(width: number) {
  return render(
    <div data-responsive-container className="@container" style={{ width }}>
      <WizardStepper currentStep={1} />
    </div>,
  );
}

function boxOf(element: Element) {
  const { width, height } = element.getBoundingClientRect();
  return { width, height };
}

describe("wizard stepper", () => {
  it("fits on one row naming only the current step while the wizard stacks", async () => {
    // When
    const screen = await renderInWizardFrame(720);

    // Then
    const progress = screen
      .getByRole("navigation", { name: "Wizard progress" })
      .element();
    expect(boxOf(progress).height).toBeLessThanOrEqual(40);
    await expect
      .element(screen.getByText("Authenticate Credentials"))
      .toBeVisible();
    // Other steps keep their names for assistive tech but take no room.
    const otherStep = screen.getByText("Link a Provider").element();
    expect(otherStep.checkVisibility()).toBe(true);
    // The block holding the name is clipped to 1px; the text inside overflows it.
    expect(boxOf(otherStep.closest("div")!).width).toBeLessThanOrEqual(1);
    await expect
      .element(
        screen.getByText(
          "Authorize a secure connection between Prowler and your provider.",
        ),
      )
      .not.toBeVisible();
    expect(
      screen
        .getByText("Authenticate Credentials")
        .element()
        .closest("[aria-current]"),
    ).toHaveAttribute("aria-current", "step");
  });

  it("lists every step with its description beside a wide wizard", async () => {
    // When
    const screen = await renderInWizardFrame(1200);

    // Then
    await expect
      .element(
        screen.getByText(
          "Enter the provider details you would like to add in Prowler.",
        ),
      )
      .toBeVisible();
    await expect.element(screen.getByText("Link a Provider")).toBeVisible();
    expect(
      boxOf(
        screen.getByRole("navigation", { name: "Wizard progress" }).element(),
      ).height,
    ).toBeGreaterThan(300);
  });
});
