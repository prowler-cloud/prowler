import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";

import {
  ORGANIZATION_WIZARD_STEPS,
  PROVIDER_WIZARD_STEPS,
  WizardStepper,
} from "./wizard-stepper";

// Like the modal frame: a marked size container, so lg: follows its width.
function renderInWizardFrame(width: number) {
  return render(
    <div data-responsive-container className="@container" style={{ width }}>
      <WizardStepper currentStep={1} steps={ORGANIZATION_WIZARD_STEPS} />
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
    await expect.element(screen.getByText("Select Accounts")).toBeVisible();
    // Other steps keep their names for assistive tech but take no room.
    await expect.element(
      screen.getByRole("navigation", { name: "Wizard progress" }),
    ).toMatchAriaInlineSnapshot(`
        - navigation "Wizard progress":
          - text: Organization Access Select Accounts Launch Scan
      `);
    const otherStep = screen.getByText("Organization Access").element();
    expect(otherStep.checkVisibility()).toBe(true);
    // The block holding the name is clipped to 1px; the text inside overflows it.
    expect(boxOf(otherStep.closest("div")!).width).toBeLessThanOrEqual(1);
    await expect
      .element(
        screen.getByText(
          "Prowler discovers the organization; pick what to connect.",
        ),
      )
      .not.toBeVisible();
    expect(
      screen.getByText("Select Accounts").element().closest("[aria-current]"),
    ).toHaveAttribute("aria-current", "step");
  });

  it("lists every step with its description beside a wide wizard", async () => {
    // When
    const screen = await renderInWizardFrame(1200);

    // Then
    await expect
      .element(
        screen.getByText(
          "Name the organization and deploy the access Prowler uses in every account.",
        ),
      )
      .toBeVisible();
    await expect.element(screen.getByText("Organization Access")).toBeVisible();
    expect(
      boxOf(
        screen.getByRole("navigation", { name: "Wizard progress" }).element(),
      ).height,
    ).toBeGreaterThan(200);
  });

  it.each([360, 720])(
    "names both steps of the provider flow on one row at %ipx while stacked",
    async (width) => {
      // When
      const screen = await render(
        <div data-responsive-container className="@container" style={{ width }}>
          <WizardStepper currentStep={0} steps={PROVIDER_WIZARD_STEPS} />
        </div>,
      );

      // Then
      const progress = screen
        .getByRole("navigation", { name: "Wizard progress" })
        .element();
      // A name clipped to 1px for assistive tech would still count as visible.
      for (const name of ["Connect Provider", "Launch Scan"]) {
        const block = screen.getByText(name).element().closest("div")!;
        expect(boxOf(block).width, name).toBeGreaterThan(20);
      }
      expect(boxOf(progress).height).toBeLessThanOrEqual(40);
      expect(progress.scrollWidth).toBeLessThanOrEqual(width);
    },
  );

  it("names the upcoming step beside a wide wizard", async () => {
    // When
    const screen = await render(
      <div
        data-responsive-container
        className="@container"
        style={{ width: 1200 }}
      >
        <WizardStepper currentStep={0} steps={PROVIDER_WIZARD_STEPS} />
      </div>,
    );

    // Then
    const block = screen.getByText("Launch Scan").element().closest("div")!;
    expect(boxOf(block).width).toBeGreaterThan(20);
  });
});
