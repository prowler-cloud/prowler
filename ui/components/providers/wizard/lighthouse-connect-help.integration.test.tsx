import type { ReactNode } from "react";
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

const LEFT_COLUMN_WIDTH = 328;

function Help({ docsDestination = "Provider" }: { docsDestination?: string }) {
  return (
    <LighthouseConnectHelp
      docsLink="https://goto.prowler.com/provider-aws"
      docsDestination={docsDestination}
      providerType={null}
      mode="add"
      stepName="connect"
      stepLabel="Connect Provider"
      connectionMethod={null}
      isOrganizationsFlow={false}
    />
  );
}

// Like the modal frame: a marked size container, so lg: follows its width.
// A wide wizard holds the help in its left column, above the steps.
function Frame({ width, children }: { width: number; children: ReactNode }) {
  return (
    <div data-responsive-container className="@container" style={{ width }}>
      <div className="lg:w-[328px]">{children}</div>
    </div>
  );
}

function renderInWizardFrame(width: number) {
  return render(
    <Frame width={width}>
      <Help />
    </Frame>,
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

  it("fits the left column and keeps its height when the docs link changes", async () => {
    // Given
    const screen = await renderInWizardFrame(1200);
    await expect
      .element(screen.getByRole("button", { name: "Ask Lighthouse AI" }))
      .toBeVisible();
    const callout = () =>
      screen
        .getByRole("region", { name: "Help from Lighthouse AI" })
        .element()
        .getBoundingClientRect();
    const before = callout();

    // When: picking another method points the docs link elsewhere.
    await screen.rerender(
      <Frame width={1200}>
        <Help docsDestination="Alibaba Cloud Credentials" />
      </Frame>,
    );

    // Then: the steps below the help do not move.
    expect(before.width).toBeLessThanOrEqual(LEFT_COLUMN_WIDTH);
    expect(callout().height).toBe(before.height);
  });
});
