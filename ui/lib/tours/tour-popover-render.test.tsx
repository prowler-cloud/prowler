import { act, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PopoverDOM } from "driver.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  renderTourPopover,
  unmountActiveTourPopover,
} from "./tour-popover-render";

function createPopover(): PopoverDOM {
  const wrapper = document.createElement("div");
  const arrow = document.createElement("div");
  const title = document.createElement("header");
  const description = document.createElement("div");
  const footer = document.createElement("footer");
  const progress = document.createElement("span");
  const previousButton = document.createElement("button");
  const nextButton = document.createElement("button");
  const closeButton = document.createElement("button");
  const footerButtons = document.createElement("span");

  title.textContent = "Explore findings";
  description.textContent = "Review grouped findings and resources.";
  progress.textContent = "Step 2 of 4";
  previousButton.textContent = "Back";
  nextButton.textContent = "Next";
  closeButton.setAttribute("aria-label", "Close");

  wrapper.append(title, description, footer, closeButton, arrow);
  footer.append(progress, footerButtons);
  footerButtons.append(previousButton, nextButton);
  document.body.appendChild(wrapper);

  return {
    wrapper,
    arrow,
    title,
    description,
    footer,
    progress,
    previousButton,
    nextButton,
    closeButton,
    footerButtons,
  };
}

describe("renderTourPopover", () => {
  afterEach(() => {
    act(() => unmountActiveTourPopover());
    document.body.innerHTML = "";
  });

  it("renders tour UI with existing app components", async () => {
    // Given
    const popover = createPopover();

    // When
    await act(async () => renderTourPopover(popover));
    const tourUi = within(
      popover.wrapper.querySelector<HTMLElement>("[data-tour-popover-root]")!,
    );

    // Then
    expect(tourUi.getByText("Explore findings")).toBeVisible();
    expect(
      tourUi.getByText("Review grouped findings and resources."),
    ).toBeVisible();
    expect(tourUi.getByText("Step 2 of 4")).toBeVisible();
    expect(tourUi.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "50",
    );
    expect(tourUi.getByText("Explore findings")).toHaveAttribute(
      "data-slot",
      "card-title",
    );
    expect(tourUi.getByRole("button", { name: "Next" })).toHaveAttribute(
      "data-slot",
      "button",
    );
    expect(popover.title).not.toBeVisible();
    expect(popover.footer).not.toBeVisible();
  });

  it("renders synchronously so driver.js measures the real card dimensions", () => {
    // Given
    const popover = createPopover();

    // When
    renderTourPopover(popover);

    // Then
    expect(
      popover.wrapper.querySelector('[data-slot="card"]'),
    ).toBeInTheDocument();
  });

  it("applies the onboarding popover styling on the card and its slots", async () => {
    // Given
    const popover = createPopover();

    // When
    await act(async () => renderTourPopover(popover));

    // Then — styling lives at this callsite, not in a shared Card variant.
    const card = popover.wrapper.querySelector('[data-slot="card"]')!;
    expect(card).toHaveClass("gap-0");
    expect(card).toHaveClass("shadow-lg");
    const footer = popover.wrapper.querySelector('[data-slot="card-footer"]')!;
    expect(footer).toHaveClass("justify-end");
    expect(footer).toHaveClass("gap-2");
    expect(footer).toHaveClass("px-0");
  });

  it("delegates visible button clicks to driver.js native controls", async () => {
    // Given
    const user = userEvent.setup();
    const popover = createPopover();
    const onPrevious = vi.fn();
    const onNext = vi.fn();
    const onClose = vi.fn();
    popover.previousButton.addEventListener("click", onPrevious);
    popover.nextButton.addEventListener("click", onNext);
    popover.closeButton.addEventListener("click", onClose);
    await act(async () => renderTourPopover(popover));

    // When
    await user.click(screen.getByRole("button", { name: "Back" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Close" }));

    // Then
    expect(onPrevious).toHaveBeenCalledTimes(1);
    expect(onNext).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
