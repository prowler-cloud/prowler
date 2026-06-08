import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "./card";

describe("Card", () => {
  it("provides an onboarding variant for product-tour surfaces", () => {
    // Given / When
    const { container } = render(<Card variant="onboarding" />);
    const card = container.firstElementChild;

    // Then
    expect(card).toHaveAttribute("data-slot", "card");
    expect(card).toHaveClass("bg-bg-neutral-tertiary");
    expect(card).toHaveClass("border-border-neutral-tertiary");
    expect(card).toHaveClass("gap-0");
    expect(card).toHaveClass("shadow-lg");
    expect(card).toHaveClass("px-4");
    expect(card).toHaveClass("py-3");
  });

  it("styles onboarding child slots through the card variant", () => {
    // Given / When
    const { container } = render(
      <Card variant="onboarding">
        <CardHeader>
          <CardTitle>Connect your first provider</CardTitle>
          <CardDescription>Guided setup copy.</CardDescription>
        </CardHeader>
        <CardContent>
          <CardDescription>Step 1 of 3</CardDescription>
        </CardContent>
        <CardFooter>
          <button type="button">Back</button>
          <button type="button">Next</button>
        </CardFooter>
      </Card>,
    );
    const card = container.firstElementChild;

    // Then
    expect(card).toHaveClass("[&_[data-slot=card-footer]]:justify-end");
    expect(card).toHaveClass("[&_[data-slot=card-footer]]:gap-2");
    expect(card).toHaveClass("[&_[data-slot=card-description]]:text-xs");
    expect(card).toHaveClass("[&_[data-slot=card-description]]:mt-2");
  });
});
