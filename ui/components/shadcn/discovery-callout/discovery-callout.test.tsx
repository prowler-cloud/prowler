import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Button } from "@/components/shadcn/button/button";

import {
  DiscoveryCallout,
  DiscoveryCalloutAnchor,
  DiscoveryCalloutContent,
} from "./discovery-callout";

function renderCallout(open: boolean, onDismiss: () => void) {
  return render(
    <DiscoveryCallout open={open} onDismiss={onDismiss}>
      <DiscoveryCalloutAnchor asChild>
        <Button type="button">Anchor</Button>
      </DiscoveryCalloutAnchor>
      <DiscoveryCalloutContent
        title="Meet the feature"
        description="It lives right here."
        data-testid="callout"
      />
    </DiscoveryCallout>,
  );
}

describe("DiscoveryCallout", () => {
  it("renders the title and description while open", () => {
    // Given / When
    renderCallout(true, vi.fn());

    // Then
    expect(screen.getByTestId("callout")).toBeInTheDocument();
    expect(screen.getByText("Meet the feature")).toBeInTheDocument();
    expect(screen.getByText("It lives right here.")).toBeInTheDocument();
  });

  it("renders nothing while closed", () => {
    // Given / When
    renderCallout(false, vi.fn());

    // Then
    expect(screen.queryByTestId("callout")).not.toBeInTheDocument();
  });

  it("dismisses through the action button", () => {
    // Given
    const onDismiss = vi.fn();
    renderCallout(true, onDismiss);

    // When
    fireEvent.click(screen.getByRole("button", { name: "Got it" }));

    // Then
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("keeps focus free when it opens", () => {
    // Given / When: the callout opens on its own (not user-invoked)
    renderCallout(true, vi.fn());

    // Then: focus stays wherever the user had it
    expect(screen.getByTestId("callout")).not.toContainElement(
      document.activeElement as HTMLElement,
    );
  });
});
