import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useLighthouseContextStore } from "@/store/lighthouse-context/store";

import { LighthouseContextContributor } from "./context-contributor";

describe("LighthouseContextContributor", () => {
  beforeEach(() => {
    useLighthouseContextStore.getState().resetContributions();
  });

  it("should register loaded page data and remove it on unmount", () => {
    // Given / When
    const view = render(
      <LighthouseContextContributor
        contributorId="findings-total"
        item={{
          kind: "finding",
          id: "findings-summary",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Visible findings",
          findingId: "summary",
          total: 42,
        }}
      />,
    );

    // Then
    expect(
      useLighthouseContextStore.getState().contributions["findings-total"],
    ).toMatchObject({ total: 42 });

    // When
    view.unmount();

    // Then
    expect(
      useLighthouseContextStore.getState().contributions["findings-total"],
    ).toBeUndefined();
  });

  it("should replace the contribution when its loaded snapshot changes", () => {
    const view = render(
      <LighthouseContextContributor
        contributorId="findings-total"
        item={{
          kind: "finding",
          id: "findings-summary",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Visible findings",
          findingId: "summary",
          total: 42,
        }}
      />,
    );

    view.rerender(
      <LighthouseContextContributor
        contributorId="findings-total"
        item={{
          kind: "finding",
          id: "findings-summary",
          source: "automatic",
          scopeKey: "findings:/findings",
          label: "Visible findings",
          findingId: "summary",
          total: 17,
        }}
      />,
    );

    expect(
      useLighthouseContextStore.getState().contributions["findings-total"],
    ).toMatchObject({ total: 17 });
  });
});
