import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ManagedLighthouseCallout } from "./managed-lighthouse-callout";

describe("ManagedLighthouseCallout", () => {
  it("renders nothing: Cloudy has no hosted Lighthouse upsell", () => {
    const { container } = render(<ManagedLighthouseCallout />);

    expect(container).toBeEmptyDOMElement();
  });
});
