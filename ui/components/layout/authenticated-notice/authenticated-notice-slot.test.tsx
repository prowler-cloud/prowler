import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AuthenticatedNoticeSlot } from "./authenticated-notice-slot";

describe("AuthenticatedNoticeSlot", () => {
  it("renders no notice in the public application", () => {
    // Given / When
    const { container } = render(<AuthenticatedNoticeSlot />);

    // Then
    expect(container).toBeEmptyDOMElement();
  });
});
