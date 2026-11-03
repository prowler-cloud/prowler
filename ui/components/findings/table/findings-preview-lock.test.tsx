import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingsPreviewLock } from "./findings-preview-lock";

describe("FindingsPreviewLock", () => {
  it("never locks the findings list in Cloudy", () => {
    const { container } = render(<FindingsPreviewLock totalCount={1234} />);

    expect(container).toBeEmptyDOMElement();
  });
});
