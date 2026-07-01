import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("./_components/advanced-mutelist-form", () => ({
  AdvancedMutelistForm: () => <div>Advanced form</div>,
}));

import { MutelistTabs } from "./mutelist-tabs";

describe("MutelistTabs", () => {
  it("should render text-only tab triggers without icons", () => {
    // Given/When
    render(<MutelistTabs simpleContent={<div>Simple table</div>} />);

    // Then
    const simpleTab = screen.getByRole("tab", { name: "Simple" });
    const advancedTab = screen.getByRole("tab", { name: "Advanced" });

    expect(simpleTab).toBeInTheDocument();
    expect(advancedTab).toBeInTheDocument();
    expect(simpleTab.querySelector("svg")).not.toBeInTheDocument();
    expect(advancedTab.querySelector("svg")).not.toBeInTheDocument();
  });
});
