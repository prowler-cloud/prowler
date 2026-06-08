import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Tabs, TabsList, TabsTrigger } from "./tabs";

describe("TabsTrigger", () => {
  it("keeps active styling available when rendered with a tooltip", () => {
    render(
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview" tooltip="Overview">
            Overview
          </TabsTrigger>
          <TabsTrigger value="remediation" tooltip="Remediation">
            Remediation
          </TabsTrigger>
        </TabsList>
      </Tabs>,
    );

    const activeTrigger = screen.getByRole("tab", { name: "Overview" });

    expect(activeTrigger).toHaveAttribute("aria-selected", "true");
    expect(activeTrigger).toHaveClass("aria-selected:text-slate-900");
    expect(activeTrigger).toHaveClass("aria-selected:after:scale-x-100");
  });
});
