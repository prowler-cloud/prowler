import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "./tabs";

describe("Tabs", () => {
  it("animates tab content when switching between tabs", async () => {
    // Given - A tabs group with two content panels
    const user = userEvent.setup();
    render(
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">Overview content</TabsContent>
        <TabsContent value="events">Events content</TabsContent>
      </Tabs>,
    );

    // When - The user switches to another tab
    await user.click(screen.getByRole("tab", { name: /events/i }));

    const eventsPanel = screen.getByText("Events content");

    // Then - The newly active content keeps the motion-ready content element
    expect(eventsPanel).toHaveAttribute("data-slot", "tabs-content");
    expect(eventsPanel).toHaveClass(
      "will-change-transform",
      "motion-reduce:transform-none",
    );
    expect(eventsPanel).toHaveAttribute("data-state", "active");
  });
});
