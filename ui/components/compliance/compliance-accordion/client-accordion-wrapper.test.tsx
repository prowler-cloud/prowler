import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { AccordionItemProps } from "@/components/shadcn";

import { ClientAccordionWrapper } from "./client-accordion-wrapper";

const items: AccordionItemProps[] = [
  {
    key: "section-1",
    title: "Section 1",
    content: null,
    items: [{ key: "req-1", title: "Requirement 1", content: "detail" }],
  },
];

describe("ClientAccordionWrapper", () => {
  it("renders the expand-all control and the accordion inside one card", () => {
    const { container } = render(
      <ClientAccordionWrapper items={items} defaultExpandedKeys={[]} />,
    );

    const card = container.querySelector('[data-slot="card"]');
    expect(card).not.toBeNull();
    expect(card).toContainElement(
      screen.getByRole("button", { name: "Expand all" }),
    );
    expect(card).toContainElement(screen.getByText("Section 1"));
  });

  it("hides the expand-all control when requested", () => {
    render(
      <ClientAccordionWrapper
        items={items}
        defaultExpandedKeys={[]}
        hideExpandButton
      />,
    );

    expect(
      screen.queryByRole("button", { name: "Expand all" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Section 1")).toBeInTheDocument();
  });

  it("expands every section on Expand all and collapses back on toggle", async () => {
    const user = userEvent.setup();
    render(<ClientAccordionWrapper items={items} defaultExpandedKeys={[]} />);

    expect(screen.queryByText("Requirement 1")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Expand all" }));
    expect(screen.getByText("Requirement 1")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Collapse all" }));
    expect(screen.queryByText("Requirement 1")).not.toBeInTheDocument();
  });
});
