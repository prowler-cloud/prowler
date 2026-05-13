import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { MarkdownContainer } from "./markdown-container";

describe("MarkdownContainer", () => {
  it("renders bold and inline code as semantic elements", () => {
    render(
      <MarkdownContainer>
        {"**Bedrock API keys** are evaluated, configured to `never expire`."}
      </MarkdownContainer>,
    );

    const code = screen.getByText("never expire");
    expect(code.tagName).toBe("CODE");
    expect(screen.getByText("Bedrock API keys").tagName).toBe("STRONG");
  });

  it("neutralizes the @tailwindcss/typography backtick pseudo-elements on inline code", () => {
    const { container } = render(
      <MarkdownContainer>{"text `code` text"}</MarkdownContainer>,
    );

    const wrapper = container.firstElementChild;
    expect(wrapper).not.toBeNull();
    const className = wrapper?.className ?? "";

    // The prose plugin from @tailwindcss/typography adds ::before/::after
    // pseudo-elements with literal backticks on every <code> tag. Without
    // these overrides the drawer renders `never expire` with visible
    // backticks, which is the bug PROWLER-1729 fixes.
    expect(className).toMatch(/prose-code:before:content-none/);
    expect(className).toMatch(/prose-code:after:content-none/);
  });
});
