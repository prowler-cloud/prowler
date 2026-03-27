import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { QueryCodeEditor } from "./query-code-editor";

describe("QueryCodeEditor", () => {
  it("renders a code editor surface with the compact read-only badge", () => {
    // Given
    render(
      <QueryCodeEditor
        ariaLabel="openCypher"
        language="openCypher"
        value=""
        placeholder="MATCH (n) RETURN n LIMIT 25"
        requirementBadge="Read-only*"
        onChange={() => {}}
      />,
    );

    // When
    const editor = screen.getByRole("textbox", { name: /opencypher/i });

    // Then
    expect(editor).toHaveAttribute("contenteditable", "true");
    expect(screen.getByText("openCypher")).toBeInTheDocument();
    expect(screen.getByText("Read-only*")).toBeInTheDocument();
    expect(screen.getByText("MATCH (n) RETURN n LIMIT 25")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
  });

  it("propagates content changes and exposes the invalid state in the container", async () => {
    // Given
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <QueryCodeEditor
        ariaLabel="openCypher"
        language="openCypher"
        value=""
        invalid={true}
        onChange={onChange}
      />,
    );

    // When
    await user.type(screen.getByRole("textbox", { name: /opencypher/i }), "A");

    // Then
    expect(onChange).toHaveBeenCalled();
    expect(screen.getByTestId("query-code-editor")).toHaveClass(
      "border-border-error-primary",
    );
  });
});
