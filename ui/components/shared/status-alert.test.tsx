import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatusAlert } from "./status-alert";

describe("StatusAlert", () => {
  it("renders the info variant with title and children", () => {
    render(
      <StatusAlert variant="info" title="Heads up">
        <span>Something to know.</span>
      </StatusAlert>,
    );

    expect(screen.getByText("Heads up")).toBeInTheDocument();
    expect(screen.getByText("Something to know.")).toBeInTheDocument();
  });

  it("renders the error variant with title and children", () => {
    render(
      <StatusAlert variant="error" title="It broke">
        <span>Try again.</span>
      </StatusAlert>,
    );

    expect(screen.getByText("It broke")).toBeInTheDocument();
    expect(screen.getByText("Try again.")).toBeInTheDocument();
  });

  it("applies descriptionClassName to the description element", () => {
    render(
      <StatusAlert
        variant="info"
        title="Styled"
        descriptionClassName="w-full gap-3"
      >
        <span>Body</span>
      </StatusAlert>,
    );

    const description = screen
      .getByText("Body")
      .closest("[data-slot='alert-description']");
    expect(description).toHaveClass("w-full", "gap-3");
  });
});
