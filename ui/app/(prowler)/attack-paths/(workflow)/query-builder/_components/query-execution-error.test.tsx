import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { QueryExecutionError } from "./query-execution-error";

describe("QueryExecutionError", () => {
  it("renders a formatted error alert with the raw query error details", () => {
    // Given
    const error =
      "Invalid input 'WHERE': expected 'MATCH' or 'WITH' (line 1, column 1)";

    // When
    render(<QueryExecutionError error={error} />);

    // Then
    expect(
      screen.getByRole("heading", { name: /query execution failed/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/the attack paths query could not be executed/i),
    ).toBeInTheDocument();
    expect(screen.getByText(error)).toBeInTheDocument();
  });
});
