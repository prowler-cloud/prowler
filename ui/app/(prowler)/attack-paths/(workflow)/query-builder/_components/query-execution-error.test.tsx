import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { QueryExecutionError } from "./query-execution-error";

describe("QueryExecutionError", () => {
  it("renders the default title and the raw query error details without extra copy", () => {
    // Given
    const error =
      "Invalid input 'WHERE': expected 'MATCH' or 'WITH' (line 1, column 1)";

    // When
    render(<QueryExecutionError error={error} />);

    // Then
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByText(/query execution failed/i)).toBeInTheDocument();
    expect(
      screen.queryByText(/the attack paths query could not be executed/i),
    ).not.toBeInTheDocument();
    expect(screen.getByText(error)).toBeInTheDocument();
  });

  it("renders custom title and description when provided", () => {
    // Given
    const error = "Failed to load available queries";

    // When
    render(
      <QueryExecutionError
        title="Failed to load queries"
        description="Available Attack Paths queries could not be loaded for this scan."
        error={error}
      />,
    );

    // Then
    expect(screen.getByText(/failed to load queries/i)).toBeInTheDocument();
    expect(
      screen.getByText(
        /available attack paths queries could not be loaded for this scan/i,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(error)).toBeInTheDocument();
  });
});
