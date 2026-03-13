import { render, screen } from "@testing-library/react";
import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import type { AttackPathQuery } from "@/types/attack-paths";

import { QueryParametersForm } from "./query-parameters-form";

const mockQuery: AttackPathQuery = {
  type: "attack-paths-scans",
  id: "query-with-string-parameter",
  attributes: {
    name: "Query With String Parameter",
    short_description: "Requires a tag key",
    description: "Returns buckets filtered by tag",
    provider: "aws",
    attribution: null,
    parameters: [
      {
        name: "tag_key",
        label: "Tag key",
        data_type: "string",
        description: "Tag key to filter the S3 bucket.",
        placeholder: "DataClassification",
        required: true,
      },
    ],
  },
};

function TestForm() {
  const form = useForm({
    defaultValues: {
      tag_key: "",
    },
  });

  return (
    <FormProvider {...form}>
      <QueryParametersForm selectedQuery={mockQuery} />
    </FormProvider>
  );
}

describe("QueryParametersForm", () => {
  it("uses the field description as the placeholder instead of rendering helper text below", () => {
    // Given
    render(<TestForm />);

    // When
    const input = screen.getByRole("textbox", { name: /tag key/i });

    // Then
    expect(input).toHaveAttribute("data-slot", "input");
    expect(input).toHaveAttribute(
      "placeholder",
      "Tag key to filter the S3 bucket.",
    );
    expect(screen.getByTestId("query-parameters-grid")).toHaveClass(
      "grid",
      "grid-cols-1",
      "md:grid-cols-2",
    );
    expect(screen.getByText("Tag key")).toHaveClass(
      "text-text-neutral-tertiary",
      "text-xs",
      "font-medium",
    );
    expect(
      screen.queryByText("Tag key to filter the S3 bucket."),
    ).not.toBeInTheDocument();
  });
});
