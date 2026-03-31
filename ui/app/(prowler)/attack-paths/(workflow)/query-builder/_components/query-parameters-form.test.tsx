import { render, screen } from "@testing-library/react";
import { useEffect } from "react";
import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathQuery,
} from "@/types/attack-paths";

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

function TestCustomQueryForm() {
  const customQuery: AttackPathQuery = {
    type: "attack-paths-scans",
    id: ATTACK_PATH_QUERY_IDS.CUSTOM,
    attributes: {
      name: "Custom openCypher query",
      short_description: "Write your own query",
      description: "Run a custom query against the graph.",
      provider: "aws",
      attribution: null,
      parameters: [
        {
          name: "query",
          label: "openCypher",
          data_type: "string",
          input_type: "code-editor",
          placeholder: "MATCH (n) RETURN n LIMIT 25",
          description: "",
          required: true,
          editor_language: "openCypher",
          requirement_badge: "Read-only*",
        },
      ],
    },
  };

  const form = useForm({
    defaultValues: {
      query: "",
    },
  });

  return (
    <FormProvider {...form}>
      <QueryParametersForm selectedQuery={customQuery} />
    </FormProvider>
  );
}

function TestFormWithError() {
  const form = useForm({
    defaultValues: {
      tag_key: "",
    },
  });

  useEffect(() => {
    form.setError("tag_key", {
      type: "manual",
      message: "Tag key is required",
    });
  }, [form]);

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

  it("renders a code editor when the parameter input type is code-editor", () => {
    // Given
    render(<TestCustomQueryForm />);

    // When
    const input = screen.getByRole("textbox", { name: /opencypher/i });
    const codeEditor = screen.getByTestId("query-code-editor");

    // Then
    expect(input.tagName).toBe("DIV");
    expect(input).toHaveAttribute("contenteditable", "true");
    expect(codeEditor).toHaveAttribute("data-language", "openCypher");
    expect(codeEditor).toHaveClass(
      "rounded-xl",
      "border",
      "bg-bg-neutral-primary",
    );
    expect(screen.getByText("Read-only*")).toBeInTheDocument();
    expect(screen.getByText("openCypher")).toBeInTheDocument();
    expect(screen.queryByText("openCypher*")).not.toBeInTheDocument();
    expect(screen.queryByText("Read-only")).not.toBeInTheDocument();
  });

  it("uses the design-system error token for field validation messages", async () => {
    // Given
    render(<TestFormWithError />);

    // When
    const errorMessage = await screen.findByText("Tag key is required");

    // Then
    expect(errorMessage).toHaveClass("text-text-error-primary", "text-xs");
  });

  it("connects field errors to the input for accessibility", async () => {
    // Given
    render(<TestFormWithError />);

    // When
    const input = screen.getByRole("textbox", { name: /tag key/i });
    const errorMessage = await screen.findByText("Tag key is required");

    // Then
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(errorMessage).toHaveAttribute("id");
    expect(input).toHaveAttribute(
      "aria-describedby",
      expect.stringContaining(errorMessage.getAttribute("id") ?? ""),
    );
  });
});
