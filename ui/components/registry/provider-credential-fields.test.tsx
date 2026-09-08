import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { RegistryCredentialSchema } from "@/lib/registry/provider-credential-schema";

import { RegistryCredentialFields } from "./provider-credential-fields";

const schema: RegistryCredentialSchema = {
  fields: [
    {
      name: "api_key",
      label: "API Key",
      description: "Issued from the console.",
      kind: "password",
      required: true,
    },
    {
      name: "scheme",
      label: "Scheme",
      kind: "select",
      options: ["bearer", "basic"],
      required: false,
    },
    { name: "notes", label: "Notes", kind: "textarea", required: false },
  ],
};

beforeAll(() => {
  for (const name of [
    "hasPointerCapture",
    "releasePointerCapture",
    "scrollIntoView",
  ]) {
    Object.defineProperty(HTMLElement.prototype, name, {
      configurable: true,
      value: () => false,
    });
  }
});

describe("RegistryCredentialFields", () => {
  it("renders accessible controlled credential fields and emits changes", async () => {
    // Given
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <RegistryCredentialFields
        errors={{ api_key: "A key is required." }}
        onChange={onChange}
        schema={schema}
        values={{ api_key: "", scheme: "bearer", notes: "" }}
      />,
    );

    // When
    await user.type(screen.getByLabelText(/API Key/), "x");
    await user.click(screen.getByRole("combobox", { name: "Scheme" }));
    await user.keyboard("{ArrowDown}{Enter}");

    // Then
    const apiKey = screen.getByLabelText(/API Key/);
    const description = screen.getByText("Issued from the console.");
    const error = screen.getByRole("alert");
    expect(apiKey).toHaveAttribute("type", "password");
    expect(apiKey).toHaveAttribute("autocomplete", "new-password");

    expect(apiKey).toHaveAttribute(
      "aria-describedby",
      `${description.id} ${error.id}`,
    );
    expect(apiKey.id).toMatch(/-0-control$/);
    expect(apiKey).toHaveAttribute("aria-invalid", "true");
    expect(apiKey).toBeRequired();
    expect(description.id).toMatch(/-0-description$/);
    expect(error).toHaveTextContent("A key is required.");
    expect(error.id).toMatch(/-0-error$/);
    expect(onChange).toHaveBeenCalledWith("api_key", "x");
    expect(onChange).toHaveBeenCalledWith("scheme", "basic");
  });

  it("uses unique index-based IDs for hostile field names and instances", () => {
    // Given

    const hostileSchema: RegistryCredentialSchema = {
      fields: [
        {
          name: "x-description",
          label: "First",
          kind: "text",
          required: false,
        },
        {
          name: "registry-credential-x",
          label: "Second",
          description: "Second description.",
          kind: "text",
          required: false,
        },
      ],
    };

    const { container } = render(
      <>
        <RegistryCredentialFields
          errors={{}}
          onChange={vi.fn()}
          schema={hostileSchema}
          values={{}}
        />
        <RegistryCredentialFields
          errors={{}}
          onChange={vi.fn()}
          schema={schema}
          values={{}}
        />
        <RegistryCredentialFields
          errors={{}}
          onChange={vi.fn()}
          schema={schema}
          values={{}}
        />
      </>,
    );

    // When / Then
    expect(screen.getByLabelText("First").id).toMatch(/-0-control$/);

    expect(screen.getByText("Second description.").id).toMatch(
      /-1-description$/,
    );
    const ids = Array.from(container.querySelectorAll("[id]"), ({ id }) => id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
