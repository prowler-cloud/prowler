import { render, screen } from "@testing-library/react";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import type { AddProviderFormValues } from "@/types/formSchemas";

import { RadioGroupProvider } from "./radio-group-provider";

function Selector() {
  const form = useForm<AddProviderFormValues>();
  return (
    <RadioGroupProvider
      control={form.control}
      isInvalid={false}
      registryOptions={[{ type: "acme", label: "Acme Cloud" }]}
    />
  );
}

describe("provider selector", () => {
  it("adds Registry-labelled providers alongside the incorporated options", () => {
    render(<Selector />);
    expect(
      screen.getByRole("option", { name: /Acme Cloud Registry/ }),
    ).toBeVisible();
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();
  });
});
