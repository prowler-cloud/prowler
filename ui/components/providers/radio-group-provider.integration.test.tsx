import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { render } from "@/__tests__/render-browser";
import type { AddProviderFormValues } from "@/types/formSchemas";

import { RadioGroupProvider } from "./radio-group-provider";

function Selector() {
  const form = useForm<AddProviderFormValues>();
  return (
    <RadioGroupProvider
      control={form.control}
      isInvalid={false}
      registryAvailable
      registryOptions={[
        {
          type: "vcf",
          label: "Vcf",
          logoUrl: "https://media.registry.example.com/providers/vcf/logo.png",
        },
      ]}
    />
  );
}

// The logo is the first element of the option's label row.
function logoBox(option: HTMLElement) {
  const logo = option.lastElementChild?.firstElementChild;
  if (!logo) throw new Error("Provider option without a logo");
  const { width, height } = logo.getBoundingClientRect();
  return { width, height };
}

describe("provider selector logos", () => {
  it("draws a Registry provider's logo at the size of the built-in logos", async () => {
    // Given
    const screen = await render(<Selector />);

    // When
    const builtIn = screen
      .getByRole("option", { name: "Amazon Web Services" })
      .element() as HTMLElement;
    const registry = screen
      .getByRole("option", { name: "Vcf Registry" })
      .element() as HTMLElement;

    // Then
    expect(logoBox(registry)).toEqual(logoBox(builtIn));
  });
});
