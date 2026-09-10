import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import type { RegistryProviderOption } from "@/lib/registry/provider-options";
import type { AddProviderFormValues } from "@/types/formSchemas";

import { RadioGroupProvider } from "./radio-group-provider";

function Selector({
  registryOptions = [{ type: "acme", label: "Acme Cloud" }],
}: {
  registryOptions?: RegistryProviderOption[];
}) {
  const form = useForm<AddProviderFormValues>();
  return (
    <RadioGroupProvider
      control={form.control}
      isInvalid={false}
      registryOptions={registryOptions}
    />
  );
}

describe("provider selector", () => {
  it("preserves selected provider across tabs and supports searching by type", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <Selector
        registryOptions={[{ type: "acme_slug", label: "Acme Cloud" }]}
      />,
    );
    expect(screen.getByRole("tab", { name: "All" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await user.click(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    );

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));
    await user.type(
      screen.getByRole("textbox", { name: "Search providers" }),
      " ACME_SLUG ",
    );

    // Then
    expect(
      screen.getByRole("option", { name: /Acme Cloud Registry/ }),
    ).toBeVisible();

    // When
    await user.click(screen.getByRole("button", { name: "Clear search" }));
    await user.click(screen.getByRole("tab", { name: "All" }));

    // Then
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toHaveAttribute("aria-selected", "true");
  });

  it("keeps both tabs available when no Registry providers are installed", async () => {
    // Given
    const user = userEvent.setup();
    const { rerender } = render(<Selector registryOptions={[]} />);

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));

    // Then
    expect(screen.getByText("No Registry providers available.")).toBeVisible();
    expect(screen.getByRole("tab", { name: "All" })).toBeEnabled();

    // When / Then: discovery can refresh the installed options.
    rerender(<Selector />);
    expect(
      screen.getByRole("option", { name: /Acme Cloud Registry/ }),
    ).toBeVisible();
    rerender(<Selector registryOptions={[]} />);
    expect(screen.queryByRole("option")).not.toBeInTheDocument();
    expect(screen.getByText("No Registry providers available.")).toBeVisible();
  });

  it("filters Registry providers and preserves search across tabs", async () => {
    // Given
    const user = userEvent.setup();
    render(<Selector />);

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));

    // Then
    expect(
      screen.getByRole("option", { name: /Acme Cloud Registry/ }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", { name: /Amazon Web Services/ }),
    ).not.toBeInTheDocument();

    // When
    await user.type(
      screen.getByRole("textbox", { name: "Search providers" }),
      "amazon",
    );
    expect(
      screen.getByText('No providers found matching "amazon"'),
    ).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "All" }));

    // Then
    expect(
      screen.getByRole("textbox", { name: "Search providers" }),
    ).toHaveValue("amazon");
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", { name: /Acme Cloud Registry/ }),
    ).not.toBeInTheDocument();
  });

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
