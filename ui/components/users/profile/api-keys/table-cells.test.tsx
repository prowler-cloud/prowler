import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { DateCell, NameCell } from "./table-cells";
import type { EnrichedApiKey } from "./types";

const apiKey: EnrichedApiKey = {
  type: "api-keys",
  id: "api-key-1",
  attributes: {
    name: "Production access key with a very long human readable name",
    prefix: "pk_12345678",
    expires_at: "2099-01-01T00:00:00Z",
    revoked: false,
    inserted_at: "2026-01-01T00:00:00Z",
    last_used_at: null,
  },
  relationships: {
    entity: {
      data: {
        type: "users",
        id: "user-1",
      },
    },
  },
  userEmail: "user@example.com",
};

describe("NameCell", () => {
  it("keeps long API key names on one line with a tooltip", async () => {
    // Given - A long API key name
    const user = userEvent.setup();

    render(<NameCell apiKey={apiKey} />);

    // When - Reading and hovering the displayed name
    const name = screen.getByText(apiKey.attributes.name!);
    await user.hover(name);

    // Then - The cell has a fixed width, truncates, and exposes the full name
    expect(name).toHaveClass("w-64", "truncate", "whitespace-nowrap");
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      apiKey.attributes.name!,
    );
  });
});

describe("DateCell", () => {
  it("keeps API key dates on one line", () => {
    // Given - A rendered API key date
    render(<DateCell date={null} />);

    // When - Reading the date cell
    const date = screen.getByText("Never");

    // Then - The table date cannot wrap to a second line
    expect(date).toHaveClass("whitespace-nowrap");
  });
});
