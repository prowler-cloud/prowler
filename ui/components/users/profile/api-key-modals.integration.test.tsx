import { describe, expect, vi } from "vitest";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";

import type { EnrichedApiKey } from "./api-keys/types";
import { CreateApiKeyModal } from "./create-api-key-modal";
import { EditApiKeyNameModal } from "./edit-api-key-name-modal";

const apiKey: EnrichedApiKey = {
  type: "api-keys",
  id: "api-key-1",
  attributes: {
    name: "CI pipeline",
    prefix: "pk_12345678",
    expires_at: "2099-01-01T00:00:00Z",
    revoked: false,
    inserted_at: "2026-01-01T00:00:00Z",
    last_used_at: null,
  },
  relationships: {
    entity: { data: { type: "users", id: "user-1" } },
  },
  userEmail: "user@example.com",
};

// The app runs under React Compiler; only this suite compiles like it does.
describe("API key modals under React Compiler", () => {
  it("enables Create API Key once a name is typed", async () => {
    // Given
    const screen = await render(
      <CreateApiKeyModal isOpen onClose={vi.fn()} onSuccess={vi.fn()} />,
    );
    const submit = screen.getByRole("button", { name: "Create API Key" });
    await expect.element(submit).toBeDisabled();

    // When
    await screen.getByPlaceholder("My API Key").fill("CI pipeline");

    // Then
    await expect.element(submit).toBeEnabled();
  });

  it("enables Save Changes once the name changes", async () => {
    // Given
    const screen = await render(
      <EditApiKeyNameModal
        isOpen
        onClose={vi.fn()}
        onSuccess={vi.fn()}
        apiKey={apiKey}
        existingApiKeys={[apiKey]}
      />,
    );
    const submit = screen.getByRole("button", { name: "Save Changes" });

    // When
    await screen.getByPlaceholder("My API Key").fill("Nightly export");

    // Then
    await expect.element(submit).toBeEnabled();
  });
});
