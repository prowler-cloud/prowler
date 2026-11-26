import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  getInstalledRegistryProviderOptions,
  addProvider,
  getProviders,
  updateProvider,
} = vi.hoisted(() => ({
  getInstalledRegistryProviderOptions: vi.fn(),
  addProvider: vi.fn(),
  getProviders: vi.fn(),
  updateProvider: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  getInstalledRegistryProviderOptions,
}));
vi.mock("./providers", () => ({ addProvider, getProviders, updateProvider }));

import { addRegistryProvider } from "./registry-provider";

const formData = (alias = "Test") => {
  const form = new FormData();
  form.set("providerType", "acme");
  form.set("providerUid", "account");
  form.set("providerAlias", alias);
  return form;
};
describe("Registry provider account creation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "ready",
      options: [{ type: "acme", label: "Acme" }],
    });
    getProviders.mockResolvedValue({ data: [] });
  });
  it("refuses removed artifacts and revoked permission before creating an account", async () => {
    getInstalledRegistryProviderOptions
      .mockResolvedValueOnce({ status: "access_denied" })
      .mockResolvedValueOnce({ status: "ready", options: [] });
    expect((await addRegistryProvider(formData()))?.errors).toBeDefined();
    expect((await addRegistryProvider(formData()))?.errors).toBeDefined();
    expect(addProvider).not.toHaveBeenCalled();
  });
  it("reuses a previously created account after a failed credential attempt or lost response", async () => {
    const existing = {
      id: "existing",
      attributes: { provider: "acme", uid: "account", alias: "Test" },
    };
    getProviders.mockResolvedValue({ data: [existing] });
    expect(await addRegistryProvider(formData())).toEqual({ data: existing });
    expect(addProvider).not.toHaveBeenCalled();
    expect(updateProvider).not.toHaveBeenCalled();
  });
  it.each(["Test", "", " Edited "])(
    "saves alias %j before resuming credentials for an existing account",
    async (alias) => {
      // Given
      const existing = {
        id: "existing",
        attributes: { provider: "acme", uid: "account", alias: "Original" },
      };
      const updated = {
        ...existing,
        attributes: { ...existing.attributes, alias: alias.trim() },
      };
      getProviders.mockResolvedValue({ data: [existing] });
      updateProvider.mockResolvedValue({ data: updated });

      // When
      const result = await addRegistryProvider(formData(alias));

      // Then
      expect(result).toEqual({ data: updated });
      expect(Object.fromEntries(updateProvider.mock.calls[0][0])).toEqual({
        providerId: "existing",
        providerAlias: alias.trim(),
      });
      expect(addProvider).not.toHaveBeenCalled();
    },
  );
  it("keeps alias update failures visible instead of resuming with stale details", async () => {
    // Given
    const failure = {
      errors: [
        {
          detail: "Alias is invalid",
          source: { pointer: "/data/attributes/alias" },
        },
      ],
    };
    getProviders.mockResolvedValue({
      data: [
        {
          id: "existing",
          attributes: { provider: "acme", uid: "account", alias: "Original" },
        },
      ],
    });
    updateProvider.mockResolvedValue(failure);

    // When / Then
    await expect(addRegistryProvider(formData())).resolves.toEqual(failure);
    expect(addProvider).not.toHaveBeenCalled();
  });
  it("creates a validated installed provider account", async () => {
    addProvider.mockResolvedValue({ data: { id: "new" } });
    expect(await addRegistryProvider(formData())).toEqual({
      data: { id: "new" },
    });
    expect(addProvider).toHaveBeenCalledOnce();
  });
});
