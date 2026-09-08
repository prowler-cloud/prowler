import { beforeEach, describe, expect, it, vi } from "vitest";

const { getInstalledRegistryProviderOptions, addProvider, getProviders } =
  vi.hoisted(() => ({
    getInstalledRegistryProviderOptions: vi.fn(),
    addProvider: vi.fn(),
    getProviders: vi.fn(),
  }));
vi.mock("@/actions/registry/registry", () => ({
  getInstalledRegistryProviderOptions,
}));
vi.mock("./providers", () => ({ addProvider, getProviders }));

import { addRegistryProvider } from "./registry-provider";

const formData = () => {
  const form = new FormData();
  form.set("providerType", "acme");
  form.set("providerUid", "account");
  form.set("providerAlias", "Test");
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
      attributes: { provider: "acme", uid: "account", alias: "Original" },
    };
    getProviders.mockResolvedValue({ data: [existing] });
    expect(await addRegistryProvider(formData())).toEqual({ data: existing });
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
