import { describe, expect, it } from "vitest";

import { getRegistryNotInstallableMessage } from "./installability";

describe("getRegistryNotInstallableMessage", () => {
  it("tells the tenant how to get an artifact that needs approved access", () => {
    expect(getRegistryNotInstallableMessage("access_required")).toBe(
      "Needs approved access in the Prowler Registry. Once approved, it installs with that account's Registry API key.",
    );
  });

  it("says an artifact needing a newer Prowler waits for an upgrade", () => {
    expect(getRegistryNotInstallableMessage("prowler_upgrade_required")).toBe(
      "It needs a newer Prowler version than this deployment runs. It will install once the deployment is upgraded.",
    );
  });

  it("says a dependency needs access the Registry key does not have", () => {
    expect(getRegistryNotInstallableMessage("dependency_access_required")).toBe(
      "It depends on another Prowler Registry artifact that your Registry API key cannot install.",
    );
  });

  it("uses the caller's fallback for a code it does not know", () => {
    expect(
      getRegistryNotInstallableMessage("artifact_yanked", "Could not install."),
    ).toBe("Could not install.");
  });

  it("falls back for a code it does not know", () => {
    expect(getRegistryNotInstallableMessage("artifact_yanked")).toBe(
      "This artifact cannot be installed in this deployment.",
    );
  });
});
