import { describe, expect, it } from "vitest";

import { getRegistryCredentialFailureMessage } from "./credential-task";

describe("Registry credential rejection feedback", () => {
  it("explains a wrong-environment key without reflecting server data", () => {
    const message = getRegistryCredentialFailureMessage({
      stored: false,
      error: "Registry rejected the API key (HTTP 401). sensitive-input",
    });
    expect(message).toContain("Registry environment");
    expect(message).toContain("HTTP 401");
    expect(message).not.toContain("sensitive-input");
  });
  it("does not expose arbitrary backend errors", () => {
    expect(
      getRegistryCredentialFailureMessage({ error: "sensitive-input" }),
    ).toBeUndefined();
  });
});
