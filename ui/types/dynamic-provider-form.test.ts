import { describe, expect, it } from "vitest";

import { createAddProviderFormSchema } from "./formSchemas";

describe("provider account validation", () => {
  it("accepts installed dynamic types only and requires a UID", () => {
    const schema = createAddProviderFormSchema(["acme", "aws"]);
    const input = {
      providerType: "acme",
      providerUid: " account ",
      providerAlias: "Test",
    };
    expect(schema.parse(input).providerUid).toBe("account");
    expect(
      schema.safeParse({ ...input, providerType: "unknown" }).success,
    ).toBe(false);
    expect(schema.safeParse({ ...input, providerUid: " " }).success).toBe(
      false,
    );
    expect(
      schema.safeParse({ ...input, providerType: "aws", providerUid: "short" })
        .success,
    ).toBe(false);
    expect(createAddProviderFormSchema([]).safeParse(input).success).toBe(
      false,
    );
  });
});
