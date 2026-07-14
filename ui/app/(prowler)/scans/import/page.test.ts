import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("CLI Import guide page", () => {
  it("is Cloud-only and documents the push-to-cloud workflow", () => {
    // Given
    const currentDir = path.dirname(fileURLToPath(import.meta.url));

    // When
    const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

    // Then
    expect(source).toContain("if (!isCloud())");
    expect(source).toContain('redirect("/")');
    expect(source).toContain("PROWLER_CLOUD_API_KEY");
    expect(source).toContain("prowler aws --push-to-cloud");
  });
});
