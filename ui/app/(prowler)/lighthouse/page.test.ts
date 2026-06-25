import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Lighthouse page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("keys the Cloud chat by the active route conversation", () => {
    // Given / When / Then
    expect(source).toContain(
      'const chatRouteKey = activeSessionId ?? initialPrompt ?? "new";',
    );
    expect(source).toContain("key={chatRouteKey}");
  });
});
