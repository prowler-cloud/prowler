import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("profile page layout", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("uses one large card with profile sections stacked vertically", () => {
    expect(source).toContain('aria-label="User profile settings"');
    expect(source).toContain('className="w-full gap-4 p-4 md:p-5"');
    expect(source).not.toContain("xl:grid-cols");
    expect(source).not.toContain('className="flex w-full flex-col gap-6"');

    const sectionOrder = [
      "<UserBasicInfoCard",
      "<RolesCard",
      "<SamlIntegrationCard",
      "<MembershipsCard",
      "<ApiKeysCard",
    ];

    const sectionIndexes = sectionOrder.map((section) =>
      source.indexOf(section),
    );

    expect(sectionIndexes).not.toContain(-1);
    expect(sectionIndexes).toEqual([...sectionIndexes].sort((a, b) => a - b));
  });
});
