import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("resource detail content", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "resource-detail-content.tsx");
  const source = readFileSync(filePath, "utf8");

  it("renders the new finding detail drawer flow instead of the legacy finding detail component", () => {
    expect(source).toContain("FindingDetailDrawer");
    expect(source).not.toContain("FindingDetail findingDetails");
  });

  it("loads the drawer bootstrap data through a single shared resource action", () => {
    expect(source).toContain("useResourceDrawerBootstrap");
    expect(source).not.toContain("getResourceDrawerData");
    expect(source).not.toContain("listOrganizationsSafe");
    expect(source).not.toContain("getResourceById");
    expect(source).not.toContain("getLatestFindings");
  });

  it("does not import useEffect directly and relies on hooks/keyed remounts instead", () => {
    expect(source).not.toContain("useEffect");
    expect(source).not.toContain("useEffect(");
  });

  it("renders the external resource link below the resource title row", () => {
    expect(source).toContain(`</div>
          <ExternalResourceLink`);
    expect(source).toContain(`className="self-start justify-start"`);
  });

  it("keeps resource date fields together on the third details row", () => {
    expect(source).toContain(
      `className="grid min-w-0 grid-cols-2 gap-4 md:grid-cols-4 md:gap-x-8 md:gap-y-4"`,
    );
    expect(source).toContain(`className="col-span-2 md:col-span-1"`);
    expect(source).toContain(`label="Created At"
            variant="compact"
            className="col-start-1 min-w-0"`);
    expect(source).toContain(`label="Last Updated"
            variant="compact"
            className="col-start-2 min-w-0"`);
  });
});
