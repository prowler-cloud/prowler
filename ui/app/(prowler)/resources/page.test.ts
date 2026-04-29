import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("resources page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const tablePath = path.join(
    currentDir,
    "../../../components/resources/table/resources-table-with-selection.tsx",
  );

  const pageSource = readFileSync(pagePath, "utf8");
  const tableSource = readFileSync(tablePath, "utf8");

  it("fetches the deep-linked resource on the server in parallel with the rest of the page data", () => {
    expect(pageSource).toContain("getResourceById(initialResourceId");
    expect(pageSource).toContain("await Promise.all");
    expect(pageSource).toContain("initialResource={processedResource}");
  });

  it("keeps the client table free of deep-link fetch effects", () => {
    expect(tableSource).not.toContain("useEffect");
    expect(tableSource).not.toContain("useRef");
    expect(tableSource).not.toContain("getResourceById");
    expect(tableSource).not.toContain("initialResourceId");
    expect(tableSource).toContain("initialResource?: ResourceProps | null");
  });
});
