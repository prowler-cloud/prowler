import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("events timeline", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "events-timeline.tsx");
  const source = readFileSync(filePath, "utf8");

  it("delegates resource event loading to a dedicated hook instead of using useEffect in the component", () => {
    expect(source).toContain("useResourceEventsTimeline");
    expect(source).not.toContain("getResourceEvents");
    expect(source).not.toContain("useEffect(");
  });
});
