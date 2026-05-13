import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

describe("mock service worker message hardening", () => {
  it("rejects messages from unexpected origins before handling client messages", () => {
    const workerSource = readFileSync(
      join(process.cwd(), "public/mockServiceWorker.js"),
      "utf8",
    );

    expect(workerSource).toContain("event.origin !== self.location.origin");
    expect(
      workerSource.indexOf("event.origin !== self.location.origin"),
    ).toBeLessThan(workerSource.indexOf("const clientId = Reflect.get"));
  });
});
