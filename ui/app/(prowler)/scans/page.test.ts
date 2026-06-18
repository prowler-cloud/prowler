import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("scans page onboarding", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("redirects the scan tour replay to add-provider when providers are missing or disconnected", () => {
    expect(source).toContain('redirect("/providers?onboarding=add-provider")');
    expect(source).toContain(
      'resolvedSearchParams.onboarding === "view-first-scan"',
    );
  });

  it("passes the scan onboarding action to the page header when the tour can run", () => {
    expect(source).toContain('flowId: "view-first-scan"');
    expect(source).toContain("onboardingAction={onboardingAction}");
  });
});
