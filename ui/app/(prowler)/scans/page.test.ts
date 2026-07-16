import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("scans page onboarding", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("never blocks or redirects away from Scans when providers are missing or disconnected", () => {
    // Imported scans belong to a never-connected provider, so the page must render the
    // table regardless of provider connection status instead of gating/redirecting.
    expect(source).not.toContain(
      'redirect("/providers?onboarding=add-provider")',
    );
    expect(source).not.toContain("missingScanPrerequisite");
  });

  it("always renders the scans table shell", () => {
    expect(source).toContain("<ScansPageShell");
    expect(source).toContain("<SSRDataTableScans");
  });

  it("passes the scan onboarding action to the page header when the tour can run", () => {
    expect(source).toContain('flowId: "view-first-scan"');
    expect(source).toContain("onboardingAction={onboardingAction}");
  });
});

describe("scans page scheduled tab source", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(pagePath, "utf8");

  it("sources the Scheduled tab from /schedules only for the advanced capability", () => {
    expect(source).toContain("getSchedulesPage");
    expect(source).toContain("SCAN_SCHEDULE_CAPABILITY.ADVANCED");
    expect(source).toContain("tab === SCAN_JOBS_TAB.SCHEDULED");
  });

  it("maps schedule resources to rows and delegates pagination to the endpoint", () => {
    expect(source).toContain("buildScheduledTabRows");
    expect(source).toContain("pickScheduleProviderFilters");
  });
});
