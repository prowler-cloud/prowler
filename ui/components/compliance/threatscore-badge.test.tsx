import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("ThreatScoreBadge", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "threatscore-badge.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses shadcn card and progress components instead of Hero UI", () => {
    expect(source).toContain('from "@/components/shadcn/card/card"');
    expect(source).toContain('from "@/components/shadcn/progress"');
    expect(source).not.toContain("@heroui/card");
    expect(source).not.toContain("@heroui/progress");
  });

  it("uses ActionDropdown for downloads instead of ComplianceDownloadContainer", () => {
    expect(source).toContain("ActionDropdown");
    expect(source).toContain("ActionDropdownItem");
    expect(source).toContain("downloadComplianceCsv");
    expect(source).toContain("downloadComplianceReportPdf");
    expect(source).not.toContain("ComplianceDownloadContainer");
  });

  it("does not use Collapsible components", () => {
    expect(source).not.toContain("Collapsible");
    expect(source).not.toContain("CollapsibleTrigger");
    expect(source).not.toContain("CollapsibleContent");
  });
});
