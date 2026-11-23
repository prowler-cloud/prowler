import { ThreatScoreBadge } from "@/components/compliance";
import { ComplianceCard } from "@/components/compliance/compliance-card";
import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import {
  SAMPLE_COMPLIANCE_OVERVIEWS,
  SAMPLE_SCAN,
} from "@/lib/sample-preview/sample-compliance";
import { SAMPLE_THREAT_SCORE } from "@/lib/sample-preview/sample-overview";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import type { SamplePreviewActive } from "@/lib/sample-preview/sample-preview-state";
import type { ComplianceOverviewData } from "@/types/compliance";

import { ComplianceOverviewPanel } from "./compliance-overview-panel";

interface ComplianceSamplePreviewProps {
  state: SamplePreviewActive;
  /** Totals derived from the same requirements the detail page shows. */
  overviews?: ComplianceOverviewData[];
}

/** Sample per-scan compliance: cards open the sample detail; no reports. */
export function ComplianceSamplePreview({
  state,
  overviews = SAMPLE_COMPLIANCE_OVERVIEWS,
}: ComplianceSamplePreviewProps) {
  return (
    <>
      <SamplePreviewBanner
        state={state}
        page={SAMPLE_PREVIEW_PAGE.COMPLIANCE}
      />
      <div className="mb-6">
        <ThreatScoreBadge
          readOnly
          score={SAMPLE_THREAT_SCORE.score}
          scanId={SAMPLE_SCAN.id}
          provider={SAMPLE_SCAN.providerInfo.provider}
          selectedScan={SAMPLE_SCAN}
          sectionScores={SAMPLE_THREAT_SCORE.sectionScores}
        />
      </div>
      <ComplianceOverviewPanel>
        <ComplianceFrameworkGrid>
          {overviews.map(({ id, attributes }) => (
            <div key={id} className="h-full [&>*]:h-full">
              <ComplianceCard
                hideActions
                title={attributes.framework}
                version={attributes.version}
                passingRequirements={attributes.requirements_passed}
                totalRequirements={attributes.total_requirements}
                prevPassingRequirements={attributes.requirements_passed}
                prevTotalRequirements={attributes.total_requirements}
                scanId={SAMPLE_SCAN.id}
                complianceId={id}
                id={id}
                selectedScan={SAMPLE_SCAN}
              />
            </div>
          ))}
        </ComplianceFrameworkGrid>
      </ComplianceOverviewPanel>
    </>
  );
}
