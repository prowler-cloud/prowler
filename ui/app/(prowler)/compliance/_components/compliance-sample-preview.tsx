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

import { ComplianceOverviewPanel } from "./compliance-overview-panel";

interface ComplianceSamplePreviewProps {
  state: SamplePreviewActive;
}

/** Sample per-scan compliance: the Overview watchlist frameworks, inert. */
export function ComplianceSamplePreview({
  state,
}: ComplianceSamplePreviewProps) {
  return (
    <>
      <SamplePreviewBanner
        state={state}
        page={SAMPLE_PREVIEW_PAGE.COMPLIANCE}
      />
      <div inert>
        <div className="mb-6">
          <ThreatScoreBadge
            score={SAMPLE_THREAT_SCORE.score}
            scanId={SAMPLE_SCAN.id}
            provider={SAMPLE_SCAN.providerInfo.provider}
            selectedScan={SAMPLE_SCAN}
            sectionScores={SAMPLE_THREAT_SCORE.sectionScores}
          />
        </div>
        <ComplianceOverviewPanel>
          <ComplianceFrameworkGrid>
            {SAMPLE_COMPLIANCE_OVERVIEWS.map(({ id, attributes }) => (
              <div key={id} className="h-full [&>*]:h-full">
                <ComplianceCard
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
      </div>
    </>
  );
}
