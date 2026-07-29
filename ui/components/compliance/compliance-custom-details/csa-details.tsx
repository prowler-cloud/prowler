import { Badge } from "@/components/shadcn/badge/badge";
import { CSA_MAPPING_SECTIONS } from "@/lib/compliance/csa";
import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface CSADetailsProps {
  requirement: Requirement;
}

export const CSACustomDetails = ({ requirement }: CSADetailsProps) => {
  const mappingSections = CSA_MAPPING_SECTIONS.map((section) => ({
    ...section,
    data: requirement[section.key] as Array<{
      ReferenceId: string;
      Identifiers: string[];
    }>,
  })).filter((section) => section.data && section.data.length > 0);

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.ccm_lite && (
          <ComplianceBadge
            label="CCM Lite"
            value={requirement.ccm_lite as string}
            variant={requirement.ccm_lite === "Yes" ? "success" : "secondary"}
          />
        )}
        {requirement.iaas && (
          <ComplianceBadge
            label="IaaS"
            value={requirement.iaas as string}
            variant="info"
          />
        )}
        {requirement.paas && (
          <ComplianceBadge
            label="PaaS"
            value={requirement.paas as string}
            variant="info"
          />
        )}
        {requirement.saas && (
          <ComplianceBadge
            label="SaaS"
            value={requirement.saas as string}
            variant="info"
          />
        )}
      </ComplianceBadgeContainer>

      {mappingSections.map((section) => (
        <ComplianceDetailSection key={section.title} title={section.title}>
          <div className="flex flex-col gap-3">
            {section.data.map((mapping, index) => (
              <div key={index} className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs font-medium">
                  {mapping.ReferenceId}
                </span>
                <div className="flex flex-wrap gap-2">
                  {mapping.Identifiers.map((identifier, idx) => (
                    <Badge key={idx} variant={section.variant}>
                      {identifier}
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </ComplianceDetailSection>
      ))}
    </ComplianceDetailContainer>
  );
};
