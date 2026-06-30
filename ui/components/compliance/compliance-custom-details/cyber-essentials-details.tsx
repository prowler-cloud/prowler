import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface CyberEssentialsDetailsProps {
  requirement: Requirement;
}

export const CyberEssentialsCustomDetails = ({
  requirement,
}: CyberEssentialsDetailsProps) => {
  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.theme && (
          <ComplianceBadge
            label="Theme"
            value={requirement.theme as string}
            variant="tag"
          />
        )}
        {requirement.assessment_status && (
          <ComplianceBadge
            label="Assessment Status"
            value={requirement.assessment_status as string}
            variant="info"
          />
        )}
        {requirement.cloud_applicability && (
          <ComplianceBadge
            label="Cloud Applicability"
            value={requirement.cloud_applicability as string}
            variant="secondary"
          />
        )}
      </ComplianceBadgeContainer>

      {requirement.remediation_procedure && (
        <ComplianceDetailSection title="Remediation Procedure">
          <ComplianceDetailText>
            {requirement.remediation_procedure as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.references && (
        <ComplianceDetailSection title="References">
          <ComplianceDetailText>
            {requirement.references as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
