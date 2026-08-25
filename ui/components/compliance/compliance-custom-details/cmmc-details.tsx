import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface CMMCDetailsProps {
  requirement: Requirement;
}

export const CMMCCustomDetails = ({ requirement }: CMMCDetailsProps) => {
  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.domain && (
          <ComplianceBadge
            label="Domain"
            value={requirement.domain as string}
            variant="tag"
          />
        )}
        {requirement.level && (
          <ComplianceBadge
            label="Level"
            value={requirement.level as string}
            variant="tag"
          />
        )}
        {requirement.source_requirement && (
          <ComplianceBadge
            label="Source Requirement"
            value={requirement.source_requirement as string}
            variant="tag"
          />
        )}
      </ComplianceBadgeContainer>
    </ComplianceDetailContainer>
  );
};
