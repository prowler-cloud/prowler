import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface DORADetailsProps {
  requirement: Requirement;
}

export const DORACustomDetails = ({ requirement }: DORADetailsProps) => {
  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.pillar && (
          <ComplianceBadge
            label="Pillar"
            value={requirement.pillar as string}
            variant="tag"
          />
        )}
        {requirement.article && (
          <ComplianceBadge
            label="Article"
            value={requirement.article as string}
            variant="tag"
          />
        )}
        {requirement.article_title && (
          <ComplianceBadge
            label="Article Title"
            value={requirement.article_title as string}
            variant="tag"
          />
        )}
      </ComplianceBadgeContainer>
    </ComplianceDetailContainer>
  );
};
