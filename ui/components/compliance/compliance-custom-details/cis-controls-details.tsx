import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface CISControlsDetailsProps {
  requirement: Requirement;
}

export const CISControlsCustomDetails = ({
  requirement,
}: CISControlsDetailsProps) => {
  const implementationGroups = Array.isArray(requirement.implementation_groups)
    ? (requirement.implementation_groups as string[])
    : [];

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.function && (
          <ComplianceBadge
            label="Security Function"
            value={requirement.function as string}
            variant="info"
          />
        )}
        {requirement.asset_type && (
          <ComplianceBadge
            label="Asset Type"
            value={requirement.asset_type as string}
            variant="secondary"
          />
        )}
        {implementationGroups.map((group) => (
          <ComplianceBadge
            key={group}
            label="Implementation Group"
            value={group}
            variant="tag"
          />
        ))}
      </ComplianceBadgeContainer>
    </ComplianceDetailContainer>
  );
};
