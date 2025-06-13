import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

export const ThreatCustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.attributeDescription && (
        <ComplianceDetailSection title="Attribute Description">
          <ComplianceDetailText>
            {requirement.attributeDescription as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {typeof requirement.levelOfRisk === "number" && (
          <ComplianceBadge
            label="Risk Level"
            value={requirement.levelOfRisk}
            color="red"
          />
        )}

        {typeof requirement.weight === "number" && (
          <ComplianceBadge
            label="Weight"
            value={requirement.weight}
            color="green"
          />
        )}

        {typeof requirement.score === "number" && (
          <ComplianceBadge
            label="Score"
            value={requirement.score}
            color="green"
            conditional={true}
          />
        )}
      </ComplianceBadgeContainer>

      {requirement.additionalInformation && (
        <ComplianceDetailSection title="Additional Information">
          <ComplianceDetailText>
            {requirement.additionalInformation as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
