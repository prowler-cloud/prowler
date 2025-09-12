import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

export const GenericCustomDetails = ({
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

      <ComplianceBadgeContainer>
        {requirement.item_id && (
          <ComplianceBadge
            label="Item ID"
            value={requirement.item_id as string}
            color="indigo"
          />
        )}

        {requirement.service && (
          <ComplianceBadge
            label="Service"
            value={requirement.service as string}
            color="blue"
          />
        )}

        {requirement.type && (
          <ComplianceBadge
            label="Type"
            value={requirement.type as string}
            color="orange"
          />
        )}
      </ComplianceBadgeContainer>

      {requirement.subsection && (
        <ComplianceDetailSection title="SubSection">
          <ComplianceDetailText>
            {requirement.subsection as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.subgroup && (
        <ComplianceDetailSection title="SubGroup">
          <ComplianceDetailText>
            {requirement.subgroup as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
