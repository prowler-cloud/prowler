import { translateType } from "@/lib/compliance/ens";
import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceChipContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

export const ENSCustomDetails = ({
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
        {requirement.type && (
          <ComplianceBadge
            label="Type"
            value={translateType(requirement.type as string)}
            color="orange"
          />
        )}

        {requirement.nivel && (
          <ComplianceBadge
            label="Level"
            value={requirement.nivel as string}
            color="red"
          />
        )}
      </ComplianceBadgeContainer>

      <ComplianceChipContainer
        title="Dimensions"
        items={(requirement.dimensiones as string[]) || []}
      />
    </ComplianceDetailContainer>
  );
};
