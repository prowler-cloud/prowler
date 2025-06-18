import { Requirement } from "@/types/compliance";

import {
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

export const ISOCustomDetails = ({
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

      {requirement.objetive_name && (
        <ComplianceDetailSection title="Objective">
          <ComplianceDetailText>
            {requirement.objetive_name as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
