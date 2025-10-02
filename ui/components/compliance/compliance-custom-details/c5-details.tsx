import { Requirement } from "@/types/compliance";

import {
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

export const C5CustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  const aboutCriteria = requirement.about_criteria as string | undefined;
  const complementaryCriteria = requirement.complementary_criteria as
    | string
    | undefined;

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {aboutCriteria && (
        <ComplianceDetailSection title="About Criteria">
          <ComplianceDetailText>{aboutCriteria}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {complementaryCriteria && (
        <ComplianceDetailSection title="Complementary Criteria">
          <ComplianceDetailText>{complementaryCriteria}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
