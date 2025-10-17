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
  const sections = [
    {
      title: "Description",
      content: requirement.description,
    },
    {
      title: "About Criteria",
      content: requirement.about_criteria as string | undefined,
    },
    {
      title: "Complementary Criteria",
      content: requirement.complementary_criteria as string | undefined,
    },
  ].filter((section) => section.content);

  return (
    <ComplianceDetailContainer>
      {sections.map((section) => (
        <ComplianceDetailSection key={section.title} title={section.title}>
          <ComplianceDetailText>{section.content}</ComplianceDetailText>
        </ComplianceDetailSection>
      ))}
    </ComplianceDetailContainer>
  );
};
