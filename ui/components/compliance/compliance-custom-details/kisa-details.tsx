import { Requirement } from "@/types/compliance";

import {
  ComplianceBulletList,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

export const KISACustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  const auditChecklist = requirement.audit_checklist as string[] | undefined;
  const relatedRegulations = requirement.related_regulations as
    | string[]
    | undefined;
  const auditEvidence = requirement.audit_evidence as string[] | undefined;
  const nonComplianceCases = requirement.non_compliance_cases as
    | string[]
    | undefined;

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBulletList
        title="Audit Checklist"
        items={auditChecklist || []}
      />

      <ComplianceBulletList
        title="Related Regulations"
        items={relatedRegulations || []}
      />

      <ComplianceBulletList
        title="Audit Evidence"
        items={auditEvidence || []}
      />

      <ComplianceBulletList
        title="Non-Compliance Cases"
        items={nonComplianceCases || []}
      />
    </ComplianceDetailContainer>
  );
};
