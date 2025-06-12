import { SeverityBadge } from "@/components/ui/table";
import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
  ComplianceLink,
} from "./shared-components";

export const AWSWellArchitectedCustomDetails = ({
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

      {requirement.well_architected_name && (
        <ComplianceDetailSection title="Best Practice">
          <ComplianceDetailText>
            {requirement.well_architected_name as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.level_of_risk && (
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-sm font-medium">
              Risk Level:
            </span>
            <SeverityBadge
              severity={
                requirement.level_of_risk.toString().toLowerCase() as
                  | "low"
                  | "medium"
                  | "high"
              }
            />
          </div>
        )}

        {requirement.well_architected_question_id && (
          <ComplianceBadge
            label="Question ID"
            value={requirement.well_architected_question_id as string}
            color="indigo"
          />
        )}

        {requirement.well_architected_practice_id && (
          <ComplianceBadge
            label="Practice ID"
            value={requirement.well_architected_practice_id as string}
            color="indigo"
          />
        )}

        {requirement.assessment_method && (
          <ComplianceBadge
            label="Assessment"
            value={requirement.assessment_method as string}
            color="blue"
          />
        )}
      </ComplianceBadgeContainer>

      {requirement.implementation_guidance_url && (
        <ComplianceDetailSection title="Implementation Guidance">
          <ComplianceLink
            href={requirement.implementation_guidance_url as string}
          >
            {requirement.implementation_guidance_url as string}
          </ComplianceLink>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
