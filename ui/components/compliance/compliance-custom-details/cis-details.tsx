import ReactMarkdown from "react-markdown";

import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
  ComplianceLink,
} from "./shared-components";

interface CISDetailsProps {
  requirement: Requirement;
}

export const CISCustomDetails = ({ requirement }: CISDetailsProps) => {
  const processReferences = (
    references: string | number | string[] | object[] | undefined,
  ): string[] => {
    if (typeof references !== "string") return [];

    // Use regex to extract all URLs that start with https://
    const urlRegex = /https:\/\/[^:]+/g;
    const urls = references.match(urlRegex);

    return urls || [];
  };

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.profile && (
          <ComplianceBadge
            label="Profile"
            value={requirement.profile as string}
            color="purple"
          />
        )}

        {requirement.assessment_status && (
          <ComplianceBadge
            label="Assessment"
            value={requirement.assessment_status as string}
            color="blue"
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

      {requirement.rationale_statement && (
        <ComplianceDetailSection title="Rationale Statement">
          <ComplianceDetailText>
            {requirement.rationale_statement as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.impact_statement && (
        <ComplianceDetailSection title="Impact Statement">
          <ComplianceDetailText>
            {requirement.impact_statement as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.remediation_procedure &&
        typeof requirement.remediation_procedure === "string" && (
          <ComplianceDetailSection title="Remediation Procedure">
            {/* Prettier -> "plugins": ["prettier-plugin-tailwindcss"] is not ready yet to "prose": */}
            {/* eslint-disable-next-line */}
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <ReactMarkdown>{requirement.remediation_procedure}</ReactMarkdown>
            </div>
          </ComplianceDetailSection>
        )}

      {requirement.audit_procedure &&
        typeof requirement.audit_procedure === "string" && (
          <ComplianceDetailSection title="Audit Procedure">
            {/* eslint-disable-next-line */}
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <ReactMarkdown>{requirement.audit_procedure}</ReactMarkdown>
            </div>
          </ComplianceDetailSection>
        )}

      {requirement.additional_information && (
        <ComplianceDetailSection title="Additional Information">
          <ComplianceDetailText className="whitespace-pre-wrap">
            {requirement.additional_information as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.default_value && (
        <ComplianceDetailSection title="Default Value">
          <ComplianceDetailText>
            {requirement.default_value as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.references && (
        <ComplianceDetailSection title="References">
          <div className="space-y-1">
            {processReferences(requirement.references).map(
              (url: string, index: number) => (
                <div key={index}>
                  <ComplianceLink href={url}>{url}</ComplianceLink>
                </div>
              ),
            )}
          </div>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
