import ReactMarkdown from "react-markdown";

import { CustomLink } from "@/components/ui/custom/custom-link";
import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceChipContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface ASDEssentialEightDetailsProps {
  requirement: Requirement;
}

export const ASDEssentialEightCustomDetails = ({
  requirement,
}: ASDEssentialEightDetailsProps) => {
  const processReferences = (
    references: string | number | boolean | string[] | object[] | undefined,
  ): string[] => {
    if (typeof references !== "string") return [];

    // Each requirement's References field is a single URL or a comma/space
    // separated list of https URLs — match every https URL up to the next
    // separator.
    const urlRegex = /https:\/\/[^\s,]+/g;
    return references.match(urlRegex) || [];
  };

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.aws_description && (
        <ComplianceDetailSection title="AWS Implementation Notes">
          <ComplianceDetailText>
            {requirement.aws_description as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.maturity_level && (
          <ComplianceBadge
            label="Maturity Level"
            value={requirement.maturity_level as string}
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

        {requirement.cloud_applicability && (
          <ComplianceBadge
            label="Cloud Applicability"
            value={requirement.cloud_applicability as string}
            color="orange"
          />
        )}
      </ComplianceBadgeContainer>

      {/* `Array.isArray` narrows the index-signature union; `ComplianceChipContainer` itself returns null on empty arrays, so no length check needed here. */}
      {Array.isArray(requirement.mitigated_threats) && (
        <ComplianceChipContainer
          title="Mitigated Threats"
          items={requirement.mitigated_threats as string[]}
        />
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
            <div className="prose prose-sm dark:prose-invert max-w-none">
              <ReactMarkdown>{requirement.remediation_procedure}</ReactMarkdown>
            </div>
          </ComplianceDetailSection>
        )}

      {requirement.audit_procedure &&
        typeof requirement.audit_procedure === "string" && (
          <ComplianceDetailSection title="Audit Procedure">
            <div className="prose prose-sm dark:prose-invert max-w-none">
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

      {requirement.references && (
        <ComplianceDetailSection title="References">
          <div className="flex flex-col gap-1">
            {processReferences(requirement.references).map((url: string) => (
              // URLs are unique within this list, so they outperform the
              // positional index as a React key (avoids reconciliation
              // glitches if the order ever shifts).
              <div key={url}>
                <CustomLink href={url}>{url}</CustomLink>
              </div>
            ))}
          </div>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
