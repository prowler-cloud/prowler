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

// Each requirement's References field is a single URL or a comma/space
// separated list of URLs. The regex matches both http:// and https:// so
// plain-http references aren't silently dropped.
const URL_REGEX = /https?:\/\/[^\s,]+/g;

const extractUrls = (references: Requirement[keyof Requirement]): string[] => {
  if (typeof references !== "string") return [];
  return references.match(URL_REGEX) ?? [];
};

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

export const ASDEssentialEightCustomDetails = ({
  requirement,
}: ASDEssentialEightDetailsProps) => {
  const {
    description,
    implementation_notes,
    maturity_level,
    assessment_status,
    cloud_applicability,
    mitigated_threats,
    rationale_statement,
    impact_statement,
    remediation_procedure,
    audit_procedure,
    additional_information,
    references,
  } = requirement;

  const referenceUrls = extractUrls(references);

  return (
    <ComplianceDetailContainer>
      {description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {typeof implementation_notes === "string" && implementation_notes && (
        <ComplianceDetailSection title="Implementation Notes">
          <ComplianceDetailText>{implementation_notes}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {typeof maturity_level === "string" && maturity_level && (
          <ComplianceBadge
            label="Maturity Level"
            value={maturity_level}
            color="purple"
          />
        )}

        {typeof assessment_status === "string" && assessment_status && (
          <ComplianceBadge
            label="Assessment"
            value={assessment_status}
            color="blue"
          />
        )}

        {typeof cloud_applicability === "string" && cloud_applicability && (
          <ComplianceBadge
            label="Cloud Applicability"
            value={cloud_applicability}
            color="orange"
          />
        )}
      </ComplianceBadgeContainer>

      {/* `isStringArray` narrows the index-signature union to string[], so no cast is needed. `ComplianceChipContainer` returns null on empty arrays, so no length check is needed here either. */}
      {isStringArray(mitigated_threats) && (
        <ComplianceChipContainer
          title="Mitigated Threats"
          items={mitigated_threats}
        />
      )}

      {typeof rationale_statement === "string" && rationale_statement && (
        <ComplianceDetailSection title="Rationale Statement">
          <ComplianceDetailText>{rationale_statement}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {typeof impact_statement === "string" && impact_statement && (
        <ComplianceDetailSection title="Impact Statement">
          <ComplianceDetailText>{impact_statement}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {typeof remediation_procedure === "string" && remediation_procedure && (
        <ComplianceDetailSection title="Remediation Procedure">
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown>{remediation_procedure}</ReactMarkdown>
          </div>
        </ComplianceDetailSection>
      )}

      {typeof audit_procedure === "string" && audit_procedure && (
        <ComplianceDetailSection title="Audit Procedure">
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown>{audit_procedure}</ReactMarkdown>
          </div>
        </ComplianceDetailSection>
      )}

      {typeof additional_information === "string" && additional_information && (
        <ComplianceDetailSection title="Additional Information">
          <ComplianceDetailText className="whitespace-pre-wrap">
            {additional_information}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {referenceUrls.length > 0 && (
        <ComplianceDetailSection title="References">
          <div className="flex flex-col gap-1">
            {referenceUrls.map((url) => (
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
