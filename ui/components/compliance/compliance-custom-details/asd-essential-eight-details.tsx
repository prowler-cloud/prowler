import ReactMarkdown from "react-markdown";

import { CustomLink } from "@/components/shadcn/custom/custom-link";
import {
  isASDAssessmentStatus,
  isASDCloudApplicability,
  isASDMaturityLevel,
  type Requirement,
} from "@/types/compliance";

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

const extractUrls = (references: unknown): string[] => {
  if (typeof references !== "string") return [];
  return references.match(URL_REGEX) ?? [];
};

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

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
  const maturityLevel = isASDMaturityLevel(maturity_level)
    ? maturity_level
    : undefined;
  const assessmentStatus = isASDAssessmentStatus(assessment_status)
    ? assessment_status
    : undefined;
  const cloudApplicability = isASDCloudApplicability(cloud_applicability)
    ? cloud_applicability
    : undefined;

  return (
    <ComplianceDetailContainer>
      {description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {isNonEmptyString(implementation_notes) && (
        <ComplianceDetailSection title="Implementation Notes">
          <ComplianceDetailText>{implementation_notes}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {maturityLevel && (
          <ComplianceBadge
            label="Maturity Level"
            value={maturityLevel}
            variant="secondary"
          />
        )}

        {assessmentStatus && (
          <ComplianceBadge
            label="Assessment"
            value={assessmentStatus}
            variant="info"
          />
        )}

        {cloudApplicability && (
          <ComplianceBadge
            label="Cloud Applicability"
            value={cloudApplicability}
            variant="secondary"
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

      {isNonEmptyString(rationale_statement) && (
        <ComplianceDetailSection title="Rationale Statement">
          <ComplianceDetailText>{rationale_statement}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {isNonEmptyString(impact_statement) && (
        <ComplianceDetailSection title="Impact Statement">
          <ComplianceDetailText>{impact_statement}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {isNonEmptyString(remediation_procedure) && (
        <ComplianceDetailSection title="Remediation Procedure">
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown>{remediation_procedure}</ReactMarkdown>
          </div>
        </ComplianceDetailSection>
      )}

      {isNonEmptyString(audit_procedure) && (
        <ComplianceDetailSection title="Audit Procedure">
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown>{audit_procedure}</ReactMarkdown>
          </div>
        </ComplianceDetailSection>
      )}

      {isNonEmptyString(additional_information) && (
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
