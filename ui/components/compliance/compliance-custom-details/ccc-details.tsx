import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceChipContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface CCCDetailsProps {
  requirement: Requirement;
}

export const CCCCustomDetails = ({ requirement }: CCCDetailsProps) => {
  // Helper to render threat mappings
  const renderThreatMappings = () => {
    if (!requirement.section_threat_mappings) return null;

    const mappings = requirement.section_threat_mappings as Array<{
      ReferenceId: string;
      Identifiers: string[];
    }>;

    return (
      <ComplianceDetailSection title="Threat Mappings">
        <div className="flex flex-col gap-3">
          {mappings.map((mapping, index) => (
            <div key={index} className="flex flex-col gap-1">
              <span className="text-muted-foreground text-xs font-medium">
                {mapping.ReferenceId}
              </span>
              <div className="flex flex-wrap gap-2">
                {mapping.Identifiers.map((identifier, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center rounded-md bg-red-50 px-2 py-1 text-xs font-medium text-red-700 ring-1 ring-red-600/10 ring-inset dark:bg-red-400/10 dark:text-red-400 dark:ring-red-400/20"
                  >
                    {identifier}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </ComplianceDetailSection>
    );
  };

  // Helper to render guideline mappings
  const renderGuidelineMappings = () => {
    if (!requirement.section_guideline_mappings) return null;

    const mappings = requirement.section_guideline_mappings as Array<{
      ReferenceId: string;
      Identifiers: string[];
    }>;

    return (
      <ComplianceDetailSection title="Guideline Mappings">
        <div className="flex flex-col gap-3">
          {mappings.map((mapping, index) => (
            <div key={index} className="flex flex-col gap-1">
              <span className="text-muted-foreground text-xs font-medium">
                {mapping.ReferenceId}
              </span>
              <div className="flex flex-wrap gap-2">
                {mapping.Identifiers.map((identifier, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center rounded-md bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600/10 ring-inset dark:bg-blue-400/10 dark:text-blue-400 dark:ring-blue-400/20"
                  >
                    {identifier}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </ComplianceDetailSection>
    );
  };

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.family_name && (
          <ComplianceBadge
            label="Family"
            value={requirement.family_name as string}
            color="purple"
          />
        )}
      </ComplianceBadgeContainer>

      {requirement.family_description && (
        <ComplianceDetailSection title="Family Description">
          <ComplianceDetailText>
            {requirement.family_description as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.subsection && (
        <ComplianceDetailSection title="SubSection">
          <ComplianceDetailText>
            {requirement.subsection as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.subsection_objective && (
        <ComplianceDetailSection title="SubSection Objective">
          <ComplianceDetailText className="whitespace-pre-wrap">
            {requirement.subsection_objective as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {requirement.applicability && (
        <ComplianceChipContainer
          title="Applicability"
          items={requirement.applicability as string[]}
        />
      )}

      {requirement.recommendation && (
        <ComplianceDetailSection title="Recommendation">
          <ComplianceDetailText className="whitespace-pre-wrap">
            {requirement.recommendation as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {renderThreatMappings()}
      {renderGuidelineMappings()}
    </ComplianceDetailContainer>
  );
};
