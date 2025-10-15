import { cn } from "@/lib";
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
  // Helper to render section mappings (threats or guidelines)
  const renderSectionMappings = (
    data: unknown,
    title: string,
    colorScheme: "red" | "blue",
  ) => {
    if (!data) return null;

    const mappings = data as Array<{
      ReferenceId: string;
      Identifiers: string[];
    }>;

    const colorClasses = {
      red: "bg-red-50 text-red-700 ring-red-600/10 dark:bg-red-400/10 dark:text-red-400 dark:ring-red-400/20",
      blue: "bg-blue-50 text-blue-700 ring-blue-600/10 dark:bg-blue-400/10 dark:text-blue-400 dark:ring-blue-400/20",
    };

    return (
      <ComplianceDetailSection title={title}>
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
                    className={cn(
                      "inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset",
                      colorClasses[colorScheme],
                    )}
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

      {renderSectionMappings(
        requirement.section_threat_mappings,
        "Threat Mappings",
        "red",
      )}
      {renderSectionMappings(
        requirement.section_guideline_mappings,
        "Guideline Mappings",
        "blue",
      )}
    </ComplianceDetailContainer>
  );
};
