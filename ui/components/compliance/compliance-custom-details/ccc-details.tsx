import { cn } from "@/lib";
import { CCC_MAPPING_SECTIONS, CCC_TEXT_SECTIONS } from "@/lib/compliance/ccc";
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
  // Map text sections with requirement data
  const textSections = CCC_TEXT_SECTIONS.map((section) => ({
    ...section,
    content: requirement[section.key] as string | undefined,
  })).filter((section) => section.content);

  // Map mapping sections with requirement data
  const mappingSections = CCC_MAPPING_SECTIONS.map((section) => ({
    ...section,
    data: requirement[section.key] as Array<{
      ReferenceId: string;
      Identifiers: string[];
    }>,
  })).filter((section) => section.data);

  return (
    <ComplianceDetailContainer>
      {textSections.map((section) => (
        <ComplianceDetailSection key={section.title} title={section.title}>
          <ComplianceDetailText className={section.className}>
            {section.content}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      ))}

      {requirement.family_name && (
        <ComplianceBadgeContainer>
          <ComplianceBadge
            label="Family"
            value={requirement.family_name as string}
            color="purple"
          />
        </ComplianceBadgeContainer>
      )}

      {requirement.applicability && (
        <ComplianceChipContainer
          title="Applicability"
          items={requirement.applicability as string[]}
        />
      )}

      {mappingSections.map((section) => (
        <ComplianceDetailSection key={section.title} title={section.title}>
          <div className="flex flex-col gap-3">
            {section.data.map((mapping, index) => (
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
                        section.colorClasses,
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
      ))}
    </ComplianceDetailContainer>
  );
};
