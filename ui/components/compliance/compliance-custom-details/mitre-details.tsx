import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceChipContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
  ComplianceLink,
} from "./shared-components";

export const MITRECustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  const cloudServices = requirement.cloud_services as
    | Array<{
        service: string;
        category: string;
        value: string;
        comment: string;
      }>
    | undefined;

  return (
    <ComplianceDetailContainer>
      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceBadgeContainer>
        {requirement.technique_id && (
          <ComplianceBadge
            label="Technique ID"
            value={requirement.technique_id as string}
            color="indigo"
          />
        )}
      </ComplianceBadgeContainer>

      <ComplianceChipContainer
        title="Tactics"
        items={(requirement.tactics as string[]) || []}
      />

      <ComplianceChipContainer
        title="Platforms"
        items={(requirement.platforms as string[]) || []}
      />

      {requirement.subtechniques &&
        Array.isArray(requirement.subtechniques) &&
        requirement.subtechniques.length > 0 && (
          <ComplianceChipContainer
            title="Subtechniques"
            items={requirement.subtechniques as string[]}
          />
        )}

      {requirement.technique_url && (
        <ComplianceDetailSection title="MITRE ATT&CK Reference">
          <ComplianceLink href={requirement.technique_url as string}>
            {requirement.technique_url as string}
          </ComplianceLink>
        </ComplianceDetailSection>
      )}

      {cloudServices && cloudServices.length > 0 && (
        <ComplianceDetailSection title="Cloud Security Mappings">
          <div className="space-y-4">
            {cloudServices.map((service, index) => (
              <div key={index} className="space-y-3 rounded-lg border p-4">
                <div className="flex flex-wrap items-center gap-3">
                  <ComplianceBadge
                    label="Service"
                    value={service.service}
                    color="blue"
                  />
                  <ComplianceBadge
                    label="Category"
                    value={service.category}
                    color="indigo"
                  />
                  <ComplianceBadge
                    label="Coverage"
                    value={service.value}
                    color="orange"
                  />
                </div>
                {service.comment && (
                  <div>
                    <h5 className="text-muted-foreground mb-1 text-xs font-medium">
                      Details
                    </h5>
                    <ComplianceDetailText className="text-xs">
                      {service.comment}
                    </ComplianceDetailText>
                  </div>
                )}
              </div>
            ))}
          </div>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
