import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
} from "./shared-components";

interface FedRAMP20xDetailsProps {
  requirement: Requirement;
}

const DescriptionSection = ({ requirement }: FedRAMP20xDetailsProps) =>
  requirement.description ? (
    <ComplianceDetailSection title="Description">
      <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
    </ComplianceDetailSection>
  ) : null;

export const FedRAMP20xKSICustomDetails = ({
  requirement,
}: FedRAMP20xDetailsProps) => {
  return (
    <ComplianceDetailContainer>
      <DescriptionSection requirement={requirement} />

      <ComplianceBadgeContainer>
        {requirement.theme && (
          <ComplianceBadge
            label="Theme"
            value={requirement.theme as string}
            variant="tag"
          />
        )}
        {requirement.class_applicability && (
          <ComplianceBadge
            label="Class Applicability"
            value={requirement.class_applicability as string}
            variant="tag"
          />
        )}
      </ComplianceBadgeContainer>

      {requirement.nist_controls && (
        <ComplianceDetailSection title="NIST SP 800-53 Controls">
          <ComplianceDetailText>
            {requirement.nist_controls as string}
          </ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};

export const FedRAMP20xFRRCustomDetails = ({
  requirement,
}: FedRAMP20xDetailsProps) => {
  return (
    <ComplianceDetailContainer>
      <DescriptionSection requirement={requirement} />

      <ComplianceBadgeContainer>
        {requirement.ruleset && (
          <ComplianceBadge
            label="Ruleset"
            value={requirement.ruleset as string}
            variant="tag"
          />
        )}
        {requirement.subset && (
          <ComplianceBadge
            label="Subset"
            value={requirement.subset as string}
            variant="tag"
          />
        )}
        {requirement.force && (
          <ComplianceBadge
            label="Force"
            value={requirement.force as string}
            variant="tag"
          />
        )}
      </ComplianceBadgeContainer>
    </ComplianceDetailContainer>
  );
};
