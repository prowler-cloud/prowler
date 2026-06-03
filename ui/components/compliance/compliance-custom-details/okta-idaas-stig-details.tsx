import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceChipContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
  getSeverityBadgeColor,
} from "./shared-components";

export const OktaIDaaSStigCustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  const severity = requirement.severity as string | undefined;
  const stigId = requirement.stig_id as string | undefined;
  const ruleId = requirement.rule_id as string | undefined;
  const cci = requirement.cci as string[] | undefined;
  const checkText = requirement.check_text as string | undefined;
  const fixText = requirement.fix_text as string | undefined;

  return (
    <ComplianceDetailContainer>
      <ComplianceBadgeContainer>
        {severity && (
          <ComplianceBadge
            label="Severity"
            value={severity}
            color={getSeverityBadgeColor(severity)}
          />
        )}
        {stigId && (
          <ComplianceBadge label="STIG ID" value={stigId} color="indigo" />
        )}
        {ruleId && (
          <ComplianceBadge label="Rule ID" value={ruleId} color="indigo" />
        )}
      </ComplianceBadgeContainer>

      {requirement.description && (
        <ComplianceDetailSection title="Description">
          <ComplianceDetailText>{requirement.description}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      <ComplianceChipContainer title="CCI" items={cci || []} />

      {checkText && (
        <ComplianceDetailSection title="Check">
          <ComplianceDetailText>{checkText}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}

      {fixText && (
        <ComplianceDetailSection title="Fix">
          <ComplianceDetailText>{fixText}</ComplianceDetailText>
        </ComplianceDetailSection>
      )}
    </ComplianceDetailContainer>
  );
};
