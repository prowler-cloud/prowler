import { Severity, SeverityBadge } from "@/components/shadcn/table";
import { Requirement } from "@/types/compliance";

import {
  ComplianceBadge,
  ComplianceBadgeContainer,
  ComplianceChipContainer,
  ComplianceDetailContainer,
  ComplianceDetailSection,
  ComplianceDetailText,
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
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-sm font-medium">
              Severity:
            </span>
            <SeverityBadge severity={severity.toLowerCase() as Severity} />
          </div>
        )}
        {stigId && (
          <ComplianceBadge label="STIG ID" value={stigId} variant="tag" />
        )}
        {ruleId && (
          <ComplianceBadge label="Rule ID" value={ruleId} variant="tag" />
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
