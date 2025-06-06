import { Requirement } from "@/types/compliance";

export const KISACustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  const auditChecklist = requirement.audit_checklist as string[] | undefined;
  const relatedRegulations = requirement.related_regulations as
    | string[]
    | undefined;
  const auditEvidence = requirement.audit_evidence as string[] | undefined;
  const nonComplianceCases = requirement.non_compliance_cases as
    | string[]
    | undefined;

  return (
    <div className="space-y-4">
      {requirement.description && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Description
          </h4>
          <p className="text-sm">{requirement.description}</p>
        </div>
      )}

      {auditChecklist && auditChecklist.length > 0 && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Audit Checklist
          </h4>
          <div className="space-y-2">
            {auditChecklist.map((item: string, index: number) => (
              <div key={index} className="flex items-start gap-2">
                <span className="text-muted-foreground mt-1 text-xs">•</span>
                <p className="text-sm">{item}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {relatedRegulations && relatedRegulations.length > 0 && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Related Regulations
          </h4>
          <div className="space-y-2">
            {relatedRegulations.map((regulation: string, index: number) => (
              <div key={index} className="flex items-start gap-2">
                <span className="text-muted-foreground mt-1 text-xs">•</span>
                <p className="text-sm">{regulation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {auditEvidence && auditEvidence.length > 0 && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Audit Evidence
          </h4>
          <div className="space-y-2">
            {auditEvidence.map((evidence: string, index: number) => (
              <div key={index} className="flex items-start gap-2">
                <span className="text-muted-foreground mt-1 text-xs">•</span>
                <p className="text-sm">{evidence}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {nonComplianceCases && nonComplianceCases.length > 0 && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Non-Compliance Cases
          </h4>
          <div className="space-y-2">
            {nonComplianceCases.map((caseItem: string, index: number) => (
              <div key={index} className="flex items-start gap-2">
                <span className="text-muted-foreground mt-1 text-xs">•</span>
                <p className="text-sm">{caseItem}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
