import Link from "next/link";

import { SeverityBadge } from "@/components/ui/table";
import { Requirement } from "@/types/compliance";

export const AWSWellArchitectedCustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
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

      {requirement.well_architected_name && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Best Practice
          </h4>
          <p className="text-sm">{requirement.well_architected_name}</p>
        </div>
      )}

      {requirement.well_architected_question_id && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Question ID
          </h4>
          <p className="text-sm">{requirement.well_architected_question_id}</p>
        </div>
      )}

      {requirement.well_architected_practice_id && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Practice ID
          </h4>
          <p className="text-sm">{requirement.well_architected_practice_id}</p>
        </div>
      )}

      {requirement.level_of_risk && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Level of Risk
          </h4>
          <SeverityBadge
            severity={
              requirement.level_of_risk.toString().toLowerCase() as
                | "low"
                | "medium"
                | "high"
            }
          />
        </div>
      )}

      {requirement.assessment_method && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Assessment Method
          </h4>
          <p className="text-sm">{requirement.assessment_method}</p>
        </div>
      )}

      {requirement.implementation_guidance_url && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Implementation Guidance
          </h4>
          <Link
            href={requirement.implementation_guidance_url as string}
            target="_blank"
            rel="noopener noreferrer"
            className="break-all text-sm text-blue-600 underline hover:text-blue-800"
          >
            {requirement.implementation_guidance_url}
          </Link>
        </div>
      )}
    </div>
  );
};
