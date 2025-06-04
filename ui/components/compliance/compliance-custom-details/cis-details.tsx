import Link from "next/link";
import ReactMarkdown from "react-markdown";

import { Requirement } from "@/types/compliance";

interface CISDetailsProps {
  requirement: Requirement;
}

export const CISCustomDetails = ({ requirement }: CISDetailsProps) => {
  const processReferences = (
    references: string | number | string[] | undefined,
  ): string[] => {
    if (typeof references !== "string") return [];

    // Use regex to extract all URLs that start with https://
    const urlRegex = /https:\/\/[^:]+/g;
    const urls = references.match(urlRegex);

    return urls || [];
  };

  return (
    <div className="space-y-4">
      {requirement.profile && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Profile Level
          </h4>
          <p className="text-sm">{requirement.profile}</p>
        </div>
      )}

      {requirement.subsection && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            SubSection
          </h4>
          <p className="text-sm">{requirement.subsection}</p>
        </div>
      )}

      {requirement.assessment_status && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Assessment Status
          </h4>
          <p className="text-sm">{requirement.assessment_status}</p>
        </div>
      )}

      {requirement.description && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Description
          </h4>
          <p className="text-sm">{requirement.description}</p>
        </div>
      )}

      {requirement.rationale_statement && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Rationale Statement
          </h4>
          <p className="text-sm">{requirement.rationale_statement}</p>
        </div>
      )}

      {requirement.impact_statement && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Impact Statement
          </h4>
          <p className="text-sm">{requirement.impact_statement}</p>
        </div>
      )}

      {requirement.remediation_procedure &&
        typeof requirement.remediation_procedure === "string" && (
          <div>
            <h4 className="text-muted-foreground mb-1 text-sm font-medium">
              Remediation Procedure
            </h4>
            {/* Prettier -> "plugins": ["prettier-plugin-tailwindcss"] is not ready yet to "prose": */}
            {/* eslint-disable-next-line */}
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <ReactMarkdown>{requirement.remediation_procedure}</ReactMarkdown>
            </div>
          </div>
        )}

      {requirement.audit_procedure &&
        typeof requirement.audit_procedure === "string" && (
          <div>
            <h4 className="text-muted-foreground mb-1 text-sm font-medium">
              Audit Procedure
            </h4>
            {/* eslint-disable-next-line */}
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <ReactMarkdown>{requirement.audit_procedure}</ReactMarkdown>
            </div>
          </div>
        )}

      {requirement.additional_information && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Additional Information
          </h4>
          <p className="whitespace-pre-wrap text-sm">
            {requirement.additional_information}
          </p>
        </div>
      )}

      {requirement.default_value && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            Default Value
          </h4>
          <p className="text-sm">{requirement.default_value}</p>
        </div>
      )}

      {requirement.references && (
        <div>
          <h4 className="text-muted-foreground mb-1 text-sm font-medium">
            References
          </h4>
          <div className="text-sm">
            {processReferences(requirement.references).map(
              (url: string, index: number) => (
                <div key={index}>
                  <Link
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="break-all text-blue-600 underline hover:text-blue-800"
                  >
                    {url}
                  </Link>
                </div>
              ),
            )}
          </div>
        </div>
      )}
    </div>
  );
};
