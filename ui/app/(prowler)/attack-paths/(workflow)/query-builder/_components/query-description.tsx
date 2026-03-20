import { Info } from "lucide-react";

import { Alert, AlertDescription } from "@/components/shadcn";
import type { AttackPathQuery } from "@/types/attack-paths";

interface QueryDescriptionProps {
  query: AttackPathQuery;
}

export const QueryDescription = ({ query }: QueryDescriptionProps) => {
  return (
    <Alert variant="info">
      <Info className="text-bg-data-info mt-0.5 size-4 shrink-0" />
      <AlertDescription className="w-full gap-2">
        <p className="whitespace-pre-line">{query.attributes.description}</p>

        {query.attributes.documentation_link && (
          <p className="text-xs">
            <a
              href={query.attributes.documentation_link.link}
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline"
            >
              {query.attributes.documentation_link.text}
            </a>
          </p>
        )}

        {query.attributes.attribution && (
          <p className="text-xs">
            Source:{" "}
            <a
              href={query.attributes.attribution.link}
              target="_blank"
              rel="noopener noreferrer"
              className="underline"
            >
              {query.attributes.attribution.text}
            </a>
          </p>
        )}
      </AlertDescription>
    </Alert>
  );
};
