import { Info } from "lucide-react";

import { Alert, AlertDescription } from "@/components/shadcn";
import { getAttackPathHubUrl } from "@/lib/external-urls";
import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathQuery,
} from "@/types/attack-paths";

interface QueryDescriptionProps {
  query: AttackPathQuery;
}

const isSafeUrl = (url: string): boolean => {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol === "https:" || parsedUrl.protocol === "http:";
  } catch {
    return false;
  }
};

export const QueryDescription = ({ query }: QueryDescriptionProps) => {
  const documentationLink = query.attributes.documentation_link;
  // Every built-in query has a Prowler Hub page keyed by its id. The synthetic
  // custom query has no catalog entry, so it gets no hub link.
  const hubUrl =
    query.id === ATTACK_PATH_QUERY_IDS.CUSTOM
      ? null
      : getAttackPathHubUrl(query.id);

  return (
    <Alert variant="info">
      <Info className="text-bg-data-info mt-0.5 size-4 shrink-0" />
      <AlertDescription className="w-full gap-2">
        <p className="whitespace-pre-line">{query.attributes.description}</p>

        {hubUrl && (
          <p className="text-xs">
            <a
              href={hubUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline"
            >
              View on Prowler Hub
            </a>
          </p>
        )}

        {documentationLink && (
          <p className="text-xs">
            {isSafeUrl(documentationLink.link) ? (
              <a
                href={documentationLink.link}
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium underline"
              >
                {documentationLink.text}
              </a>
            ) : (
              <span className="font-medium">{documentationLink.text}</span>
            )}
          </p>
        )}
      </AlertDescription>
    </Alert>
  );
};
