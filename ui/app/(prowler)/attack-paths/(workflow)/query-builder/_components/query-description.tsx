import { Info } from "lucide-react";

import { Alert, AlertDescription } from "@/components/shadcn";
import type { AttackPathQuery } from "@/types/attack-paths";

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
  const attribution = query.attributes.attribution;

  return (
    <Alert variant="info">
      <Info className="text-bg-data-info mt-0.5 size-4 shrink-0" />
      <AlertDescription className="w-full gap-2">
        <p className="whitespace-pre-line">{query.attributes.description}</p>

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

        {attribution && (
          <p className="text-xs">
            {isSafeUrl(attribution.link) ? (
              <>
                Source:{" "}
                <a
                  href={attribution.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline"
                >
                  {attribution.text}
                </a>
              </>
            ) : (
              <>
                Source: <span>{attribution.text}</span>
              </>
            )}
          </p>
        )}
      </AlertDescription>
    </Alert>
  );
};
