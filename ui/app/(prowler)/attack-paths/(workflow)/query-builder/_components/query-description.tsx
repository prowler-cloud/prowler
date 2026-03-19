import { Info } from "lucide-react";

import type { AttackPathQuery } from "@/types/attack-paths";

interface QueryDescriptionProps {
  query: AttackPathQuery;
}

export const QueryDescription = ({ query }: QueryDescriptionProps) => {
  return (
    <div className="bg-bg-neutral-tertiary text-text-neutral-secondary dark:text-text-neutral-secondary rounded-md px-3 py-2 text-sm">
      <div className="flex items-start gap-2">
        <Info
          className="mt-0.5 size-4 shrink-0"
          style={{ color: "var(--bg-data-info)" }}
        />
        <div className="flex flex-col gap-2">
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
        </div>
      </div>
    </div>
  );
};
