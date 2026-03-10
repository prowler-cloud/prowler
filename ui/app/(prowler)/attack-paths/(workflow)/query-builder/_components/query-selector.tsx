"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import type { AttackPathQuery } from "@/types/attack-paths";

interface QuerySelectorProps {
  queries: AttackPathQuery[];
  selectedQueryId: string | null;
  onQueryChange: (queryId: string) => void;
}

/**
 * Query selector dropdown component
 * Allows users to select from available Attack Paths queries
 */
export const QuerySelector = ({
  queries,
  selectedQueryId,
  onQueryChange,
}: QuerySelectorProps) => {
  return (
    <Select value={selectedQueryId || ""} onValueChange={onQueryChange}>
      <SelectTrigger className="w-full text-left">
        <SelectValue placeholder="Choose a query..." />
      </SelectTrigger>
      <SelectContent>
        {queries.map((query) => (
          <SelectItem key={query.id} value={query.id}>
            <div className="flex flex-col gap-1">
              <span className="font-medium">{query.attributes.name}</span>
              <span className="text-xs text-gray-500">
                {query.attributes.short_description}
              </span>
            </div>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};
