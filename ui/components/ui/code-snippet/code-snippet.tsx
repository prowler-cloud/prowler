import { Snippet } from "@heroui/snippet";

export const CodeSnippet = ({ value }: { value: string }) => (
  <Snippet
    className="bg-bg-neutral-tertiary text-text-neutral-primary border-border-neutral-tertiary w-full rounded-lg border py-1 text-xs"
    hideSymbol
    classNames={{
      pre: "w-full truncate",
    }}
  >
    {value}
  </Snippet>
);
