import { Snippet } from "@nextui-org/react";

export const CodeSnippet = ({ value }: { value: string }) => (
  <Snippet
    className="w-full bg-gray-50 py-1 text-xs dark:bg-slate-800"
    hideSymbol
    classNames={{
      pre: "w-full truncate",
    }}
  >
    {value}
  </Snippet>
);
