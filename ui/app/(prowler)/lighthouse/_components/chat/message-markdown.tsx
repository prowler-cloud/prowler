import { defaultRehypePlugins, Streamdown } from "streamdown";

import { escapeAngleBracketPlaceholders } from "@/lib/markdown";

// Renders assistant message text as markdown (code blocks, tables, lists),
// matching the Lighthouse v1 chat. `isStreaming` animates partial output.
export function MessageMarkdown({
  text,
  isStreaming = false,
}: {
  text: string;
  isStreaming?: boolean;
}) {
  return (
    <div className="lighthouse-markdown max-w-full min-w-0 overflow-x-auto">
      <Streamdown
        parseIncompleteMarkdown
        shikiTheme={["github-light", "github-dark"]}
        controls={{ code: true, table: true, mermaid: true }}
        // Omit defaultRehypePlugins.raw so HTML-like tokens (e.g. <bucket_name>)
        // are escaped rather than parsed as elements.
        rehypePlugins={[
          defaultRehypePlugins.katex,
          defaultRehypePlugins.harden,
        ]}
        isAnimating={isStreaming}
      >
        {escapeAngleBracketPlaceholders(text)}
      </Streamdown>
    </div>
  );
}
