import {
  defaultRehypePlugins,
  Streamdown,
  type StreamdownProps,
} from "streamdown";

import { escapeAngleBracketPlaceholders } from "@/lib/markdown";

interface MarkdownPositionPoint {
  line: number;
}

interface MarkdownPosition {
  start: MarkdownPositionPoint;
  end: MarkdownPositionPoint;
}

interface MarkdownNode {
  tagName?: string;
  position?: MarkdownPosition;
  children?: unknown[];
}

const STREAMDOWN_COMPONENTS = {
  p: ({ node, children, ...props }) => {
    if (isStandaloneImage(node)) return <>{children}</>;

    // Streamdown renders multiline code nodes as blocks, including unfinished
    // inline code that its streaming parser still places inside a paragraph.
    const Paragraph = containsMultilineCode(node) ? "div" : "p";
    return <Paragraph {...props}>{children}</Paragraph>;
  },
} satisfies NonNullable<StreamdownProps["components"]>;

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
        components={STREAMDOWN_COMPONENTS}
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

function containsMultilineCode(node: unknown): boolean {
  if (!isMarkdownNode(node)) return false;

  const isMultilineCode =
    node.tagName === "code" &&
    node.position?.start.line !== node.position?.end.line;

  return (
    isMultilineCode ||
    (node.children?.some((child) => containsMultilineCode(child)) ?? false)
  );
}

function isStandaloneImage(node: unknown): boolean {
  if (!isMarkdownNode(node) || node.children?.length !== 1) return false;

  const [child] = node.children;
  return isMarkdownNode(child) && child.tagName === "img";
}

function isMarkdownNode(value: unknown): value is MarkdownNode {
  return typeof value === "object" && value !== null;
}
