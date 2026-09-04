import type { ReactNode } from "react";

interface SlackInlineCodeProps {
  children: ReactNode;
}

/**
 * A Slack identifier — a channel name, the bot mention, a slash command — set
 * apart from the prose around it.
 */
export const SlackInlineCode = ({ children }: SlackInlineCodeProps) => (
  <code className="bg-bg-neutral-tertiary text-text-neutral-secondary rounded px-1 py-0.5 font-mono">
    {children}
  </code>
);
