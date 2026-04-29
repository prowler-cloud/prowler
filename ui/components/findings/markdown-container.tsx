import ReactMarkdown from "react-markdown";

interface MarkdownContainerProps {
  children: string;
}

export const MarkdownContainer = ({ children }: MarkdownContainerProps) => (
  <div className="prose prose-sm dark:prose-invert max-w-none break-words whitespace-normal">
    <ReactMarkdown>{children}</ReactMarkdown>
  </div>
);
