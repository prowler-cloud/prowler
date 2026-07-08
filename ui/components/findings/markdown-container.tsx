import ReactMarkdown from "react-markdown";

interface MarkdownContainerProps {
  children: string;
}

export const MarkdownContainer = ({ children }: MarkdownContainerProps) => (
  <div className="prose prose-sm dark:prose-invert prose-code:before:content-none prose-code:after:content-none max-w-none break-words whitespace-normal">
    <ReactMarkdown>{children}</ReactMarkdown>
  </div>
);
