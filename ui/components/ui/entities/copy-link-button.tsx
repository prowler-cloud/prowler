import { CheckCheck, Link } from "lucide-react";
import { useState } from "react";

type CopyLinkButtonProps = {
  url: string;
};

export const CopyLinkButton = ({ url }: CopyLinkButtonProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);

      // Reset copied state after 2 seconds
      setTimeout(() => setCopied(false), 1000);
    } catch (err) {
      console.error("Failed to copy URL to clipboard:", err);
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="ml-2 cursor-pointer p-0"
      aria-label="Copy URL to clipboard"
    >
      {copied ? (
        <CheckCheck size={16} className="inline" />
      ) : (
        <Link size={16} className="inline" />
      )}
    </button>
  );
};
