"use client";

import { Tooltip } from "@nextui-org/react";
import { CheckCheck, ExternalLink } from "lucide-react";
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

      setTimeout(() => setCopied(false), 500);
    } catch (err) {
      console.error("Failed to copy URL to clipboard:", err);
    }
  };

  return (
    <Tooltip content="Copy URL to clipboard" size="sm">
      <button
        type="button"
        onClick={handleCopy}
        className="ml-2 cursor-pointer p-0"
        aria-label="Copy URL to clipboard"
      >
        {copied ? (
          <CheckCheck size={16} className="inline" />
        ) : (
          <ExternalLink size={16} className="inline" />
        )}
      </button>
    </Tooltip>
  );
};
