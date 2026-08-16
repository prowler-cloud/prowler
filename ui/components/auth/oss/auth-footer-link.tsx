"use client";

import { useSearchParams } from "next/navigation";

import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { appendAttributionToCallbackPath } from "@/lib/auth-callback-url";
import { extractUtmParams } from "@/lib/utm";

interface AuthFooterLinkProps {
  text: string;
  linkText: string;
  href: string;
}

export const AuthFooterLink = ({
  text,
  linkText,
  href,
}: AuthFooterLinkProps) => {
  const searchParams = useSearchParams();
  const targetHref = appendAttributionToCallbackPath(
    href,
    extractUtmParams(searchParams),
  );

  return (
    <p className="text-center text-sm">
      {text}&nbsp;
      <CustomLink size="md" href={targetHref} target="_self">
        {linkText}
      </CustomLink>
    </p>
  );
};
