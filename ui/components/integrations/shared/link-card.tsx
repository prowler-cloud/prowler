"use client";

import { ExternalLinkIcon, LucideIcon } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn";
import { CustomLink } from "@/components/ui/custom/custom-link";

import { Card, CardContent, CardHeader } from "../../shadcn";

interface LinkCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  learnMoreUrl: string;
  learnMoreAriaLabel: string;
  bodyText: string;
  linkHref: string;
  linkText: string;
}

export const LinkCard = ({
  icon: Icon,
  title,
  description,
  learnMoreUrl,
  learnMoreAriaLabel,
  bodyText,
  linkHref,
  linkText,
}: LinkCardProps) => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="dark:bg-prowler-blue-800 flex h-10 w-10 items-center justify-center rounded-lg bg-gray-100">
              <Icon size={24} className="text-gray-700 dark:text-gray-200" />
            </div>
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                {title}
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
                  {description}
                </p>
                <CustomLink
                  href={learnMoreUrl}
                  aria-label={learnMoreAriaLabel}
                  size="xs"
                >
                  Learn more
                </CustomLink>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href={linkHref}>
                <ExternalLinkIcon size={14} />
                {linkText}
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-600 dark:text-gray-300">{bodyText}</p>
      </CardContent>
    </Card>
  );
};
