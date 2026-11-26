"use client";

import Link from "next/link";

import { PREMIUM_PAGE_PATH } from "@/lib/premium";
import { isCloud } from "@/lib/shared/env";

export function EditionIndicator() {
  if (isCloud()) return null;

  return (
    <Link
      href={PREMIUM_PAGE_PATH}
      className="border-border-neutral-secondary hover:bg-bg-neutral-tertiary hidden items-center gap-2 rounded-full border px-3 py-1 text-xs transition-colors md:flex"
    >
      <span
        aria-hidden="true"
        className="bg-text-neutral-tertiary size-1.5 rounded-full"
      />
      <span className="text-text-neutral-secondary">
        Local Server · Open Source
      </span>
      <span className="text-text-success-primary font-medium">
        What&apos;s in Cloud?
      </span>
    </Link>
  );
}
