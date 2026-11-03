/**
 * Cloudy brand marks.
 *
 * The exports keep their upstream names (ProwlerBrand, ProwlerExtended,
 * ProwlerShort) so every call site stays untouched and future upstream merges
 * stay small; what they draw is Cloudy's own mark. Prowler's name and logo are
 * trademarks of Prowler and are not used anywhere in the Cloudy UI.
 *
 * The mark: a cloud silhouette crossed by a three-node path — the product's
 * own object (an attack path across your cloud) drawn as a symbol.
 */
import React from "react";

import { cn } from "@/lib/utils";

import { IconSvgProps } from "../../../types/index";

const CLOUDY_NAME = "Cloudy";

const CloudyMarkPaths = () => (
  <>
    <path
      d="M10.2 26.5h20.6a7.2 7.2 0 0 0 .9-14.34A10.4 10.4 0 0 0 11.6 10.4a8.05 8.05 0 0 0-1.4 16.1Z"
      fill="currentColor"
      opacity="0.16"
    />
    <path
      d="M10.2 26.5h20.6a7.2 7.2 0 0 0 .9-14.34A10.4 10.4 0 0 0 11.6 10.4a8.05 8.05 0 0 0-1.4 16.1Z"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinejoin="round"
    />
    <path
      d="m11.5 21.2 7.2-5.4 5.6 4.1 6-5.2"
      stroke="var(--text-lighthouse)"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <circle cx="11.5" cy="21.2" r="2.1" fill="var(--text-lighthouse)" />
    <circle cx="18.7" cy="15.8" r="2.1" fill="var(--text-lighthouse)" />
    <circle cx="30.3" cy="14.7" r="2.1" fill="var(--text-lighthouse)" />
  </>
);

interface ProwlerBrandProps {
  className?: string;
}

/** Mark + wordmark, used in the sidebar and on the auth screens. */
export const ProwlerBrand = ({ className }: ProwlerBrandProps) => (
  <span
    role="img"
    aria-label={CLOUDY_NAME}
    className={cn(
      "text-text-neutral-primary inline-flex items-center gap-2.5",
      className,
    )}
  >
    <svg
      viewBox="0 0 40 36"
      fill="none"
      aria-hidden="true"
      className="size-8 shrink-0"
    >
      <CloudyMarkPaths />
    </svg>
    <span
      aria-hidden="true"
      className="text-[22px] leading-none font-semibold tracking-[-0.03em]"
    >
      {CLOUDY_NAME}
    </span>
  </span>
);

export const ProwlerExtended: React.FC<IconSvgProps> = ({
  size,
  width = 216,
  height,
  ...props
}) => (
  <svg
    className="text-text-neutral-primary"
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 168 36"
    fill="none"
    role="img"
    aria-label={CLOUDY_NAME}
    height={size || height}
    width={size || width}
    {...props}
  >
    <CloudyMarkPaths />
    <text
      x="48"
      y="26"
      fill="currentColor"
      fontFamily="var(--font-sans), system-ui, sans-serif"
      fontSize="24"
      fontWeight="600"
      letterSpacing="-0.7"
    >
      {CLOUDY_NAME}
    </text>
  </svg>
);

export const ProwlerShort: React.FC<IconSvgProps> = ({
  size,
  width = 30,
  height,
  ...props
}) => (
  <svg
    className="text-text-neutral-primary"
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 40 36"
    fill="none"
    role="img"
    aria-label={CLOUDY_NAME}
    height={size || height}
    width={size || width}
    {...props}
  >
    <CloudyMarkPaths />
  </svg>
);
