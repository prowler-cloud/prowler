import * as React from "react";

import { IconSvgProps } from "@/types";

export const IacProviderBadge: React.FC<IconSvgProps> = ({
  size,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
    fill="none"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 256 256"
    width={size || width}
    {...props}
  >
    <rect width="256" height="256" fill="#e8eaed" rx="60" />
    <g
      stroke="#5f6368"
      strokeWidth="14"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {/* Slash: / */}
      <path d="M112 205L148 51" />
      {/* Left bracket: < */}
      <path d="M85 85L45 128L85 171" />
      {/* Right bracket: > */}
      <path d="M171 85L211 128L171 171" />
    </g>
  </svg>
);
