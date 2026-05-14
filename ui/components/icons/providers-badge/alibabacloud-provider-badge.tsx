import { FC } from "react";

import { IconSvgProps } from "@/types";

export const AlibabaCloudProviderBadge: FC<IconSvgProps> = ({
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
    <g fill="none">
      <rect width="256" height="256" fill="#f4f2ed" rx="60" />
      <g transform="translate(28, 66) scale(1.66)">
        {/* Horizontal bar */}
        <rect x="40.1" y="32.8" fill="#FF6A00" width="40.1" height="9" />
        {/* Right bracket */}
        <path
          fill="#FF6A00"
          d="M100.2,0H73.7l6.4,9.1L99.5,15c3.6,1.1,5.9,4.5,5.8,8c0,0,0,0,0,0V52c0,0,0,0,0,0c0,3.6-2.3,6.9-5.8,8l-19.3,5.9L73.7,75h26.5c11.1,0,20-9,20-20V20C120.3,9,111.3,0,100.2,0"
        />
        {/* Left bracket */}
        <path
          fill="#FF6A00"
          d="M20,0h26.5l-6.4,9.1L20.8,15c-3.6,1.1-5.9,4.5-5.8,8c0,0,0,0,0,0V52c0,0,0,0,0,0c0,3.6,2.3,6.9,5.8,8l19.3,5.9l6.4,9.1H20C9,75,0,66,0,55V20C0,9,9,0,20,0"
        />
      </g>
    </g>
  </svg>
);
