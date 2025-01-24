import * as React from "react";

import { IconSvgProps } from "@/types";

export const AzureProviderBadge: React.FC<IconSvgProps> = ({
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
      <path
        fill="url(#skillIconsAzureLight0)"
        d="M94.674 34.002h59.182L92.42 216.032a9.44 9.44 0 0 1-8.94 6.419H37.422a9.42 9.42 0 0 1-9.318-8.026a9.4 9.4 0 0 1 .39-4.407L85.733 40.421A9.44 9.44 0 0 1 94.674 34z"
      />
      <path
        fill="#0078d4"
        d="M180.674 156.095H86.826a4.34 4.34 0 0 0-4.045 2.75a4.34 4.34 0 0 0 1.079 4.771l60.305 56.287a9.48 9.48 0 0 0 6.468 2.548h53.141z"
      />
      <path
        fill="url(#skillIconsAzureLight1)"
        d="M94.675 34.002a9.36 9.36 0 0 0-8.962 6.544L28.565 209.863a9.412 9.412 0 0 0 8.882 12.588h47.247a10.1 10.1 0 0 0 7.75-6.592l11.397-33.586l40.708 37.968a9.63 9.63 0 0 0 6.059 2.21h52.943l-23.22-66.355l-67.689.016l41.428-122.11z"
      />
      <path
        fill="url(#skillIconsAzureLight2)"
        d="M170.264 40.412a9.42 9.42 0 0 0-8.928-6.41H95.379a9.42 9.42 0 0 1 8.928 6.41l57.241 169.604a9.43 9.43 0 0 1-1.273 8.509a9.43 9.43 0 0 1-7.655 3.928h65.959a9.43 9.43 0 0 0 7.654-3.929a9.42 9.42 0 0 0 1.272-8.508z"
      />
      <defs>
        <linearGradient
          id="skillIconsAzureLight0"
          x1="116.244"
          x2="54.783"
          y1="47.967"
          y2="229.54"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#114a8b" />
          <stop offset="1" stopColor="#0669bc" />
        </linearGradient>
        <linearGradient
          id="skillIconsAzureLight1"
          x1="135.444"
          x2="121.227"
          y1="132.585"
          y2="137.392"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopOpacity="0.3" />
          <stop offset="0.071" stopOpacity="0.2" />
          <stop offset="0.321" stopOpacity="0.1" />
          <stop offset="0.623" stopOpacity="0.05" />
          <stop offset="1" stopOpacity="0" />
        </linearGradient>
        <linearGradient
          id="skillIconsAzureLight2"
          x1="127.625"
          x2="195.091"
          y1="42.671"
          y2="222.414"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#3ccbf4" />
          <stop offset="1" stopColor="#2892df" />
        </linearGradient>
      </defs>
    </g>
  </svg>
);
