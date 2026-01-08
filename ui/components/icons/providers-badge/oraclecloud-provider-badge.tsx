import * as React from "react";

import { IconSvgProps } from "@/types";

export const OracleCloudProviderBadge: React.FC<IconSvgProps> = ({
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
        fill="#c74634"
        d="M 56 128
           C 56 101.5 87.2 80 128 80
           C 168.8 80 200 101.5 200 128
           C 200 154.5 168.8 176 128 176
           C 87.2 176 56 154.5 56 128 Z
           M 72 128
           C 72 145.7 96.5 160 128 160
           C 159.5 160 184 145.7 184 128
           C 184 110.3 159.5 96 128 96
           C 96.5 96 72 110.3 72 128 Z"
        fillRule="evenodd"
      />
    </g>
  </svg>
);
