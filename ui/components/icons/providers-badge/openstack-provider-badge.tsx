import * as React from "react";

import { IconSvgProps } from "@/types";

export const OpenStackProviderBadge: React.FC<IconSvgProps> = ({
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
      <g transform="translate(48 48) scale(2.5)" fill="#da1a32">
        <path d="M58.054.68H5.946C2.676.68 0 3.356 0 6.626V20.64h14.452v-2.3c0-1.776 1.44-3.215 3.215-3.215h28.665c1.776 0 3.215 1.44 3.215 3.215v2.3H64v-14A5.97 5.97 0 0 0 58.054.68zm-8.506 44.97c0 1.776-1.44 3.215-3.215 3.215H17.67c-1.776 0-3.215-1.44-3.215-3.215v-2.3H0v14.013c0 3.27 2.676 5.946 5.946 5.946h52.108c3.27 0 5.946-2.676 5.946-5.946V43.36H49.548zM0 24.773h14.452v14.452H0zm49.548 0H64v14.452H49.548z" />
      </g>
    </g>
  </svg>
);
