import { FC } from "react";

import { IconSvgProps } from "@/types";

export const ImageProviderBadge: FC<IconSvgProps> = ({
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
    <rect width="256" height="256" fill="#1c1917" rx="60" />
    <g
      transform="translate(20, 20) scale(9)"
      fill="none"
      stroke="#fff"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12.89 1.45L21 5.75V18.25L12.89 22.55C12.33 22.84 11.67 22.84 11.11 22.55L3 18.25V5.75L11.11 1.45C11.67 1.16 12.33 1.16 12.89 1.45Z" />
      <path d="M3.5 6L12 10.5L20.5 6" />
      <path d="M12 22.5V10.5" />
    </g>
  </svg>
);
