import { type FC } from "react";

import { IconSvgProps } from "@/types";

export const GoogleWorkspaceProviderBadge: FC<IconSvgProps> = ({
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
      <g transform="translate(64 64) scale(2.0)">
        <path
          d="M62.3 30.9c0-2.5-.2-4.9-.6-7.2H32v13.6h17c-.7 3.9-3 7.2-6.3 9.4v8.3h10.2c6-5.5 9.4-13.6 9.4-23.1z"
          fill="#4285F4"
        />
        <path
          d="M32 64c8.5 0 15.6-2.8 20.8-7.6l-10.2-7.9c-2.8 1.9-6.4 3-10.6 3-8.1 0-15-5.5-17.4-12.9H4.1v8.1C9.3 57.3 19.9 64 32 64z"
          fill="#34A853"
        />
        <path
          d="M14.6 38.6c-.6-1.9-1-3.9-1-6s.3-4.1 1-6v-8.1H4.1C1.5 22.4 0 27 0 32s1.5 9.6 4.1 13.5l10.5-7.9z"
          fill="#FBBC05"
        />
        <path
          d="M32 12.7c4.6 0 8.7 1.6 11.9 4.7l8.9-8.9C47.6 3.4 40.5 0 32 0 19.9 0 9.3 6.7 4.1 17.5l10.5 8.1C17 18.2 23.9 12.7 32 12.7z"
          fill="#EA4335"
        />
      </g>
    </g>
  </svg>
);
