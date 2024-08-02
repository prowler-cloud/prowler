import * as React from "react";

import { IconSvgProps } from "@/types";

export const TwitterIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      height={size || height}
      viewBox="0 0 24 24"
      width={size || width}
      {...props}
    >
      <path
        d="M19.633 7.997c.013.175.013.349.013.523 0 5.325-4.053 11.461-11.46 11.461-2.282 0-4.402-.661-6.186-1.809.324.037.636.05.973.05a8.07 8.07 0 0 0 5.001-1.721 4.036 4.036 0 0 1-3.767-2.793c.249.037.499.062.761.062.361 0 .724-.05 1.061-.137a4.027 4.027 0 0 1-3.23-3.953v-.05c.537.299 1.16.486 1.82.511a4.022 4.022 0 0 1-1.796-3.354c0-.748.199-1.434.548-2.032a11.457 11.457 0 0 0 8.306 4.215c-.062-.3-.1-.611-.1-.923a4.026 4.026 0 0 1 4.028-4.028c1.16 0 2.207.486 2.943 1.272a7.957 7.957 0 0 0 2.556-.973 4.02 4.02 0 0 1-1.771 2.22 8.073 8.073 0 0 0 2.319-.624 8.645 8.645 0 0 1-2.019 2.083z"
        fill="currentColor"
      />
    </svg>
  );
};

export const GithubIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      height={size || height}
      viewBox="0 0 24 24"
      width={size || width}
      {...props}
    >
      <path
        clipRule="evenodd"
        d="M12.026 2c-5.509 0-9.974 4.465-9.974 9.974 0 4.406 2.857 8.145 6.821 9.465.499.09.679-.217.679-.481 0-.237-.008-.865-.011-1.696-2.775.602-3.361-1.338-3.361-1.338-.452-1.152-1.107-1.459-1.107-1.459-.905-.619.069-.605.069-.605 1.002.07 1.527 1.028 1.527 1.028.89 1.524 2.336 1.084 2.902.829.091-.645.351-1.085.635-1.334-2.214-.251-4.542-1.107-4.542-4.93 0-1.087.389-1.979 1.024-2.675-.101-.253-.446-1.268.099-2.64 0 0 .837-.269 2.742 1.021a9.582 9.582 0 0 1 2.496-.336 9.554 9.554 0 0 1 2.496.336c1.906-1.291 2.742-1.021 2.742-1.021.545 1.372.203 2.387.099 2.64.64.696 1.024 1.587 1.024 2.675 0 3.833-2.33 4.675-4.552 4.922.355.308.675.916.675 1.846 0 1.334-.012 2.41-.012 2.737 0 .267.178.577.687.479C19.146 20.115 22 16.379 22 11.974 22 6.465 17.535 2 12.026 2z"
        fill="currentColor"
        fillRule="evenodd"
      />
    </svg>
  );
};

export const MoonFilledIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    aria-hidden="true"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <path
      d="M21.53 15.93c-.16-.27-.61-.69-1.73-.49a8.46 8.46 0 01-1.88.13 8.409 8.409 0 01-5.91-2.82 8.068 8.068 0 01-1.44-8.66c.44-1.01.13-1.54-.09-1.76s-.77-.55-1.83-.11a10.318 10.318 0 00-6.32 10.21 10.475 10.475 0 007.04 8.99 10 10 0 002.89.55c.16.01.32.02.48.02a10.5 10.5 0 008.47-4.27c.67-.93.49-1.519.32-1.79z"
      fill="currentColor"
    />
  </svg>
);

export const SunFilledIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    aria-hidden="true"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <g fill="currentColor">
      <path d="M19 12a7 7 0 11-7-7 7 7 0 017 7z" />
      <path d="M12 22.96a.969.969 0 01-1-.96v-.08a1 1 0 012 0 1.038 1.038 0 01-1 1.04zm7.14-2.82a1.024 1.024 0 01-.71-.29l-.13-.13a1 1 0 011.41-1.41l.13.13a1 1 0 010 1.41.984.984 0 01-.7.29zm-14.28 0a1.024 1.024 0 01-.71-.29 1 1 0 010-1.41l.13-.13a1 1 0 011.41 1.41l-.13.13a1 1 0 01-.7.29zM22 13h-.08a1 1 0 010-2 1.038 1.038 0 011.04 1 .969.969 0 01-.96 1zM2.08 13H2a1 1 0 010-2 1.038 1.038 0 011.04 1 .969.969 0 01-.96 1zm16.93-7.01a1.024 1.024 0 01-.71-.29 1 1 0 010-1.41l.13-.13a1 1 0 011.41 1.41l-.13.13a.984.984 0 01-.7.29zm-14.02 0a1.024 1.024 0 01-.71-.29l-.13-.14a1 1 0 011.41-1.41l.13.13a1 1 0 010 1.41.97.97 0 01-.7.3zM12 3.04a.969.969 0 01-1-.96V2a1 1 0 012 0 1.038 1.038 0 01-1 1.04z" />
    </g>
  </svg>
);

export const SearchIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    aria-hidden="true"
    fill="none"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <path
      d="M11.5 21C16.7467 21 21 16.7467 21 11.5C21 6.25329 16.7467 2 11.5 2C6.25329 2 2 6.25329 2 11.5C2 16.7467 6.25329 21 11.5 21Z"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="2"
    />
    <path
      d="M22 22L20 20"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="2"
    />
  </svg>
);

export const ChevronDownIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  strokeWidth = 1.5,
  ...props
}) => (
  <svg
    aria-hidden="true"
    fill="none"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <path
      d="M19.92 8.95l-6.52 6.52c-.77.77-2.03.77-2.8 0L4.08 8.95"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeMiterlimit={10}
      strokeWidth={strokeWidth}
    />
  </svg>
);

export const PlusIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    aria-hidden="true"
    fill="none"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <g
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.5}
    >
      <path d="M6 12h12" />
      <path d="M12 18V6" />
    </g>
  </svg>
);

export const VerticalDotsIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    aria-hidden="true"
    fill="none"
    focusable="false"
    height={size || height}
    role="presentation"
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <g fill="currentColor">
      <path d="M12 10c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zM12 4c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zM12 16c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z" />
    </g>
  </svg>
);
export const WifiIcon: React.FC<IconSvgProps> = ({
  size = 24,
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
    viewBox="0 0 48 48"
    width={size || width}
    {...props}
  >
    <g fill="none">
      <path
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="4"
        d="M4 18.965a29.355 29.355 0 0 1 1.817-1.586C17.037 8.374 33.382 8.903 44 18.965"
      />
      <path
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="4"
        d="M38 25.799c-7.732-7.732-20.268-7.732-28 0m22 6.515c-4.418-4.419-11.582-4.419-16 0"
      />
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M24 40a2.5 2.5 0 1 0 0-5a2.5 2.5 0 0 0 0 5"
        clipRule="evenodd"
      />
    </g>
  </svg>
);

export const WifiOffIcon: React.FC<IconSvgProps> = ({
  size = 24,
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
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <path
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="2"
      d="M17.85 11.544a8 8 0 0 0-2.88-1.972m5.806-.756a12 12 0 0 0-9.488-3.795m-2.945 9.57a5 5 0 0 1 4.902-1.434m-7.096-1.613A8 8 0 0 1 9.623 9.36m-6.4-.545a12 12 0 0 1 3.11-2.393M4.413 4l14.142 14.142M12 19a1 1 0 1 1 0-2a1 1 0 0 1 0 2"
    />
  </svg>
);

export const WifiPendingIcon: React.FC<IconSvgProps> = ({
  size = 24,
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
    viewBox="0 0 24 24"
    width={size || width}
    {...props}
  >
    <path
      fill="currentColor"
      d="M22.59 10.39L24 8.98A16.88 16.88 0 0 0 12 4C7.31 4 3.07 5.9 0 8.98L12 21l1.41-1.42L2.93 9.08C5.45 7.16 8.59 6 12 6c4.13 0 7.88 1.68 10.59 4.39"
    />
    <path
      fill="currentColor"
      d="m23 18.59-2.56-2.56c.35-.59.56-1.28.56-2.03c0-2.24-1.76-4-4-4s-4 1.76-4 4s1.76 4 4 4c.75 0 1.44-.21 2.03-.56L21.59 20zM15 14c0-1.12.88-2 2-2s2 .88 2 2s-.88 2-2 2s-2-.88-2-2"
    />
    <path
      fill="currentColor"
      d="M22.59 10.39A14.943 14.943 0 0 0 12 6C8.59 6 5.45 7.16 2.93 9.08l2.26 2.26l8.24 8.24l.46-.46C12.15 18.09 11 16.21 11 14c0-1.62.62-3.13 1.75-4.25S15.38 8 17 8c2.21 0 4.09 1.15 5.13 2.89l.49-.49l-.02-.02z"
      opacity="0.3"
    />
  </svg>
);

export const RocketIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size || width}
      height={size || height}
      viewBox="0 0 24 24"
      {...props}
    >
      <path
        fill="currentColor"
        d="m5.65 10.025l1.95.825q.35-.7.725-1.35t.825-1.3l-1.4-.275zM9.2 12.1l2.85 2.825q1.05-.4 2.25-1.225t2.25-1.875q1.75-1.75 2.738-3.887T20.15 4q-1.8-.125-3.95.863T12.3 7.6q-1.05 1.05-1.875 2.25T9.2 12.1m4.45-1.625q-.575-.575-.575-1.412t.575-1.413t1.425-.575t1.425.575t.575 1.413t-.575 1.412t-1.425.575t-1.425-.575m.475 8.025l2.1-2.1l-.275-1.4q-.65.45-1.3.812t-1.35.713zM21.95 2.175q.475 3.025-.587 5.888T17.7 13.525L18.2 16q.1.5-.05.975t-.5.825l-4.2 4.2l-2.1-4.925L7.075 12.8L2.15 10.7l4.175-4.2q.35-.35.838-.5t.987-.05l2.475.5q2.6-2.6 5.45-3.675t5.875-.6m-18.025 13.8q.875-.875 2.138-.887t2.137.862t.863 2.138t-.888 2.137q-.625.625-2.087 1.075t-4.038.8q.35-2.575.8-4.038t1.075-2.087m1.425 1.4q-.25.25-.5.913t-.35 1.337q.675-.1 1.338-.337t.912-.488q.3-.3.325-.725T6.8 17.35t-.725-.288t-.725.313"
      />
    </svg>
  );
};
