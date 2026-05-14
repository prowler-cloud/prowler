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

export const DeleteIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 48}
      viewBox="0 0 24 24"
      width={size || width || 48}
      aria-hidden="true"
      {...props}
    >
      <g fill="none">
        <path d="m12.593 23.258-.011.002-.071.035-.02.004-.014-.004-.071-.035q-.016-.005-.024.005l-.004.01-.017.428.005.02.01.013.104.074.015.004.012-.004.104-.074.012-.016.004-.017-.017-.427q-.004-.016-.017-.018m.265-.113-.013.002-.185.093-.01.01-.003.011.018.43.005.012.008.007.201.093q.019.005.029-.008l.004-.014-.034-.614q-.005-.018-.02-.022m-.715.002a.02.02 0 0 0-.027.006l-.006.014-.034.614q.001.018.017.024l.015-.002.201-.093.01-.008.004-.011.017-.43-.003-.012-.01-.01z" />
        <path
          fill="currentColor"
          d="M14.28 2a2 2 0 0 1 1.897 1.368L16.72 5H20a1 1 0 1 1 0 2l-.003.071-.867 12.143A3 3 0 0 1 16.138 22H7.862a3 3 0 0 1-2.992-2.786L4.003 7.07 4 7a1 1 0 0 1 0-2h3.28l.543-1.632A2 2 0 0 1 9.721 2zm3.717 5H6.003l.862 12.071a1 1 0 0 0 .997.929h8.276a1 1 0 0 0 .997-.929zM10 10a1 1 0 0 1 .993.883L11 11v5a1 1 0 0 1-1.993.117L9 16v-5a1 1 0 0 1 1-1m4 0a1 1 0 0 1 1 1v5a1 1 0 1 1-2 0v-5a1 1 0 0 1 1-1m.28-6H9.72l-.333 1h5.226z"
        />
      </g>
    </svg>
  );
};

export const CheckIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || width}
    height={size || height}
    viewBox="0 0 2048 2048"
    {...props}
  >
    <path
      fill="currentColor"
      d="M2048 1024q0 142-36 272t-103 245t-160 207t-208 160t-245 103t-272 37q-142 0-272-36t-245-103t-207-160t-160-208t-103-245t-37-272q0-141 36-272t103-245t160-207t208-160T752 37t272-37q141 0 272 36t245 103t207 160t160 208t103 245t37 272m-1024 896q123 0 237-32t214-90t182-141t140-181t91-214t32-238q0-123-32-237t-90-214t-141-182t-181-140t-214-91t-238-32q-124 0-238 32t-213 90t-182 141t-140 181t-91 214t-32 238q0 124 32 238t90 213t141 182t181 140t214 91t238 32m0-512q55 0 107-15t98-45t81-69t61-91l116 56q-32 67-80 121t-109 92t-130 58t-144 21q-110 0-210-45t-174-128v173H512v-384h384v128H738q54 60 129 94t157 34m384-723V512h128v384h-384V768h158q-54-60-129-94t-157-34q-55 0-107 15t-98 45t-81 69t-61 91l-116-56q32-67 80-121t109-92t130-58t144-21q110 0 210 45t174 128"
    />
  </svg>
);

export const CrossIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || width}
    height={size || height}
    viewBox="0 0 24 24"
    {...props}
  >
    <path
      fill="currentColor"
      d="M16.066 8.995a.75.75 0 1 0-1.06-1.061L12 10.939L8.995 7.934a.75.75 0 1 0-1.06 1.06L10.938 12l-3.005 3.005a.75.75 0 0 0 1.06 1.06L12 13.06l3.005 3.006a.75.75 0 0 0 1.06-1.06L13.062 12z"
    />
  </svg>
);

export const PassIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || width}
    height={size || height}
    viewBox="0 0 16 16"
    {...props}
  >
    <g fill="currentColor">
      <path d="M6.27 10.87h.71l4.56-4.56l-.71-.71l-4.2 4.21l-1.92-1.92L4 8.6z" />
      <path
        fillRule="evenodd"
        d="M8.6 1c1.6.1 3.1.9 4.2 2c1.3 1.4 2 3.1 2 5.1c0 1.6-.6 3.1-1.6 4.4c-1 1.2-2.4 2.1-4 2.4s-3.2.1-4.6-.7s-2.5-2-3.1-3.5S.8 7.5 1.3 6c.5-1.6 1.4-2.9 2.8-3.8C5.4 1.3 7 .9 8.6 1m.5 12.9c1.3-.3 2.5-1 3.4-2.1c.8-1.1 1.3-2.4 1.2-3.8c0-1.6-.6-3.2-1.7-4.3c-1-1-2.2-1.6-3.6-1.7c-1.3-.1-2.7.2-3.8 1S2.7 4.9 2.3 6.3c-.4 1.3-.4 2.7.2 4q.9 1.95 2.7 3c1.2.7 2.6.9 3.9.6"
        clipRule="evenodd"
      />
    </g>
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

export const AlertIcon: React.FC<IconSvgProps> = ({
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
    <g fill="none">
      <path d="M24 0v24H0V0zM12.593 23.258l-.011.002l-.071.035l-.02.004l-.014-.004l-.071-.035q-.016-.005-.024.005l-.004.01l-.017.428l.005.02l.01.013l.104.074l.015.004l.012-.004l.104-.074l.012-.016l.004-.017l-.017-.427q-.004-.016-.017-.018m.265-.113l-.013.002l-.185.093l-.01.01l-.003.011l.018.43l.005.012l.008.007l.201.093q.019.005.029-.008l.004-.014l-.034-.614q-.005-.019-.02-.022m-.715.002a.02.02 0 0 0-.027.006l-.006.014l-.034.614q.001.018.017.024l.015-.002l.201-.093l.01-.008l.004-.011l.017-.43l-.003-.012l-.01-.01z" />
      <path
        fill="currentColor"
        d="m13.299 3.148l8.634 14.954a1.5 1.5 0 0 1-1.299 2.25H3.366a1.5 1.5 0 0 1-1.299-2.25l8.634-14.954c.577-1 2.02-1 2.598 0M12 4.898L4.232 18.352h15.536zM12 15a1 1 0 1 1 0 2a1 1 0 0 1 0-2m0-7a1 1 0 0 1 1 1v4a1 1 0 1 1-2 0V9a1 1 0 0 1 1-1"
      />
    </g>
  </svg>
);

export const NotificationIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    fill="none"
    height={size || height || 24}
    viewBox="0 0 24 24"
    width={size || width || 24}
    xmlns="http://www.w3.org/2000/svg"
    {...props}
  >
    <path
      clipRule="evenodd"
      d="M18.707 8.796c0 1.256.332 1.997 1.063 2.85.553.628.73 1.435.73 2.31 0 .874-.287 1.704-.863 2.378a4.537 4.537 0 01-2.9 1.413c-1.571.134-3.143.247-4.736.247-1.595 0-3.166-.068-4.737-.247a4.532 4.532 0 01-2.9-1.413 3.616 3.616 0 01-.864-2.378c0-.875.178-1.682.73-2.31.754-.854 1.064-1.594 1.064-2.85V8.37c0-1.682.42-2.781 1.283-3.858C7.861 2.942 9.919 2 11.956 2h.09c2.08 0 4.204.987 5.466 2.625.82 1.054 1.195 2.108 1.195 3.745v.426zM9.074 20.061c0-.504.462-.734.89-.833.5-.106 3.545-.106 4.045 0 .428.099.89.33.89.833-.025.48-.306.904-.695 1.174a3.635 3.635 0 01-1.713.731 3.795 3.795 0 01-1.008 0 3.618 3.618 0 01-1.714-.732c-.39-.269-.67-.694-.695-1.173z"
      fill="currentColor"
      fillRule="evenodd"
    />
  </svg>
);

export const IdIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    fill="currentColor"
    height={size || height || 24}
    viewBox="0 0 24 24"
    width={size || width || 24}
    {...props}
  >
    <path d="M18 4v16H6V8.8L10.8 4zm0-2h-8L4 8v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2M9.5 19h-2v-2h2zm7 0h-2v-2h2zm-7-4h-2v-4h2zm3.5 4h-2v-4h2zm0-6h-2v-2h2zm3.5 2h-2v-4h2z" />
  </svg>
);

export const DoneIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      width={size || width || 24}
      height={size || height || 24}
      viewBox="0 0 24 24"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      {...props}
    >
      <path d="m2.394 13.742 4.743 3.62 7.616-8.704-1.506-1.316-6.384 7.296-3.257-2.486zm19.359-5.084-1.506-1.316-6.369 7.279-.753-.602-1.25 1.562 2.247 1.798z" />
    </svg>
  );
};

export const CopyIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      fill="none"
      height={size || height || 20}
      shapeRendering="geometricPrecision"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.5"
      viewBox="0 0 24 24"
      width={size || width || 20}
      {...props}
    >
      <path d="M6 17C4.89543 17 4 16.1046 4 15V5C4 3.89543 4.89543 3 6 3H13C13.7403 3 14.3866 3.4022 14.7324 4M11 21H18C19.1046 21 20 20.1046 20 19V9C20 7.89543 19.1046 7 18 7H11C9.89543 7 9 7.89543 9 9V19C9 20.1046 9.89543 21 11 21Z" />
    </svg>
  );
};

export const FlowIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 20}
      viewBox="0 0 20 20"
      width={size || width || 20}
      {...props}
    >
      <path
        fill="currentColor"
        d="M16.4 4a2.4 2.4 0 1 0-4.8 0c0 .961.568 1.784 1.384 2.167c-.082 1.584-1.27 2.122-3.335 2.896c-.87.327-1.829.689-2.649 1.234V6.176A2.396 2.396 0 0 0 6 1.6a2.397 2.397 0 0 0-1 4.576v7.649A2.39 2.39 0 0 0 3.6 16a2.4 2.4 0 1 0 4.8 0c0-.961-.568-1.784-1.384-2.167c.082-1.583 1.271-2.122 3.335-2.896c2.03-.762 4.541-1.711 4.64-4.756A2.4 2.4 0 0 0 16.4 4M6 2.615a1.384 1.384 0 1 1 0 2.768a1.384 1.384 0 0 1 0-2.768m0 14.77a1.385 1.385 0 1 1 0-2.77a1.385 1.385 0 0 1 0 2.77m8-12a1.385 1.385 0 1 1 0-2.77a1.385 1.385 0 0 1 0 2.77"
      />
    </svg>
  );
};

export const ConnectionIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 20}
      viewBox="0 0 20 20"
      width={size || width || 20}
      {...props}
    >
      <path
        fill="currentColor"
        d="M18 14.824V12.5A3.5 3.5 0 0 0 14.5 9h-2A1.5 1.5 0 0 1 11 7.5V5.176A2.4 2.4 0 0 0 12.4 3a2.4 2.4 0 1 0-4.8 0c0 .967.576 1.796 1.4 2.176V7.5A1.5 1.5 0 0 1 7.5 9h-2A3.5 3.5 0 0 0 2 12.5v2.324A2.396 2.396 0 0 0 3 19.4a2.397 2.397 0 0 0 1-4.576V12.5A1.5 1.5 0 0 1 5.5 11h2c.539 0 1.044-.132 1.5-.35v4.174a2.396 2.396 0 0 0 1 4.576a2.397 2.397 0 0 0 1-4.576V10.65c.456.218.961.35 1.5.35h2a1.5 1.5 0 0 1 1.5 1.5v2.324A2.4 2.4 0 0 0 14.6 17a2.4 2.4 0 1 0 4.8 0c0-.967-.575-1.796-1.4-2.176M10 1.615a1.384 1.384 0 1 1 0 2.768a1.384 1.384 0 0 1 0-2.768m-7 16.77a1.385 1.385 0 1 1 0-2.77a1.385 1.385 0 0 1 0 2.77m7 0a1.385 1.385 0 1 1 0-2.77a1.385 1.385 0 0 1 0 2.77m7 0a1.385 1.385 0 1 1 0-2.77a1.385 1.385 0 0 1 0 2.77"
      />
    </svg>
  );
};

export const ConnectionTrue: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    fill="none"
    stroke="currentColor"
    strokeLinecap="round"
    strokeLinejoin="round"
    strokeWidth="1.5"
    height={size || height || 24}
    viewBox="0 0 24 24"
    width={size || width || 24}
    {...props}
  >
    <path
      d="M12 20h.012M8.25 17c2-2 5.5-2 7.5 0m2.75-3c-3.768-3.333-9-3.333-13 0M2 11c3.158-2.667 6.579-4 10-4m3 .5s1 0 2 2c0 0 2.477-3.9 5-5.5"
      color="currentColor"
    />
  </svg>
);

export const ConnectionFalse: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    fill="none"
    stroke="currentColor"
    strokeLinecap="round"
    strokeLinejoin="round"
    strokeWidth="1.5"
    height={size || height || 24}
    viewBox="0 0 24 24"
    width={size || width || 24}
    {...props}
  >
    <path
      d="M12 18h.012M8.25 15c2-2 5.5-2 7.5 0m2.75-3a11 11 0 0 0-.231-.199M5.5 12c2.564-2.136 5.634-2.904 8.5-2.301M2 9c3.466-2.927 7.248-4.247 11-3.962M22 5l-6 6m6 0-6-6"
      color="currentColor"
    />
  </svg>
);

export const ConnectionPending: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.05"
    height={size || height || 24}
    viewBox="0 0 24 24"
    width={size || width || 24}
    {...props}
  >
    <g fill="none" stroke="currentColor" strokeWidth="1.05">
      <circle cx="12" cy="18" r="2" />
      <path strokeOpacity=".2" d="M7.757 13.757a6 6 0 0 1 8.486 0" />
      <path
        strokeOpacity=".2"
        d="M4.929 10.93c3.905-3.905 10.237-3.905 14.142 0"
        opacity=".8"
      />
      <path
        strokeOpacity=".2"
        d="M2.101 8.1c5.467-5.468 14.331-5.468 19.798 0"
        opacity=".8"
      />
    </g>
  </svg>
);

export const SuccessIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    width={size || width || 24}
    height={size || height || 24}
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    {...props}
  >
    <path
      d="M12 2C6.49 2 2 6.49 2 12C2 17.51 6.49 22 12 22C17.51 22 22 17.51 22 12C22 6.49 17.51 2 12 2ZM16.78 9.7L11.11 15.37C10.97 15.51 10.78 15.59 10.58 15.59C10.38 15.59 10.19 15.51 10.05 15.37L7.22 12.54C6.93 12.25 6.93 11.77 7.22 11.48C7.51 11.19 7.99 11.19 8.28 11.48L10.58 13.78L15.72 8.64C16.01 8.35 16.49 8.35 16.78 8.64C17.07 8.93 17.07 9.4 16.78 9.7Z"
      fill="currentColor"
    />
  </svg>
);

export const ArrowUpIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || "1em"}
      viewBox="0 0 12 12"
      width={size || width || "1em"}
      aria-hidden="true"
      focusable="false"
      role="presentation"
      {...props}
    >
      <path
        d="M3 7.5L6 4.5L9 7.5"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.5"
      />
    </svg>
  );
};

export const ArrowDownIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || "1em"}
      viewBox="0 0 12 12"
      width={size || width || "1em"}
      aria-hidden="true"
      focusable="false"
      role="presentation"
      {...props}
    >
      <path
        d="M3 4.5L6 7.5L9 4.5"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.5"
      />
    </svg>
  );
};

export const ChevronsLeftRightIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 24}
      viewBox="0 0 24 24"
      width={size || width || 24}
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="lucide lucide-chevrons-left-right ml-2 h-4 w-4 rotate-90"
      {...props}
    >
      <path d="m9 7-5 5 5 5M15 7l5 5-5 5" />
    </svg>
  );
};

export const PlusCircleIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 15}
      viewBox="0 0 15 15"
      width={size || width || 15}
      className="mr-2 size-4"
      {...props}
    >
      <path
        d="M7.5.877a6.623 6.623 0 1 0 0 13.246A6.623 6.623 0 0 0 7.5.877ZM1.827 7.5a5.673 5.673 0 1 1 11.346 0 5.673 5.673 0 0 1-11.346 0ZM7.5 4a.5.5 0 0 1 .5.5V7h2.5a.5.5 0 1 1 0 1H8v2.5a.5.5 0 0 1-1 0V8H4.5a.5.5 0 0 1 0-1H7V4.5a.5.5 0 0 1 .5-.5Z"
        fill="currentColor"
        fillRule="evenodd"
        clipRule="evenodd"
      />
    </svg>
  );
};

export const CustomFilterIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      height={size || height || 16}
      width={size || width || 16}
      viewBox="0 0 24 24"
      {...props}
    >
      <g fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M9.5 14a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm5-10a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z" />
        <path strokeLinecap="round" d="M15 16.959h7m-13-10H2m0 10h2m18-10h-2" />
      </g>
    </svg>
  );
};

export const SaveIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 48}
      viewBox="0 0 24 24"
      width={size || width || 48}
      aria-hidden="true"
      {...props}
    >
      <path
        d="m20.71 9.29l-6-6a1 1 0 0 0-.32-.21A1.1 1.1 0 0 0 14 3H6a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3v-8a1 1 0 0 0-.29-.71M9 5h4v2H9Zm6 14H9v-3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1Zm4-1a1 1 0 0 1-1 1h-1v-3a3 3 0 0 0-3-3h-4a3 3 0 0 0-3 3v3H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h1v3a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V6.41l4 4Z"
        fill="currentColor"
      />
    </svg>
  );
};

export const AddIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 20}
      viewBox="0 0 24 24"
      width={size || width || 20}
      aria-hidden="true"
      {...props}
    >
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10m.75-13a.75.75 0 0 0-1.5 0v2.25H9a.75.75 0 0 0 0 1.5h2.25V15a.75.75 0 0 0 1.5 0v-2.25H15a.75.75 0 0 0 0-1.5h-2.25z"
        clipRule="evenodd"
      />
    </svg>
  );
};

export const ScheduleIcon: React.FC<IconSvgProps> = ({
  size = 24,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size || width}
      height={size || height}
      viewBox="0 0 24 24" // <- AÑADÍ ESTO
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      <path d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h3.5" />
      <path d="M16 2v4M8 2v4M3 10h5" />
      <path d="M17.5 17.5L16 16.3V14" />
      <circle cx="16" cy="16" r="6" />
    </svg>
  );
};

export const InfoIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || width}
    height={size || height}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeLinecap="round"
    strokeLinejoin="round"
    strokeWidth="2"
    {...props}
  >
    <circle cx="12" cy="12" r="10" />
    <path d="M12 16v-4M12 8h.01" />
  </svg>
);

export const ManualIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || width}
    height={size || height}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    {...props}
  >
    <circle cx="12" cy="12" r="10" />
    <polygon points="10 8 16 12 10 16 10 8" />
  </svg>
);

export const SpinnerIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  className,
  ...props
}) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || width}
    height={size || height}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeLinecap="round"
    strokeLinejoin="round"
    strokeWidth="2"
    className={className}
    {...props}
  >
    <path d="M20 4v5h-.582m0 0a8.001 8.001 0 00-15.356 2m15.356-2H15M4 20v-5h.581m0 0a8.003 8.003 0 0015.357-2M4.581 15H9" />
  </svg>
);

export const DocIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M14 3v4a1 1 0 0 0 1 1h4" />
      <path d="M5 12V5a2 2 0 0 1 2-2h7l5 5v4" />
      <path d="M5 15v6h1a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2z" />
      <path d="M20 16.5a1.5 1.5 0 0 0-3 0v3a1.5 1.5 0 0 0 3 0" />
      <path d="M12.5 15a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-3 0v-3a1.5 1.5 0 0 1 1.5-1.5" />
    </svg>
  );
};

export const APIdocIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M4 13h5m3 3V8h3a2 2 0 0 1 2 2v1a2 2 0 0 1-2 2h-3m8-5v8M9 16v-5.5a2.5 2.5 0 0 0-5 0V16" />
    </svg>
  );
};

export const SupportIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 7h.01" strokeLinecap="round" />
      <path
        d="M10 11h2v5m-2 0h4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};

export const CircleHelpIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
      <path d="M12 17h.01" />
    </svg>
  );
};

export const AWSIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="currentColor"
      {...props}
    >
      <path d="M15.626 14.62c-1.107 1.619-2.728 2.384-4.625 2.384c-2.304 0-4.277-1.773-3.993-4.124c.314-2.608 2.34-3.73 5.708-4.143c.601-.073.85-.094 2.147-.19l.138-.01v-.215C15 6.526 13.933 5.3 12.5 5.3c-1.437 0-2.44.747-3.055 2.526l-1.89-.652C8.442 4.604 10.193 3.3 12.5 3.3c2.602 0 4.5 2.178 4.5 5.022c0 2.649.163 4.756.483 5.557c.356.893.486 1.117.884 1.613l-1.56 1.251c-.524-.652-.753-1.048-1.182-2.122m5.631 5.925c-.27.2-.741.081-.528-.44c.264-.648.547-1.408.262-1.752c-.21-.255-.468-.382-1.027-.382c-.46 0-.69.06-.995.08c-.204.014-.294-.297-.091-.44c.261-.185.544-.33.87-.428c1.15-.344 2.505-.155 2.67.083c.365.53-.2 2.569-1.16 3.28m-1.182-1.084a8 8 0 0 1-.829.695c-2.122 1.616-4.871 2.46-7.258 2.46c-3.843 0-7.28-1.793-9.888-4.795c-.224-.23-.039-.566.223-.384c2.81 2.077 6.288 3.333 9.888 3.333c2.266 0 4.708-.537 7.035-1.692c.163-.077.345-.182.504-.255c.367-.21.69.306.325.638m-5.064-8.92c-1.259.094-1.496.113-2.052.181c-2.553.313-3.797 1.003-3.966 2.398c-.125 1.043.81 1.884 2.008 1.884c2.039 0 3.517-1.228 4.022-4.463z" />
    </svg>
  );
};

export const AzureIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 16 16"
      width={size || width}
      height={size || height}
      fill="currentColor"
      {...props}
    >
      <path
        fillRule="evenodd"
        d="m15.37 13.68l-4-12a1 1 0 0 0-1-.68H5.63a1 1 0 0 0-.95.68l-4.05 12a1 1 0 0 0 1 1.32h2.93a1 1 0 0 0 .94-.68l.61-1.78l3 2.27a1 1 0 0 0 .6.19h4.68a1 1 0 0 0 .98-1.32m-5.62.66a.32.32 0 0 1-.2-.07L3.9 10.08l-.09-.07h3l.08-.21l1-2.53l2.24 6.63a.34.34 0 0 1-.38.44m4.67 0H10.7a1 1 0 0 0 0-.66l-4.05-12h3.72a.34.34 0 0 1 .32.23l4.05 12a.34.34 0 0 1-.32.43"
        clipRule="evenodd"
      />
    </svg>
  );
};

export const M365Icon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  strokeWidth = 2,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size || width}
      height={size || height}
      viewBox="0 0 48 48"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      {...props}
    >
      <path
        strokeLinejoin="round"
        d="M20.507 3.241L8.443 9.74a8.6 8.6 0 0 0-4.508 7.563V30.7a8.6 8.6 0 0 0 4.508 7.564m15.668-5.597l-2.826-1.557a8.6 8.6 0 0 1-4.45-7.532v-4.072"
        strokeWidth={strokeWidth}
      ></path>
      <path
        strokeLinejoin="round"
        d="M31.166 19.275v4.45a8.6 8.6 0 0 1-4.508 7.564l-11.466 6.202a8.6 8.6 0 0 1-7.435.358q.33.222.687.414l11.465 6.202a8.6 8.6 0 0 0 8.182 0l11.465-6.202a8.6 8.6 0 0 0 4.508-7.563"
        strokeWidth={strokeWidth}
      ></path>
      <path
        strokeLinejoin="round"
        d="M39.557 9.739L28.092 3.536a8.6 8.6 0 0 0-7.585-.295a8.6 8.6 0 0 0-3.673 7.048v8.986l3.288-1.661a8.6 8.6 0 0 1 7.756 0l11.465 5.793a8.6 8.6 0 0 1 4.72 7.484l.001-.191V17.302a8.6 8.6 0 0 0-4.507-7.563"
        strokeWidth={strokeWidth}
      ></path>
    </svg>
  );
};

export const GCPIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="currentColor"
      {...props}
    >
      <path d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0c-3.875 2.551-3.922 8.11-.247 10.941l.006-.007l-.007.03a6.7 6.7 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.37 9.37 0 0 0-2.821-4.552l-.043.043l.006-.05A9.34 9.34 0 0 0 12.19 2.38m-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.19 5.19 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.6 2.6 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.75 6.75 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.2 5.2 0 0 1 3.67-1.69z" />
    </svg>
  );
};

export const MutedIcon: React.FC<IconSvgProps> = ({
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      height={size || height || 24}
      width={size || width || 24}
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      <path d="M10.268 21a2 2 0 0 0 3.464 0" />
      <path d="M17 17H4a1 1 0 0 1-.74-1.673C4.59 13.956 6 12.499 6 8a6 6 0 0 1 .258-1.742" />
      <path d="m2 2 20 20" />
      <path d="M8.668 3.01A6 6 0 0 1 18 8c0 2.687.77 4.653 1.707 6.05" />
    </svg>
  );
};

export const KubernetesIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
      width={size || width}
      height={size || height}
      fill="currentColor"
      {...props}
    >
      <path
        fill="currentColor"
        d="m29.223 17.964l-3.304-.754a9.78 9.78 0 0 0-1.525-6.624l2.54-2.026l-1.247-1.564l-2.539 2.024A9.97 9.97 0 0 0 17 6.05V3h-2v3.05a9.97 9.97 0 0 0-6.148 2.97l-2.54-2.024L5.066 8.56l2.54 2.025a9.78 9.78 0 0 0-1.524 6.625l-3.304.754l.446 1.95l3.297-.753a10.04 10.04 0 0 0 4.269 5.358l-1.33 2.763l1.802.867l1.329-2.76a9.8 9.8 0 0 0 6.82 0l1.33 2.76l1.802-.868l-1.33-2.762a10.04 10.04 0 0 0 4.269-5.358l3.297.752ZM24 16q-.002.385-.039.763l-5-1.142a3 3 0 0 0-.137-.594l3.996-3.187A7.94 7.94 0 0 1 24 16m-9 0a1 1 0 1 1 1 1a1 1 0 0 1-1-1m6.576-5.726l-3.996 3.187a3 3 0 0 0-.58-.277V8.07a7.98 7.98 0 0 1 4.576 2.205M15 8.07v5.115a3 3 0 0 0-.58.277l-3.996-3.187A7.98 7.98 0 0 1 15 8.07M8 16a7.94 7.94 0 0 1 1.18-4.16l3.996 3.187a3 3 0 0 0-.137.594l-5 1.141A8 8 0 0 1 8 16m.484 2.712l4.975-1.136a3 3 0 0 0 .414.537L11.66 22.71a8.03 8.03 0 0 1-3.176-3.998M16 24a8 8 0 0 1-2.54-.42l2.22-4.612A3 3 0 0 0 16 19a3 3 0 0 0 .319-.032l2.221 4.612A8 8 0 0 1 16 24m4.34-1.29l-2.213-4.598a3 3 0 0 0 .414-.536l4.976 1.136a8.03 8.03 0 0 1-3.176 3.998"
      />
    </svg>
  );
};

export const LighthouseIcon: React.FC<IconSvgProps> = ({
  size = 19,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={width || size}
      height={height || size}
      viewBox="0 0 19 18"
      fill="none"
      {...props}
    >
      <path
        d="M16.792 11.6488H17.2955L17.4214 12.404L18.0508 12.6557L17.4214 13.0333L17.2955 13.6627H16.792V11.6488Z"
        fill="url(#paint0_linear_10004_99259)"
      />
      <path
        d="M17.295 11.6488H16.7915L16.6657 12.404L15.7845 12.5299L16.6657 13.0333L16.7915 13.6627H17.295V11.6488Z"
        fill="url(#paint1_linear_10004_99259)"
      />
      <path
        d="M16.6985 13.1295C16.6854 13.0787 16.6589 13.0323 16.6218 12.9952C16.5847 12.9581 16.5383 12.9316 16.4875 12.9185L15.5865 12.6862C15.5711 12.6818 15.5576 12.6725 15.548 12.6598C15.5384 12.647 15.5331 12.6315 15.5331 12.6155C15.5331 12.5995 15.5384 12.584 15.548 12.5713C15.5576 12.5585 15.5711 12.5493 15.5865 12.5449L16.4875 12.3124C16.5383 12.2993 16.5847 12.2729 16.6218 12.2358C16.6589 12.1987 16.6854 12.1524 16.6985 12.1016L16.9309 11.2007C16.9352 11.1852 16.9444 11.1716 16.9572 11.162C16.97 11.1523 16.9855 11.147 17.0016 11.147C17.0176 11.147 17.0332 11.1523 17.0459 11.162C17.0587 11.1716 17.068 11.1852 17.0723 11.2007L17.3045 12.1016C17.3176 12.1524 17.3441 12.1988 17.3812 12.2359C17.4183 12.273 17.4647 12.2995 17.5155 12.3126L18.4165 12.5447C18.432 12.549 18.4456 12.5583 18.4554 12.571C18.4651 12.5838 18.4704 12.5995 18.4704 12.6155C18.4704 12.6316 18.4651 12.6472 18.4554 12.66C18.4456 12.6728 18.432 12.682 18.4165 12.6863L17.5155 12.9185C17.4647 12.9316 17.4183 12.9581 17.3812 12.9952C17.3441 13.0323 17.3176 13.0787 17.3045 13.1295L17.0721 14.0304C17.0678 14.0458 17.0586 14.0594 17.0458 14.0691C17.033 14.0788 17.0174 14.084 17.0014 14.084C16.9854 14.084 16.9698 14.0788 16.957 14.0691C16.9443 14.0594 16.935 14.0458 16.9307 14.0304L16.6985 13.1295Z"
        stroke="url(#paint2_linear_10004_99259)"
        strokeWidth="0.643499"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M2.31079 4.89459H3.04694L3.23098 5.99873L4.15116 6.36677L3.23098 6.91884L3.04694 7.83895H2.31079V4.89459Z"
        fill="url(#paint3_linear_10004_99259)"
      />
      <path
        d="M3.04706 4.89459H2.31091L2.12687 5.99873L0.838614 6.18275L2.12687 6.91884L2.31091 7.83895H3.04706V4.89459Z"
        fill="url(#paint4_linear_10004_99259)"
      />
      <path
        d="M2.17422 7.05874C2.15505 6.98444 2.11632 6.91664 2.06206 6.86238C2.0078 6.80812 1.93999 6.7694 1.86568 6.75023L0.54844 6.41059C0.525966 6.40421 0.506187 6.39067 0.492102 6.37204C0.478018 6.3534 0.470398 6.33068 0.470398 6.30732C0.470398 6.28396 0.478018 6.26124 0.492102 6.2426C0.506187 6.22396 0.525966 6.21043 0.54844 6.20405L1.86568 5.86419C1.93996 5.84504 2.00776 5.80635 2.06202 5.75213C2.11628 5.69792 2.15502 5.63015 2.17422 5.5559L2.51389 4.23876C2.52021 4.2162 2.53373 4.19632 2.5524 4.18216C2.57106 4.168 2.59385 4.16034 2.61728 4.16034C2.64071 4.16034 2.66349 4.168 2.68216 4.18216C2.70082 4.19632 2.71435 4.2162 2.72066 4.23876L3.06012 5.5559C3.07928 5.63019 3.11801 5.698 3.17228 5.75226C3.22654 5.80651 3.29435 5.84524 3.36865 5.86441L4.6859 6.20384C4.70855 6.21009 4.72853 6.22359 4.74276 6.24228C4.757 6.26098 4.76471 6.28382 4.76471 6.30732C4.76471 6.33082 4.757 6.35366 4.74276 6.37235C4.72853 6.39105 4.70855 6.40455 4.6859 6.4108L3.36865 6.75023C3.29435 6.7694 3.22654 6.80812 3.17228 6.86238C3.11801 6.91664 3.07928 6.98444 3.06012 7.05874L2.72044 8.37588C2.71413 8.39844 2.70061 8.41832 2.68194 8.43248C2.66328 8.44664 2.64049 8.4543 2.61706 8.4543C2.59363 8.4543 2.57085 8.44664 2.55218 8.43248C2.53351 8.41832 2.51999 8.39844 2.51368 8.37588L2.17422 7.05874Z"
        stroke="url(#paint5_linear_10004_99259)"
        strokeWidth="0.940817"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M7.42609 2.81921C11.9573 2.81921 13.3237 2.85331 13.7679 2.97546C16.3331 3.65291 18.0099 6.18425 17.5882 8.73816C17.4875 9.31539 17.2796 9.8738 16.9905 10.3885L16.9407 10.1913L16.9378 10.1825L16.9105 10.1073C16.8878 10.0584 16.8567 10.0136 16.8196 9.97449L16.7591 9.9198L16.6907 9.87683C16.6195 9.83923 16.5397 9.81922 16.4583 9.81921C16.3769 9.81924 16.2972 9.83916 16.2259 9.87683L16.1575 9.9198C16.0926 9.96912 16.0412 10.0341 16.0071 10.1073L15.9788 10.1825L15.9769 10.1913L15.6888 11.3055L14.5735 11.5936L14.5648 11.5966C14.4866 11.6187 14.415 11.6592 14.3568 11.7147L14.303 11.7753C14.2379 11.8616 14.2025 11.9669 14.2025 12.0751C14.2025 12.1833 14.2378 12.2895 14.303 12.3759C14.3684 12.462 14.4607 12.5241 14.5648 12.5536L14.5638 12.5546L14.5735 12.5565L14.6956 12.5878C14.6713 12.5997 14.6479 12.6133 14.6234 12.6249C13.8904 12.9691 13.8233 12.9802 12.0911 13.0135L10.3138 13.0585L9.75812 12.4921C9.45833 12.1812 9.16972 11.9257 9.12531 11.9257C9.08095 11.9293 9.03644 13.1718 9.03644 14.702V17.4784H5.14972V7.47644L5.29523 7.38855L6.25714 7.14148L6.26984 7.13757C6.46419 7.08384 6.63587 6.96787 6.75812 6.8075C6.88031 6.64687 6.94757 6.44974 6.94757 6.24792C6.94746 6.09685 6.91016 5.94847 6.84015 5.81628L6.75812 5.68933L6.65753 5.57703C6.58501 5.50863 6.50193 5.45184 6.41144 5.41003L6.26984 5.35828L6.25714 5.35535L4.19073 4.82214L3.67413 2.81921H7.42609ZM9.0589 7.95007L9.0921 9.09363L10.7581 9.12683C11.7576 9.14904 12.5906 9.1157 12.846 9.03796C13.3013 8.90462 13.7015 8.39421 13.7015 7.95007C13.7014 7.58362 13.3897 7.08369 13.0677 6.93933C12.9111 6.86172 12.0341 6.81726 10.9134 6.81726H9.0257L9.0589 7.95007ZM1.81476 2.9823L1.65167 2.81921H1.85675L1.81476 2.9823Z"
        fill="url(#paint6_linear_10004_99259)"
      />
      <path
        d="M16.7691 0.565186H17.114L17.2002 1.08243L17.6313 1.25485L17.2002 1.51347L17.114 1.94451H16.7691V0.565186Z"
        fill="url(#paint7_linear_10004_99259)"
      />
      <path
        d="M17.1139 0.565186H16.769L16.6828 1.08243L16.0793 1.16864L16.6828 1.51347L16.769 1.94451H17.1139V0.565186Z"
        fill="url(#paint8_linear_10004_99259)"
      />
      <path
        d="M16.7049 1.5782C16.6959 1.54339 16.6778 1.51163 16.6524 1.48621C16.627 1.46079 16.5952 1.44265 16.5604 1.43367L15.9433 1.27456C15.9328 1.27157 15.9235 1.26523 15.9169 1.2565C15.9103 1.24777 15.9067 1.23713 15.9067 1.22618C15.9067 1.21524 15.9103 1.2046 15.9169 1.19586C15.9235 1.18713 15.9328 1.18079 15.9433 1.17781L16.5604 1.01859C16.5952 1.00962 16.6269 0.991496 16.6524 0.966097C16.6778 0.940698 16.6959 0.908955 16.7049 0.874167L16.864 0.257133C16.867 0.246565 16.8733 0.237254 16.8821 0.230621C16.8908 0.223988 16.9015 0.220398 16.9125 0.220398C16.9235 0.220398 16.9341 0.223988 16.9429 0.230621C16.9516 0.237254 16.9579 0.246565 16.9609 0.257133L17.1199 0.874167C17.1289 0.908973 17.1471 0.940738 17.1725 0.966155C17.1979 0.991573 17.2297 1.00972 17.2645 1.01869L17.8816 1.1777C17.8922 1.18063 17.9015 1.18696 17.9082 1.19572C17.9149 1.20447 17.9185 1.21518 17.9185 1.22618C17.9185 1.23719 17.9149 1.24789 17.9082 1.25665C17.9015 1.26541 17.8922 1.27173 17.8816 1.27466L17.2645 1.43367C17.2297 1.44265 17.1979 1.46079 17.1725 1.48621C17.1471 1.51163 17.1289 1.54339 17.1199 1.5782L16.9608 2.19523C16.9578 2.2058 16.9515 2.21511 16.9428 2.22174C16.934 2.22838 16.9234 2.23197 16.9124 2.23197C16.9014 2.23197 16.8907 2.22838 16.882 2.22174C16.8732 2.21511 16.8669 2.2058 16.8639 2.19523L16.7049 1.5782Z"
        stroke="url(#paint9_linear_10004_99259)"
        strokeWidth="0.44074"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <defs>
        <linearGradient
          id="paint0_linear_10004_99259"
          x1="16.8241"
          y1="11.8964"
          x2="18.1535"
          y2="11.9909"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2EE59B" />
          <stop offset="1" stopColor="#62DFF0" />
        </linearGradient>
        <linearGradient
          id="paint1_linear_10004_99259"
          x1="17.2565"
          y1="11.8964"
          x2="15.6648"
          y2="12.0322"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2EE59B" />
          <stop offset="1" stopColor="#62DFF0" />
        </linearGradient>
        <linearGradient
          id="paint2_linear_10004_99259"
          x1="15.6082"
          y1="11.5082"
          x2="18.6858"
          y2="11.8582"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2EE59B" />
          <stop offset="1" stopColor="#62DFF0" />
        </linearGradient>
        <linearGradient
          id="paint3_linear_10004_99259"
          x1="3.23098"
          y1="4.89459"
          x2="3.23098"
          y2="7.83895"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0.0673077" stopColor="#0A776E" />
          <stop offset="0.831731" stopColor="#23C176" />
        </linearGradient>
        <linearGradient
          id="paint4_linear_10004_99259"
          x1="1.94284"
          y1="4.89459"
          x2="1.94284"
          y2="7.83895"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0.0673077" stopColor="#0A776E" />
          <stop offset="0.831731" stopColor="#23C176" />
        </linearGradient>
        <linearGradient
          id="paint5_linear_10004_99259"
          x1="0.580082"
          y1="4.68836"
          x2="5.07973"
          y2="5.20013"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2EE59B" />
          <stop offset="1" stopColor="#62DFF0" />
        </linearGradient>
        <linearGradient
          id="paint6_linear_10004_99259"
          x1="2.06038"
          y1="4.62182"
          x2="18.786"
          y2="6.69814"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2EE59B" />
          <stop offset="1" stopColor="#62DFF0" />
        </linearGradient>
        <linearGradient
          id="paint7_linear_10004_99259"
          x1="17.2002"
          y1="0.565186"
          x2="17.2002"
          y2="1.94451"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0.0673077" stopColor="#0A776E" />
          <stop offset="0.831731" stopColor="#23C176" />
        </linearGradient>
        <linearGradient
          id="paint8_linear_10004_99259"
          x1="16.5966"
          y1="0.565186"
          x2="16.5966"
          y2="1.94451"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0.0673077" stopColor="#0A776E" />
          <stop offset="0.831731" stopColor="#23C176" />
        </linearGradient>
        <linearGradient
          id="paint9_linear_10004_99259"
          x1="15.9581"
          y1="0.467756"
          x2="18.0661"
          y2="0.707504"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#2EE59B" />
          <stop offset="1" stopColor="#62DFF0" />
        </linearGradient>
      </defs>
    </svg>
  );
};

export const BellIcon: React.FC<IconSvgProps> = ({
  size = 24,
  width,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width={size || width}
      height={size || height}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M10.268 21a2 2 0 0 0 3.464 0" />
      <path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326" />
    </svg>
  );
};

export const SidebarExpandIcon: React.FC<IconSvgProps> = ({
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
      fill="none"
      {...props}
    >
      <path
        d="M19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V5C3 4.46957 3.21071 3.96086 3.58579 3.58579C3.96086 3.21071 4.46957 3 5 3H19C19.5304 3 20.0391 3.21071 20.4142 3.58579C20.7893 3.96086 21 4.46957 21 5V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M7.25 10L5.5 12L7.25 14M9.5 21V3"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};

export const SidebarCollapseIcon: React.FC<IconSvgProps> = ({
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
      fill="none"
      {...props}
    >
      <path
        d="M19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V5C3 4.46957 3.21071 3.96086 3.58579 3.58579C3.96086 3.21071 4.46957 3 5 3H19C19.5304 3 20.0391 3.21071 20.4142 3.58579C20.7893 3.96086 21 4.46957 21 5V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M16.75 10L18.5 12L16.75 14M14.5 21V3"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
};
