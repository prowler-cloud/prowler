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
  size,
  height,
  width,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size || width || 24}
      height={size || height || 24}
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
