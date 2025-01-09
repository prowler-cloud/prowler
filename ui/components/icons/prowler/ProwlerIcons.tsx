import React from "react";

import { IconSvgProps } from "../../../types/index";

export const ProwlerExtended: React.FC<IconSvgProps> = ({
  size,
  width = 216,
  height,
  ...props
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1233.67 204.4"
      fill="none"
      height={size || height}
      width={size || width}
      color="evenodd"
      {...props}
    >
      <path
        className="cls-1"
        d="M1169.38 132.04c20.76-12.21 34.44-34.9 34.44-59.79 0-38.18-31.06-69.25-69.25-69.25l-216.9.23V148.4h-64.8V3h-79.95l-47.14 95.97V3h-52.09l-47.14 95.97V3h-53.48v69.6C560.37 30.64 521.34 0 475.28 0c-42.63 0-79.24 26.25-94.54 63.43C376.39 29.4 347.26 3 312.07 3H212.06v47.43C202.9 22.91 176.91 3 146.35 3H0l46.34 46.33v151.64h53.47v-76.68l17.21 17.21h29.33c30.56 0 56.54-19.91 65.71-47.43v106.91h53.48v-81.51l76.01 81.51h69.62l-64.29-68.94c11.14-6.56 20.22-16.15 26.26-27.46 1.27 55.26 46.58 99.82 102.14 99.82 46.06 0 85.09-30.64 97.81-72.6v69.18h60.88l38.34-78.06v78.06h60.88l66.2-134.78v135.69h95.41l22.86-22.86v22.86h95.05l21.84-21.84v20.93h53.48v-81.5l76.01 81.5h69.62l-64.29-68.94ZM146.35 88.02H99.81V56.48h46.54c8.7 0 15.77 7.07 15.77 15.77s-7.07 15.77-15.77 15.77Zm165.72 0-46.54-.18V56.48h46.54c8.7 0 15.77 7.07 15.77 15.77s-7.08 15.77-15.77 15.77Zm163.21 62.9c-26.86 0-48.72-21.86-48.72-48.72s21.86-48.72 48.72-48.72S524 75.34 524 102.2s-21.86 48.72-48.72 48.72Zm559.28-2.51h-63.41v-20.35h42.91V77.18h-42.91V56.72h63.41v91.69Zm100.01-60.39-46.54-.18V56.48h46.54c8.7 0 15.77 7.07 15.77 15.77s-7.07 15.77-15.77 15.77Z"
        fill="currentColor"
        fillRule="evenodd"
        clipRule="evenodd"
      />
    </svg>
  );
};

export const ProwlerShort: React.FC<IconSvgProps> = ({
  size,
  width = 30,
  height,
  ...props
}) => (
  <svg
    id="Layer_1"
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 432.08 396.77"
    fill="none"
    height={size || height}
    width={size || width}
    color="evenodd"
    {...props}
  >
    <path
      className="cls-1"
      d="M293.3.01H0s92.87,92.85,92.87,92.85v303.9h107.17v-153.68l34.48,34.49h58.78c76.52,0,138.78-62.26,138.78-138.78S369.82.01,293.3.01ZM293.3,170.4h-93.27v-63.21h93.27c17.43,0,31.6,14.18,31.6,31.6s-14.18,31.6-31.6,31.6Z"
      fill="currentColor"
      fillRule="evenodd"
      clipRule="evenodd"
      color="evenodd"
    />
  </svg>
);
