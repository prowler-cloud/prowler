import Image from "next/image";
import React from "react";

import { IconSvgProps } from "../../../types/index";

export const ProwlerExtended: React.FC<IconSvgProps> = ({
  size,
  width = 216,
  height,
  className = "",
  ...props
}) => {
  return (
    <Image
      src="/opsvision-logo.png"
      alt="OpsVision"
      width={size ? Number(size) : Number(width)}
      height={size ? Number(size) : height ? Number(height) : 72}
      className={`h-auto w-auto ${className}`}
      priority
    />
  );
};

export const ProwlerShort: React.FC<IconSvgProps> = ({
  size,
  width = 30,
  height,
  className = "",
  ...props
}) => (
  <Image
    src="/opsvision-icon.jpg"
    alt="OpsVision"
    width={size ? Number(size) : Number(width)}
    height={size ? Number(size) : height ? Number(height) : 30}
    className={`h-auto w-auto rounded-sm ${className}`}
    priority
  />
);
