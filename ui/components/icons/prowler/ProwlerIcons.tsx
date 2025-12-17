import { FC, ImgHTMLAttributes } from "react";

export interface IconImgProps extends ImgHTMLAttributes<HTMLImageElement> {
  size?: number;
}

/**
 * Large logo (Auth pages)
 */
export const ProwlerExtended: FC<IconImgProps> = ({
  size = 220,
  style,
  ...props
}) => (
  <img
    src="/logo.png"
    alt="Cignify"
    width={size}
    height="auto"
    style={{
      display: "block",
      maxWidth: size,
      height: "auto",
      margin: 0,
      padding: 0,
      ...style,
    }}
    {...props}
  />
);

/**
 * Small logo (Sidebar / menu)
 */
export const ProwlerShort: FC<IconImgProps> = ({
  size = 100,
  style,
  ...props
}) => (
  <img
    src="/logoicon.png"
    alt="Cignify"
    width={size}
    height="auto"
    style={{
      display: "block",
      margin: 0,
      padding: 0,
      ...style,
    }}
    {...props}
  />
);
