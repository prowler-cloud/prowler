import { Boxes } from "lucide-react";
import { type FC } from "react";

import { IconSvgProps } from "@/types";

/**
 * Neutral fallback glyph for any dynamic provider
 */
export const GenericProviderBadge: FC<IconSvgProps> = ({
  size,
  width,
  height,
  ...props
}) => (
  <Boxes
    aria-hidden="true"
    focusable="false"
    width={size ?? width}
    height={size ?? height}
    {...props}
  />
);
