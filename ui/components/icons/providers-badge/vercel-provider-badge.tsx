import { IconSvgProps } from "@/types";

export const VercelProviderBadge: React.FC<IconSvgProps> = ({
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
    <rect width="256" height="256" fill="#000000" rx="60" />
    <path d="M128 45L217 195H39L128 45Z" fill="#ffffff" />
  </svg>
);
