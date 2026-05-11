import { IconSvgProps } from "@/types";

export const LovableProviderBadge: React.FC<IconSvgProps> = ({
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
    <rect width="256" height="256" fill="#FF4F8B" rx="60" />
    <path
      d="M128 196c-7 0-13.6-2.7-18.6-7.7l-44.7-44.7c-15.6-15.6-15.6-40.9 0-56.6 15.6-15.6 40.9-15.6 56.6 0L128 94.7l6.7-6.7c15.6-15.6 40.9-15.6 56.6 0 15.6 15.6 15.6 40.9 0 56.6l-44.7 44.7c-5 5-11.6 7.7-18.6 7.7Z"
      fill="#FFFFFF"
    />
  </svg>
);
