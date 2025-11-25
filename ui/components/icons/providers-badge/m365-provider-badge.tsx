import type { FC } from "react";
import { useId } from "react";

import type { IconSvgProps } from "@/types";

export const M365ProviderBadge: FC<IconSvgProps> = ({
  size,
  width,
  height,
  ...props
}) => {
  const uniqueId = useId();
  const gradientId0 = `m365-gradient-0-${uniqueId}`;
  const gradientId1 = `m365-gradient-1-${uniqueId}`;
  const gradientId2 = `m365-gradient-2-${uniqueId}`;
  const gradientId4 = `m365-gradient-4-${uniqueId}`;
  const clipId0 = `m365-clip-0-${uniqueId}`;
  const clipId1 = `m365-clip-1-${uniqueId}`;

  return (
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
      <g>
        <rect width="256" height="256" rx="60" fill="#f4f2ed" />
        <g transform="scale(3.1) translate(2 2)">
          <g clipPath={`url(#${clipId0})`}>
            <g clipPath={`url(#${clipId1})`}>
              <path
                d="M53.1574 10.3146C52.1706 7.19669 49.2773 5.07764 46.007 5.07764L43.5352 5.07764C39.9228 5.07764 36.8237 7.65268 36.1621 11.2039L32.4891 30.9179L33.5912 27.2788C34.5491 24.1158 37.4644 21.9526 40.7692 21.9526H52.2499L58.8326 24.2562L62.3337 21.9644C59.0634 21.9644 56.1701 19.8336 55.1833 16.7157L53.1574 10.3146Z"
                fill={`url(#${gradientId0})`}
              />
              <path
                d="M20.615 62.8082C21.5914 65.9426 24.4927 68.0777 27.7757 68.0777H32.6415C36.7421 68.0777 40.0824 64.7845 40.1408 60.6844L40.3984 42.5737L39.4114 45.86C38.459 49.0313 35.5396 51.2027 32.2284 51.2027H20.75L14.8141 48.4965L11.4807 51.2027C14.7636 51.2027 17.665 53.3378 18.6414 56.4722L20.615 62.8082Z"
                fill={`url(#${gradientId1})`}
              />
              <path
                d="M45.5 5.07764H19.25C11.75 5.07764 7.25001 14.7496 4.25002 24.4216C0.695797 35.8804 -3.95498 51.2056 9.50001 51.2056H20.931C24.2656 51.2056 27.1975 49.0121 28.135 45.812C30.1073 39.0797 33.5545 27.3661 36.2631 18.446C37.6417 13.906 38.79 10.007 40.5523 7.57888C41.5404 6.21761 43.1871 5.07764 45.5 5.07764Z"
                fill={`url(#${gradientId2})`}
              />
              <path
                d="M27.4946 68.0776H53.7446C61.2446 68.0776 65.7446 58.4071 68.7446 48.7365C72.2988 37.2794 76.9496 21.9565 63.4946 21.9565H52.0633C48.7288 21.9565 45.797 24.1499 44.8594 27.3499C42.8871 34.0812 39.44 45.7927 36.7314 54.7113C35.3529 59.2506 34.2046 63.149 32.4422 65.5768C31.4542 66.9378 29.8075 68.0776 27.4946 68.0776Z"
                fill={`url(#${gradientId4})`}
              />
              <rect
                x="24.125"
                y="51.2031"
                width="48.375"
                height="21.375"
                rx="3.63727"
                fill="#131313"
              />
              <text
                x="27.5"
                y="67"
                fill="#ffffff"
                fontFamily="Inter, Arial, sans-serif"
                fontSize="16"
                fontWeight="700"
              >
                M365
              </text>
            </g>
          </g>
          <defs>
            <radialGradient
              id={gradientId0}
              cx="0"
              cy="0"
              r="1"
              gradientUnits="userSpaceOnUse"
              gradientTransform="translate(59.4363 31.0868) rotate(-130.285) scale(27.6431 26.1575)"
            >
              <stop offset="0.0955758" stopColor="#00AEFF" />
              <stop offset="0.773185" stopColor="#2253CE" />
              <stop offset="1" stopColor="#0736C4" />
            </radialGradient>
            <radialGradient
              id={gradientId1}
              cx="0"
              cy="0"
              r="1"
              gradientUnits="userSpaceOnUse"
              gradientTransform="translate(15.3608 50.9716) rotate(50.2556) scale(25.0142 24.5538)"
            >
              <stop stopColor="#FFB657" />
              <stop offset="0.633728" stopColor="#FF5F3D" />
              <stop offset="0.923392" stopColor="#C02B3C" />
            </radialGradient>
            <linearGradient
              id={gradientId2}
              x1="17.6789"
              y1="10.6669"
              x2="21.2461"
              y2="52.961"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0.156162" stopColor="#0D91E1" />
              <stop offset="0.487484" stopColor="#52B471" />
              <stop offset="0.652394" stopColor="#98BD42" />
              <stop offset="0.937361" stopColor="#FFC800" />
            </linearGradient>
            <radialGradient
              id={gradientId4}
              cx="0"
              cy="0"
              r="1"
              gradientUnits="userSpaceOnUse"
              gradientTransform="translate(64.843 17.441) rotate(109.722) scale(61.4524 75.0539)"
            >
              <stop offset="0.0661714" stopColor="#8C48FF" />
              <stop offset="0.5" stopColor="#F2598A" />
              <stop offset="0.895833" stopColor="#FFB152" />
            </radialGradient>
            <clipPath id={clipId0}>
              <rect
                width="72"
                height="72"
                fill="white"
                transform="translate(0.5 0.578125)"
              />
            </clipPath>
            <clipPath id={clipId1}>
              <rect
                width="72"
                height="72"
                fill="white"
                transform="translate(0.5 0.578125)"
              />
            </clipPath>
          </defs>
        </g>
      </g>
    </svg>
  );
};
