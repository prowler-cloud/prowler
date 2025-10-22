"use client";

import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

export const ThreatScoreLogo = () => {
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Avoid hydration mismatch by only rendering after mount
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="h-14" style={{ width: "280px", height: "56px" }} />;
  }

  const prowlerColor = resolvedTheme === "dark" ? "#fff" : "#000";

  return (
    <svg
      viewBox="0 0 1000 280"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="h-14 w-auto"
      preserveAspectRatio="xMinYMid meet"
    >
      {/* Prowler logo from the new SVG - scaled and positioned to match THREATSCORE size */}
      <g transform="scale(0.50) translate(-60, 20)">
        <path
          fill={prowlerColor}
          d="M1222.86,185.51c20.76-12.21,34.44-34.9,34.44-59.79,0-38.18-31.06-69.25-69.25-69.25l-216.9.23v145.17h-64.8V56.47h-79.95s-47.14,95.97-47.14,95.97V56.47h-52.09s-47.14,95.97-47.14,95.97V56.47h-53.48v69.6c-12.72-41.96-51.75-72.6-97.81-72.6-42.63,0-79.24,26.25-94.54,63.43-4.35-34.03-33.48-60.43-68.67-60.43h-100.01v47.43c-9.16-27.52-35.14-47.43-65.71-47.43H53.47s46.34,46.33,46.34,46.33v151.64h53.47v-76.68l17.21,17.21h29.33c30.56,0,56.54-19.91,65.71-47.43v106.91h53.48v-81.51l76.01,81.51h69.62l-64.29-68.94c11.14-6.56,20.22-16.15,26.26-27.46,1.27,55.26,46.58,99.82,102.14,99.82,46.06,0,85.09-30.64,97.81-72.6v69.18h60.88l38.34-78.06v78.06h60.88l66.2-134.78v135.69h95.41l22.86-22.86v22.86h95.05l21.84-21.84v20.93h53.48v-81.5l76.01,81.5h69.62l-64.29-68.94ZM199.83,141.5h-46.54v-31.54h46.54c8.7,0,15.77,7.07,15.77,15.77s-7.07,15.77-15.77,15.77ZM365.55,141.5l-46.54-.18v-31.36h46.54c8.7,0,15.77,7.07,15.77,15.77s-7.08,15.77-15.77,15.77ZM528.76,204.39c-26.86,0-48.72-21.86-48.72-48.72s21.86-48.72,48.72-48.72,48.72,21.86,48.72,48.72-21.86,48.72-48.72,48.72ZM1088.03,201.88h-63.41v-20.35h42.91v-50.88h-42.91v-20.46h63.41v91.69ZM1188.05,141.5l-46.54-.18v-31.36h46.54c8.7,0,15.77,7.07,15.77,15.77s-7.07,15.77-15.77,15.77Z"
        />
      </g>

      {/* THREATSCORE text */}
      <text x="0" y="240" fontSize="80" fontWeight="700" fill="#22c55e">
        THREATSCORE
      </text>

      {/* Gauge icon - semicircular meter - 1.5x larger */}
      <g transform="translate(680, 0) scale(2)">
        {/* Gauge arcs - drawing from left to right (orange, red, green) */}
        <path
          d="M 20 80 A 60 60 0 0 1 50 29.6"
          stroke="#fb923c"
          strokeWidth="16"
          fill="none"
          strokeLinecap="round"
        />
        <path
          d="M 50 29.6 A 60 60 0 0 1 110 29.6"
          stroke="#ef4444"
          strokeWidth="16"
          fill="none"
          strokeLinecap="round"
        />
        <path
          d="M 110 29.6 A 60 60 0 0 1 140 80"
          stroke="#22c55e"
          strokeWidth="16"
          fill="none"
          strokeLinecap="round"
        />

        {/* Checkmark */}
        <path
          d="M 60 80 L 72 92 L 104 60"
          stroke="#22c55e"
          strokeWidth="8"
          fill="none"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </g>
    </svg>
  );
};
