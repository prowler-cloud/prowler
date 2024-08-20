import { nextui } from "@nextui-org/theme";

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./components/**/*.{ts,jsx,tsx,mdx}",
    "./app/**/*.{ts,jsx,tsx,mdx}",
    "./node_modules/@nextui-org/theme/dist/**/*.{js,ts,jsx,tsx}",
  ],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        system: {
          success: {
            DEFAULT: "#09BF3D",
            medium: "#3CEC6D",
            light: "#B5FDC8",
            lighter: "#D9FFE3",
          },
          error: {
            DEFAULT: "#E11D48",
            medium: "#FB718F",
            light: "#FECDD8",
            lighter: "#FFE4EA",
          },
          info: {
            DEFAULT: "#7C3AED",
            medium: "#B48BFA",
            light: "#E5D6FE",
            lighter: "#F1E9FE",
          },
          warning: {
            DEFAULT: "#FBBF24",
            medium: "#FDDD8A",
            light: "#feefc7",
            lighter: "#FFF9EB",
          },
          severity: {
            critical: "#AC1954",
            high: "#F31260",
            medium: "#FA7315",
            low: "#fcd34d",
          },
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-geist-mono)"],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        advance: { from: { width: 0 }, to: { width: "100%" } },
        "fade-in": { from: { opacity: 0 }, to: { opacity: 1 } },
        "fade-out": { from: { opacity: 1 }, to: { opacity: 0 } },
        "slide-in": {
          from: { transform: "translateX(100%)" },
          to: { transform: "translateX(0)" },
        },
        "slide-out": {
          from: { transform: "translateX(0)" },
          to: { transform: "translateX(100%)" },
        },
        woosh: {
          "0, 10%": { left: 0, right: "100%" },
          "40%, 60%": { left: 0, right: 0 },
          "90%, 100%": { left: "100%", right: 0 },
        },
        lineAnim: {
          "0%": { left: "-40%" },
          "50%": { left: "20%", width: "80%" },
          "100%": { left: "100%", width: "100%" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
      screens: {
        "3xl": "1920px", // Add breakpoint to optimize layouts for large screens.
      },
    },
  },
  plugins: [require("tailwindcss-animate"), nextui()],
};
