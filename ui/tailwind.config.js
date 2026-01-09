const { heroui } = require("@heroui/theme");

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./components/**/*.{ts,jsx,tsx}",
    "./app/**/*.{ts,jsx,tsx}",
    "./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
    "!./docs/**/*",
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
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-geist-mono)"],
      },
      colors: {
        prowler: {
          theme: {
            pale: "#f3fcff",
            green: "#8ce112",
            purple: "#5001d0",
            orange: "#f69000",
            yellow: "#ffdf16",
          },
          blue: {
            800: "#1e293bff",
            400: "#1A202C",
          },
          grey: {
            medium: "#353a4d",
            light: "#868994",
            600: "#64748b",
          },
          green: {
            DEFAULT: "#9FD655",
            medium: "#09BF3D",
          },
          black: {
            DEFAULT: "#000",
            900: "#18181A",
          },
          white: {
            DEFAULT: "#FFF",
            900: "#18181A",
          },
        },
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
        danger: "#E11D48",
        action: "#9FD655",
      },
      animation: {
        "fade-in": "fade-in 200ms ease-out 0s 1 normal forwards running",
        "fade-out": "fade-out 200ms ease-in 0s 1 normal forwards running",
        expand: "expand 400ms linear 0s 1 normal forwards running",
        "slide-in": "slide-in 400ms linear 0s 1 normal forwards running",
        "slide-out": "slide-out 400ms linear 0s 1 normal forwards running",
        collapse: "collapse 400ms linear 0s 1 normal forwards running",
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
        "collapsible-down": {
          from: { height: "0" },
          to: { height: "var(--radix-collapsible-content-height)" },
        },
        "collapsible-up": {
          from: { height: "var(--radix-collapsible-content-height)" },
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
        dropArrow: {
          "0%": { transform: "translateY(-8px)", opacity: "0" },
          "50%": { opacity: "1" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        first: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        second: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        third: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
      animation: {
        "collapsible-down": "collapsible-down 0.2s ease-out",
        "collapsible-up": "collapsible-up 0.2s ease-out",
        "drop-arrow": "dropArrow 0.6s ease-out infinite",
        first: "first 20s linear infinite",
        second: "second 30s linear infinite",
        third: "third 25s linear infinite",
      },
      screens: {
        "3xl": "1920px", // Add breakpoint to optimize layouts for large screens.
      },
    },
  },
  plugins: [
    require("tailwindcss-animate"),
    require("@tailwindcss/typography"),
    heroui({
      themes: {
        dark: {
          colors: {
            primary: {
              DEFAULT: "#6ee7b7",
              foreground: "#000000",
            },
            focus: "#6ee7b7",
            background: "#09090B",
          },
        },
        light: {
          colors: {
            primary: {
              DEFAULT: "#6ee7b7",
              foreground: "#000000",
            },
          },
        },
      },
    }),
  ],
};
