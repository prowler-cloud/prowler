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
          },
          blue: {
            800: "#1e293bff",
            400: "#1A202C",
          },
          black: {
            DEFAULT: "#000",
          },
          white: {
            DEFAULT: "#FFF",
          },
        },
        system: {
          success: {
            DEFAULT: "#09BF3D",
            medium: "#3CEC6D",
            lighter: "#D9FFE3",
          },
          error: {
            light: "#FECDD8",
          },
          severity: {
            high: "#F31260",
            low: "#fcd34d",
          },
        },
        danger: "#E11D48",
      },
      keyframes: {
        "collapsible-down": {
          from: { height: "0" },
          to: { height: "var(--radix-collapsible-content-height)" },
        },
        "collapsible-up": {
          from: { height: "var(--radix-collapsible-content-height)" },
          to: { height: "0" },
        },
        "fade-in": { from: { opacity: 0 }, to: { opacity: 1 } },
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
        "fade-in": "fade-in 200ms ease-out 0s 1 normal forwards running",
        "collapsible-down": "collapsible-down 0.2s ease-out",
        "collapsible-up": "collapsible-up 0.2s ease-out",
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
            background: "#000000",
            foreground: "#ffffff",
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
