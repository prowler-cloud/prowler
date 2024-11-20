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
        prowler: {
          theme: {
            midnight: "#030921",
            pale: "#f3fcff",
            green: "#8ce112",
            purple: "#5001d0",
            coral: "#ff5356",
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
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-geist-mono)"],
      },
      boxShadow: {
        "box-light":
          "-16px -16px 40px rgba(255, 255, 255, 0.8), 16px 4px 64px rgba(18, 61, 101, 0.3), inset -8px -6px 80px rgba(255, 255, 255, 0.18)",
        "button-curved-default":
          "-4px -2px 16px rgba(255, 255, 255, 0.7), 4px 2px 16px rgba(136, 165, 191, 0.38)",
        "button-curved-pressed":
          "inset -4px -4px 16px rgba(255, 255, 255, 0.8), inset 4px 4px 12px rgba(136, 165, 191, 0.4)",
        "button-flat-nopressed":
          "-4px -2px 16px #FFFFFF, 4px 2px 16px rgba(136, 165, 191, 0.48)",
        "button-flat-pressed":
          "inset -3px -3px 7px #FFFFFF, inset 3px 3px 7px rgba(136, 165, 191, 0.48)",
        "box-down-light":
          "inset -3px -3px 7px #FFFFFF, inset 2px 2px 5px rgba(136, 165, 191, 0.38)",
        "box-up":
          "-4px -2px 16px #FFFFFF, 4px 2px 16px rgba(136, 165, 191, 0.54)",
        "box-dark":
          "-4px -2px 16px rgba(195, 200, 205, 0.09), 4px 4px 18px rgba(0, 0, 0, 0.5)",
        "box-dark-out": "inset 2px 2px 2px rgba(26, 32, 38, 0.4)",
        "buttons-box-dark":
          "-5px -6px 16px rgba(195, 200, 205, 0.04), 22px 22px 60px rgba(0, 0, 0, 0.5)",
        "button-curved-default-dark":
          "-4px -4px 16px rgba(195, 200, 205, 0.06), 4px 4px 18px rgba(0, 0, 0, 0.6)",
        "button-curved-pressed-dark":
          "-4px -2px 16px rgba(195, 200, 205, 0.07), 4px 4px 18px rgba(0, 0, 0, 0.44)",
        "sky-light":
          "-16px 20px 40px rgba(215, 215, 215, 0.3), -2px 2px 24px rgba(22, 28, 47, 0.3), -16px 28px 120px rgba(0, 0, 0, 0.1)",
        "midnight-dark":
          "-16px 20px 40px rgba(3, 9, 33, 0.3), -2px 2px 24px rgba(3, 9, 33, 0.6), -16px 28px 120px rgba(3, 9, 33, 0.1)",
        switcher:
          "0px -6px 24px #FFFFFF, 0px 7px 16px rgba(104, 132, 157, 0.5)",
        up: "0.3rem 0.3rem 0.6rem #c8d0e7, -0.2rem -0.2rem 0.5rem #fff",
        down: "inset 0.2rem 0.2rem 0.5rem #c8d0e7, inset -0.2rem -0.2rem 0.5rem #fff",
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
  plugins: [
    require("tailwindcss-animate"),
    nextui({
      themes: {
        dark: {
          colors: {
            primary: {
              DEFAULT: "#9FD655",
              foreground: "#000000",
            },
            focus: "#9FD655",
            background: "#030921",
          },
        },
        light: {
          colors: {
            primary: {
              DEFAULT: "#9FD655",
              foreground: "#000000",
            },
          },
        },
      },
    }),
  ],
};
