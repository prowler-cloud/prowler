/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "*.{py,html,js}",
    "./**/*.{py,html,js}",
    "./**/**/*.{py,html,js}",
  ],
  theme: {
    extend: {
      colors: {
        prowler: {
          stone: {
            950: "#1C1917",
            900: "#292524",
            500: "#E7E5E4",
            300: "#F5F5F4",
          },
          gray: {
            900: "#9bAACF",
            700: "#BEC8E4",
            500: "#C8D0E7",
            300: "#E4EBF5",
          },
          status: {
            passed: "#1FB53F",
            failed: "#A3231F",
          },
        	lime: "#84CC16",
          white: "#FFFFFF",
          error: "#B91C1C",
        },
      },
      fontSize: {
        '3xs': '0.625rem',  // 10px
        '2xs': '0.6875rem', // 11px
        xs: '0.75rem',      // 12px
        sm: '0.875rem',     // 14px
        base: '1rem',       // 16px
        lg: '1.125rem',     // 18px
        xl: '1.25rem',      // 20px
        '2xl': '1.375rem',  // 22px
        '2xxl': '1.5rem',   // 24px
        '3xl': '1.75rem',   // 28px
        '4xl': '2rem',      // 32px
        '5xl': '2.25rem',   // 36px
        '6xl': '2.75rem',   // 44px
        '7xl': '3.5rem'     // 56px
      },
      fontWeight: {
        light: 300,
        regular: 400,
        medium: 500,
        bold: 700,
        heavy: 800
      },
      lineHeight: {
        14: "0.875rem",     // 14px
        22: "1.375rem",     // 22px
        26: "1.625rem",     // 26px
        28: "1.75rem",      // 28px
        30: "1.875rem",     // 30px
        32: "2rem",         // 32px
        34: "2.125rem",     // 34px
        36: "2.25rem",      // 36px
        40: "2.5rem",       // 40px
        44: "2.75rem",      // 44px
        48: "3rem",         // 48px
        56: "3.5rem",       // 56px
        68: "4.25rem",      // 68px
      },
			boxShadow: {
				"provider":
					".3rem .3rem .6rem #c8d0e7, -.2rem -.2rem .5rem #FFF",
				"box-up":
					"0.3rem 0.3rem 0.6rem #c8d0e7, -0.2rem -0.2rem 0.5rem #FFF",
				"box-down":
					"inset .2rem .2rem .5rem #c8d0e7, inset -.2rem -.2rem .5rem #FFF",
			},
			backgroundImage: {
        "gradient-passed":
          "linear-gradient(127.43deg, #F1F5F8 -177.68%, #4ADE80 87.35%)",
        "gradient-failed":
          "linear-gradient(127.43deg, #F1F5F8 -177.68%, #EF4444 87.35%)",
      },
    },
  },
  plugins: [],
};
