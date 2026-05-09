/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "templates/*.html",
    "templates/**/*.html",
    "static/**/*.js"
  ],
  theme: {
    extend: {
      fontFamily: { mono: ["JetBrains Mono","ui-monospace","SFMono-Regular","Menlo","monospace"] },
      colors: {
        accent: {
          50:"#ecfeff",100:"#cffafe",200:"#a5f3fc",300:"#67e8f9",400:"#22d3ee",
          500:"#06b6d4",600:"#0891b2",700:"#0e7490",800:"#155e75",900:"#164e63"
        }
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(6,182,212,.3), 0 4px 30px rgba(6,182,212,.15)"
      }
    }
  },
  plugins: [require("@tailwindcss/typography")]
}
