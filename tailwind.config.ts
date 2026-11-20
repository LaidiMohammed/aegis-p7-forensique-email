import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}", "./components/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: { slate9: "#0b1320", board: "#111c2e", amberx: "#f5a524", teal: "#4fd1c5", edge: "#23344f" },
      fontFamily: { mono: ["IBM Plex Mono", "Consolas", "monospace"], display: ["Manrope", "Arial", "sans-serif"] },
    },
  },
  plugins: [],
};
export default config;
