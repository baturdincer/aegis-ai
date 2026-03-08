/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bw: {
          bg:      '#000000',
          panel:   '#0a0a0a',
          card:    '#111111',
          border:  '#1a1a1a',
          border2: '#2a2a2a',
          text:    '#f0f0f0',
          sub:     '#888888',
          muted:   '#444444',
          white:   '#ffffff',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
