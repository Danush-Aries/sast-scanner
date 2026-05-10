/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#f59e0b',
        low: '#10b981',
      }
    },
  },
  },
  plugins: [],
}

