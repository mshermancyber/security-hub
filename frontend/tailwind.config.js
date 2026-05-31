/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx,js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        ink:    { 950: '#05070b', 900: '#0a0d12', 800: '#10141b', 700: '#161b24', 600: '#1f2632', 500: '#2a3140' },
        wire:   { DEFAULT: '#1d2330', strong: '#2a3140' },
        amber:  { DEFAULT: '#ff9f1c', soft: '#ffb84d', glow: '#ffcf6b' },
        cyber:  { green: '#34f5c5', red: '#ff4d6d', blue: '#5cc8ff', yellow: '#ffd166', purple: '#b794f6' },
        mute:   { DEFAULT: '#8a93a6', soft: '#5e6678', deep: '#3a4254' },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(255,159,28,0.18), 0 0 16px -2px rgba(255,159,28,0.25)',
        soft: '0 0 0 1px rgba(255,255,255,0.04) inset',
      },
      keyframes: {
        pulseDot: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0.25' } },
        sweep:    { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        pulseDot: 'pulseDot 1.6s ease-in-out infinite',
        sweep:    'sweep 2.6s linear infinite',
      },
    },
  },
  plugins: [],
}
