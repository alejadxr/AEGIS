import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        c6: {
          bg: '#050505',
          surface: '#0A0A0A',
          elevated: '#111111',
          border: 'rgba(255, 255, 255, 0.04)',
          'border-hover': 'rgba(255, 255, 255, 0.08)',
        },
        accent: {
          DEFAULT: '#22D3EE',
          secondary: '#F97316',
        },
        danger: '#EF4444',
        warning: '#F59E0B',
        success: '#22C55E',
        info: '#3B82F6',
      },
      fontFamily: {
        sans: ['Outfit', 'system-ui', 'sans-serif'],
        mono: ['Azeret Mono', 'monospace'],
      },
      borderRadius: {
        'card': '12px',
      },
      animation: {
        'fade-in': 'fade-in 0.15s ease-out forwards',
        'fade-up': 'fade-up 0.3s ease-out forwards',
        'slide-up': 'slide-up 0.3s ease-out forwards',
        'slide-right': 'slide-right 0.2s ease-out forwards',
        'pulse-subtle': 'pulse-subtle 2s ease-in-out infinite',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-up': {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-right': {
          '0%': { opacity: '0', transform: 'translateX(-8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        'pulse-subtle': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.4' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
};
export default config;
