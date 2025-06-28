/// <reference types="vitest" />
/// <reference types="vite/client" />
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'],
    css: true,
    environmentOptions: {
      jsdom: {
        resources: 'usable'
      }
    },
    // Suppress console warnings during tests
    onConsoleLog(log, type) {
      // Suppress React Router future flag warnings
      if (log.includes('React Router Future Flag Warning')) {
        return false
      }
      if (log.includes('React Router will begin wrapping state updates')) {
        return false
      }
      if (log.includes('Relative route resolution within Splat routes')) {
        return false
      }
      return true
    }
  }
})