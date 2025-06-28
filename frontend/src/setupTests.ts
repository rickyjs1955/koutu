// src/setupTests.ts (for Vitest)
import { expect, afterEach, beforeAll, afterAll, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import * as matchers from '@testing-library/jest-dom/matchers'

// Extend Vitest's expect with jest-dom matchers
expect.extend(matchers)

// Cleanup after each test case (e.g. clearing jsdom)
afterEach(() => {
  cleanup()
})

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
  length: 0,
  key: vi.fn()
}
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
})

// Mock sessionStorage
const sessionStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
  length: 0,
  key: vi.fn()
}
Object.defineProperty(window, 'sessionStorage', {
  value: sessionStorageMock
})

// Mock fetch globally
global.fetch = vi.fn()

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), // deprecated
    removeListener: vi.fn(), // deprecated
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  root: Element | null = null
  rootMargin: string = ''
  thresholds: ReadonlyArray<number> = []
  constructor(_callback: IntersectionObserverCallback, _options?: IntersectionObserverInit) {}
  observe() { return null }
  disconnect() { return null }
  unobserve() { return null }
  takeRecords() { return [] }
}

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  observe() { return null }
  disconnect() { return null }
  unobserve() { return null }
}

// Mock URL.createObjectURL
global.URL.createObjectURL = vi.fn(() => 'mock-url')
global.URL.revokeObjectURL = vi.fn()

// Mock HTMLCanvasElement.getContext
HTMLCanvasElement.prototype.getContext = vi.fn()

// Suppress console errors during tests (optional)
const originalError = console.error
beforeAll(() => {
  console.error = (...args: any[]) => {
    if (
      /Warning.*not wrapped in act/.test(args[0]) ||
      /Warning.*useLayoutEffect/.test(args[0])
    ) {
      return
    }
    originalError.call(console, ...args)
  }
})

afterAll(() => {
  console.error = originalError
})