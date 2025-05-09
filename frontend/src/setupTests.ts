// frontend/src/setupTests.ts
import '@testing-library/jest-dom';

// Add custom type declarations to fix TypeScript errors
declare global {
  interface Window {
    // Properly extend without redefining the matchMedia property
    matchMedia: (query: string) => MediaQueryList;
  }
}

// Create a proper MediaQueryList mock implementation
const createMatchMediaMock = (): (query: string) => MediaQueryList => {
  return (query: string): MediaQueryList => {
    return {
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(), // deprecated
      removeListener: jest.fn(), // deprecated
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(() => true),
    } as unknown as MediaQueryList;
  };
};

// Apply the mock
window.matchMedia = window.matchMedia || createMatchMediaMock();

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value.toString();
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
});

// Mock intersectionObserver
class IntersectionObserverMock implements IntersectionObserver {
  readonly root: Element | null = null;
  readonly rootMargin: string = '';
  readonly thresholds: ReadonlyArray<number> = [];
  
  constructor() {
    this.observe = jest.fn();
    this.unobserve = jest.fn();
    this.disconnect = jest.fn();
    this.takeRecords = jest.fn(() => []);
  }
  
  observe = jest.fn();
  unobserve = jest.fn();
  disconnect = jest.fn();
  takeRecords = jest.fn(() => []);
}

Object.defineProperty(window, 'IntersectionObserver', {
  writable: true,
  configurable: true,
  value: IntersectionObserverMock,
});

// Silence React 18 console errors during testing
const originalError = console.error;
console.error = (...args) => {
  if (/Warning.*not wrapped in act/.test(args[0])) {
    return;
  }
  originalError(...args);
};