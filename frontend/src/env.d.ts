// /frontend/src/env.d.ts
/// <reference types="vite/client" />

// Global type declarations for Vite environment variables
declare global {
  interface ImportMetaEnv {
    readonly VITE_API_BASE_URL: string;
    // Add other env variables here if needed
  }

  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
}

// This empty export is needed to make this a module
export {};