// /frontend/src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import AppModern from './AppModern';
import './index.css'; // Import Tailwind CSS

// Render the application
ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <AppModern />
  </React.StrictMode>
);