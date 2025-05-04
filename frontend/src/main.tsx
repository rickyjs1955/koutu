// /frontend/src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './app';
import './index.css'; // Import Tailwind CSS

// Render the application
ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);