// /frontend/src/app.tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './hooks/useAuth';

// Create a QueryClient for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Import pages
// These would be your actual page components
const Login = () => <div>Login Page</div>;
const Register = () => <div>Register Page</div>;
const ImageUpload = () => <div>Image Upload Page</div>;
const ImageList = () => <div>Image List Page</div>;
const GarmentDetail = () => <div>Garment Detail Page</div>;
const GarmentList = () => <div>Garment List Page</div>;
const WardrobeList = () => <div>Wardrobe List Page</div>;
const WardrobeDetail = () => <div>Wardrobe Detail Page</div>;
const NotFound = () => <div>404 Not Found</div>;

// Layout component with navigation
const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { logout, isAuthenticated } = useAuth();
  
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Basic navigation bar */}
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <a href="/" className="text-xl font-bold text-gray-900">Koutu</a>
            </div>
            
            {isAuthenticated ? (
              <div className="flex items-center space-x-4">
                <a href="/images" className="text-gray-600 hover:text-gray-900">Images</a>
                <a href="/garments" className="text-gray-600 hover:text-gray-900">Garments</a>
                <a href="/wardrobes" className="text-gray-600 hover:text-gray-900">Wardrobes</a>
                <button 
                  onClick={logout}
                  className="ml-4 px-4 py-2 rounded bg-red-100 text-red-600 hover:bg-red-200"
                >
                  Logout
                </button>
              </div>
            ) : (
              <div className="flex items-center space-x-4">
                <a href="/login" className="text-gray-600 hover:text-gray-900">Login</a>
                <a href="/register" className="px-4 py-2 rounded bg-indigo-600 text-white hover:bg-indigo-700">Register</a>
              </div>
            )}
          </div>
        </div>
      </nav>
      
      {/* Main content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>
    </div>
  );
};

// Protected route component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) {
    return <div className="flex justify-center items-center h-64">Loading...</div>;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
};

// Public route component (redirects if already authenticated)
const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) {
    return <div className="flex justify-center items-center h-64">Loading...</div>;
  }
  
  if (isAuthenticated) {
    return <Navigate to="/images" replace />;
  }
  
  return <>{children}</>;
};

// Main App component
const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router>
          <Layout>
            <Routes>
              {/* Public routes */}
              <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
              <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
              
              {/* Protected routes */}
              <Route path="/" element={<Navigate to="/images" replace />} />
              <Route path="/images" element={<ProtectedRoute><ImageList /></ProtectedRoute>} />
              <Route path="/images/upload" element={<ProtectedRoute><ImageUpload /></ProtectedRoute>} />
              <Route path="/garments" element={<ProtectedRoute><GarmentList /></ProtectedRoute>} />
              <Route path="/garments/:id" element={<ProtectedRoute><GarmentDetail /></ProtectedRoute>} />
              <Route path="/wardrobes" element={<ProtectedRoute><WardrobeList /></ProtectedRoute>} />
              <Route path="/wardrobes/:id" element={<ProtectedRoute><WardrobeDetail /></ProtectedRoute>} />
              
              {/* 404 route */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Layout>
        </Router>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;