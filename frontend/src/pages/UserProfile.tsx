// /frontend/src/pages/UserProfile.tsx
import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

const UserProfile: React.FC = () => {
  const { user, logout, linkedProviders, linkProvider, unlinkProvider } = useAuth();
  const [isUnlinking, setIsUnlinking] = useState(false);
  const [unlinkError, setUnlinkError] = useState<string | null>(null);
  
  if (!user) {
    return null;
  }
  
  const handleUnlinkProvider = async (provider: string) => {
    // Don't allow unlinking if it's the only authentication method
    const hasPassword = !user.oauth_provider || user.oauth_provider !== provider;
    const otherProviders = linkedProviders.filter(p => p !== provider);
    
    if (!hasPassword && otherProviders.length === 0) {
      setUnlinkError(
        "You can't unlink this provider as it's your only authentication method. " +
        "Please add a password or link another provider first."
      );
      return;
    }
    
    setIsUnlinking(true);
    try {
      await unlinkProvider(provider);
      setUnlinkError(null);
    } catch (err) {
      setUnlinkError('Failed to unlink provider. Please try again later.');
    } finally {
      setIsUnlinking(false);
    }
  };
  
  // List of all supported providers
  const allProviders = ['google', 'microsoft', 'github'];
  
  // Providers that can be linked
  const availableProviders = allProviders.filter(
    provider => !linkedProviders.includes(provider)
  );
  
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-3xl font-bold text-gray-900 mb-8">Account Settings</h1>
        
        {/* Profile Information */}
        <div className="bg-white shadow overflow-hidden sm:rounded-lg mb-8">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">Profile Information</h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">Your personal details and account information.</p>
          </div>
          <div className="border-t border-gray-200">
            <dl>
              <div className="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt className="text-sm font-medium text-gray-500">Email address</dt>
                <dd className="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{user.email}</dd>
              </div>
              <div className="bg-white px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt className="text-sm font-medium text-gray-500">Name</dt>
                <dd className="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{user.name || 'Not provided'}</dd>
              </div>
              <div className="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt className="text-sm font-medium text-gray-500">Account created</dt>
                <dd className="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                   {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Not available'}
                </dd>
              </div>
            </dl>
          </div>
        </div>
        
        {/* Connected Accounts */}
        <div className="bg-white shadow overflow-hidden sm:rounded-lg mb-8">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">Connected Accounts</h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">Manage your connected social accounts.</p>
          </div>
          
          {unlinkError && (
            <div className="mx-6 my-4 rounded-md bg-red-50 p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">{unlinkError}</h3>
                </div>
              </div>
            </div>
          )}
          
          <div className="border-t border-gray-200">
            <div className="divide-y divide-gray-200">
              {/* Connected Providers */}
              {linkedProviders.map(provider => (
                <div key={provider} className="px-4 py-5 sm:px-6 flex justify-between items-center">
                  <div className="flex items-center">
                    {provider === 'google' && (
                      <svg className="h-8 w-8 mr-3" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <g transform="matrix(1, 0, 0, 1, 27.009001, -39.238998)">
                          <path fill="#4285F4" d="M -3.264 51.509 C -3.264 50.719 -3.334 49.969 -3.454 49.239 L -14.754 49.239 L -14.754 53.749 L -8.284 53.749 C -8.574 55.229 -9.424 56.479 -10.684 57.329 L -10.684 60.329 L -6.824 60.329 C -4.564 58.239 -3.264 55.159 -3.264 51.509 Z"/>
                          <path fill="#34A853" d="M -14.754 63.239 C -11.514 63.239 -8.804 62.159 -6.824 60.329 L -10.684 57.329 C -11.764 58.049 -13.134 58.489 -14.754 58.489 C -17.884 58.489 -20.534 56.379 -21.484 53.529 L -25.464 53.529 L -25.464 56.619 C -23.494 60.539 -19.444 63.239 -14.754 63.239 Z"/>
                          <path fill="#FBBC05" d="M -21.484 53.529 C -21.734 52.809 -21.864 52.039 -21.864 51.239 C -21.864 50.439 -21.724 49.669 -21.484 48.949 L -21.484 45.859 L -25.464 45.859 C -26.284 47.479 -26.754 49.299 -26.754 51.239 C -26.754 53.179 -26.284 54.999 -25.464 56.619 L -21.484 53.529 Z"/>
                          <path fill="#EA4335" d="M -14.754 43.989 C -12.984 43.989 -11.404 44.599 -10.154 45.789 L -6.734 42.369 C -8.804 40.429 -11.514 39.239 -14.754 39.239 C -19.444 39.239 -23.494 41.939 -25.464 45.859 L -21.484 48.949 C -20.534 46.099 -17.884 43.989 -14.754 43.989 Z"/>
                        </g>
                      </svg>
                    )}
                    
                    {provider === 'microsoft' && (
                      <svg className="h-8 w-8 mr-3" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <rect x="1" y="1" width="10" height="10" fill="#F25022"/>
                        <rect x="13" y="1" width="10" height="10" fill="#7FBA00"/>
                        <rect x="1" y="13" width="10" height="10" fill="#00A4EF"/>
                        <rect x="13" y="13" width="10" height="10" fill="#FFB900"/>
                      </svg>
                    )}
                    
                    {provider === 'github' && (
                      <svg className="h-8 w-8 mr-3" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                      </svg>
                    )}
                    
                    <div>
                      <h4 className="text-sm font-medium text-gray-900 capitalize">
                        {provider}
                      </h4>
                      <p className="text-xs text-gray-500">
                        Connected
                      </p>
                    </div>
                  </div>
                  
                  <button
                    type="button"
                    onClick={() => handleUnlinkProvider(provider)}
                    disabled={isUnlinking}
                    className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    {isUnlinking ? 'Unlinking...' : 'Disconnect'}
                  </button>
                </div>
              ))}
              
              {/* Available Providers */}
              {availableProviders.map(provider => (
                <div key={provider} className="px-4 py-5 sm:px-6 flex justify-between items-center">
                  <div className="flex items-center">
                    {provider === 'google' && (
                      <svg className="h-8 w-8 mr-3" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <g transform="matrix(1, 0, 0, 1, 27.009001, -39.238998)">
                          <path fill="#4285F4" d="M -3.264 51.509 C -3.264 50.719 -3.334 49.969 -3.454 49.239 L -14.754 49.239 L -14.754 53.749 L -8.284 53.749 C -8.574 55.229 -9.424 56.479 -10.684 57.329 L -10.684 60.329 L -6.824 60.329 C -4.564 58.239 -3.264 55.159 -3.264 51.509 Z"/>
                          <path fill="#34A853" d="M -14.754 63.239 C -11.514 63.239 -8.804 62.159 -6.824 60.329 L -10.684 57.329 C -11.764 58.049 -13.134 58.489 -14.754 58.489 C -17.884 58.489 -20.534 56.379 -21.484 53.529 L -25.464 53.529 L -25.464 56.619 C -23.494 60.539 -19.444 63.239 -14.754 63.239 Z"/>
                          <path fill="#FBBC05" d="M -21.484 53.529 C -21.734 52.809 -21.864 52.039 -21.864 51.239 C -21.864 50.439 -21.724 49.669 -21.484 48.949 L -21.484 45.859 L -25.464 45.859 C -26.284 47.479 -26.754 49.299 -26.754 51.239 C -26.754 53.179 -26.284 54.999 -25.464 56.619 L -21.484 53.529 Z"/>
                          <path fill="#EA4335" d="M -14.754 43.989 C -12.984 43.989 -11.404 44.599 -10.154 45.789 L -6.734 42.369 C -8.804 40.429 -11.514 39.239 -14.754 39.239 C -19.444 39.239 -23.494 41.939 -25.464 45.859 L -21.484 48.949 C -20.534 46.099 -17.884 43.989 -14.754 43.989 Z"/>
                        </g>
                      </svg>
                    )}
                    
                    {provider === 'microsoft' && (
                      <svg className="h-8 w-8 mr-3" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <rect x="1" y="1" width="10" height="10" fill="#F25022"/>
                        <rect x="13" y="1" width="10" height="10" fill="#7FBA00"/>
                        <rect x="1" y="13" width="10" height="10" fill="#00A4EF"/>
                        <rect x="13" y="13" width="10" height="10" fill="#FFB900"/>
                      </svg>
                    )}
                    
                    {provider === 'github' && (
                      <svg className="h-8 w-8 mr-3" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                      </svg>
                    )}
                    
                    <div>
                      <h4 className="text-sm font-medium text-gray-900 capitalize">
                        {provider}
                      </h4>
                      <p className="text-xs text-gray-500">
                        Not connected
                      </p>
                    </div>
                  </div>
                  
                  <button
                    type="button"
                    onClick={() => linkProvider(provider)}
                    className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                  >
                    Connect
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
        
        {/* Account Actions */}
        <div className="bg-white shadow overflow-hidden sm:rounded-lg">
          <div className="px-4 py-5 sm:px-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900">Account Actions</h3>
            <p className="mt-1 max-w-2xl text-sm text-gray-500">Manage your account settings.</p>
          </div>
          <div className="border-t border-gray-200 px-4 py-5 sm:px-6">
            <button
              type="button"
              onClick={logout}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
            >
              Sign Out
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfile;