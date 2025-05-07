// /frontend/src/hooks/useAuth.ts
import React, { useState, useCallback, createContext, useContext } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi } from '../api/authApi';
import { RegisterUserInput, LoginUserInput, UserResponse } from '../../../shared/src/schemas';

// Define the auth context state type
interface AuthContextType {
  user: UserResponse | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (data: LoginUserInput) => Promise<void>;
  register: (data: RegisterUserInput) => Promise<void>;
  logout: () => void;
  error: Error | null;
  loginWithToken: (token: string) => Promise<void>;
  linkedProviders: string[];
  linkProvider: (provider: string) => void;
  unlinkProvider: (provider: string) => Promise<void>;
}

// Create context with default values
const AuthContext = createContext<AuthContextType>({
  user: null,
  isLoading: false,
  isAuthenticated: false,
  login: async () => {},
  register: async () => {},
  logout: () => {},
  error: null,
  loginWithToken: async () => {},
  linkedProviders: [],
  linkProvider: () => {},
  unlinkProvider: async () => {}
});

// Auth provider props
interface AuthProviderProps {
  children: React.ReactNode;
}

// Auth provider component
export function AuthProvider({ children }: AuthProviderProps) {
  const [error, setError] = useState<Error | null>(null);
  const queryClient = useQueryClient();
  // REMOVED: const [linkedProviders, setLinkedProviders] = useState<string[]>([]);
  
  // Check if user is already logged in
  const initialIsAuthenticated = authApi.isLoggedIn();
  
  // Fetch user data if token exists
  const { data: userData, isLoading: isLoadingUser } = useQuery({
    queryKey: ['currentUser'],
    queryFn: authApi.me,
    enabled: initialIsAuthenticated,
    retry: false
  });
  
  // Initialize user as null instead of undefined
  const user = userData || null;
  // DERIVE linkedProviders from the user object
  const linkedProviders = user?.linkedProviders || [];
  
  // Login mutation
  const loginMutation = useMutation({
    mutationFn: authApi.login,
    onSuccess: (data) => {
      // Update current user data
      queryClient.setQueryData(['currentUser'], data.user);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err);
    }
  });
  
  // Register mutation
  const registerMutation = useMutation({
    mutationFn: authApi.register,
    onSuccess: (data) => {
      // Update current user data
      queryClient.setQueryData(['currentUser'], data.user);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err);
    }
  });
  
  // Login handler
  const login = async (data: LoginUserInput) => {
    // Error is handled in the mutation's onError, so try/catch can be removed if not needed for other logic
    await loginMutation.mutateAsync(data).catch(() => { /* Optional: specific UI feedback if needed */ });
  };
  
  // Register handler
  const register = async (data: RegisterUserInput) => {
    // Error is handled in the mutation's onError, so try/catch can be removed if not needed for other logic
    await registerMutation.mutateAsync(data).catch(() => { /* Optional: specific UI feedback if needed */ });
  };
  
  // Logout handler
  const logout = useCallback(() => {
    authApi.logout();
    queryClient.setQueryData(['currentUser'], null);
    // Invalidate all queries to refresh data when logging back in
    queryClient.invalidateQueries();
  }, [queryClient]);
  
  // Determine if user is authenticated
  const isAuthenticated = !!user;
  
  // Loading state
  const isLoading = isLoadingUser || loginMutation.isLoading || registerMutation.isLoading;
  
  // Define context methods directly or as clearly named handlers
  const contextLoginWithToken = async (token: string) => {
    setError(null); // Clear previous errors
    try {
      // authApi.loginWithToken sets the token and returns the user data
      const userResponse = await authApi.loginWithToken(token);
      // Update current user data in React Query cache
      queryClient.setQueryData(['currentUser'], userResponse);
      // linkedProviders will update automatically as it's derived from 'user'
    } catch (err) {
      localStorage.removeItem('token'); // Ensure token is cleared on error
      setError(err as Error);
      throw err; // Re-throw so the caller can react if needed
    }
  };

  const contextLinkProvider = (provider: string) => {
    const redirectUrl = window.location.href;
    window.location.href = `${process.env.REACT_APP_API_URL}/oauth/${provider}/authorize?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  const contextUnlinkProvider = async (provider: string) => {
    setError(null); // Clear previous errors
    try {
      await authApi.unlinkProvider(provider);
      // Invalidate user data to refetch and update linkedProviders
      queryClient.invalidateQueries(['currentUser']);
    } catch (err) {
      setError(err as Error);
      throw err; // Re-throw so the caller can react if needed
    }
  };

  // Provide auth context
  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    register,
    logout,
    error,
    loginWithToken: contextLoginWithToken,
    linkedProviders, // Now derived from user
    linkProvider: contextLinkProvider,
    unlinkProvider: contextUnlinkProvider,
  };
  
  /* Use standard function return without parentheses */
  return React.createElement(
    AuthContext.Provider,
    { value },
    children
  );
}

// Custom hook to use the auth context
export const useAuth = () => useContext(AuthContext);

export default useAuth;