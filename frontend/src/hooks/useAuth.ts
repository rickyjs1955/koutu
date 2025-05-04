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
}

// Create context with default values
const AuthContext = createContext<AuthContextType>({
  user: null,
  isLoading: false,
  isAuthenticated: false,
  login: async () => {},
  register: async () => {},
  logout: () => {},
  error: null
});

// Auth provider props
interface AuthProviderProps {
  children: React.ReactNode;
}

// Auth provider component
export function AuthProvider({ children }: AuthProviderProps) {
  const [error, setError] = useState<Error | null>(null);
  const queryClient = useQueryClient();
  
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
    try {
      await loginMutation.mutateAsync(data);
    } catch (err) {
      // Error is handled in the mutation
    }
  };
  
  // Register handler
  const register = async (data: RegisterUserInput) => {
    try {
      await registerMutation.mutateAsync(data);
    } catch (err) {
      // Error is handled in the mutation
    }
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
  
  // Loading state - use isLoading instead of isPending for React Query v4
  const isLoading = isLoadingUser || loginMutation.isLoading || registerMutation.isLoading;
  
  // Provide auth context
  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    register,
    logout,
    error
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