// /frontend/src/api/authApi.ts
import api from './index';
import { 
  RegisterUserInput, 
  LoginUserInput, 
  AuthResponse, 
  UserResponse 
} from '../../../shared/src/schemas';

export const authApi = {
  /**
   * Register a new user
   */
  async register(data: RegisterUserInput): Promise<AuthResponse> {
    const response = await api.post('/auth/register', data);
    
    // Store the token if registration was successful
    const { token } = response.data.data;
    localStorage.setItem('token', token);
    
    return response.data.data;
  },
  
  /**
   * Login a user
   */
  async login(data: LoginUserInput): Promise<AuthResponse> {
    const response = await api.post('/auth/login', data);
    
    // Store the token if login was successful
    const { token } = response.data.data;
    localStorage.setItem('token', token);
    
    return response.data.data;
  },
  
  /**
   * Get the current user's information
   */
  async me(): Promise<UserResponse> {
    const response = await api.get('/auth/me');
    return response.data.data.user;
  },
  
  /**
   * Logout the current user
   */
  logout(): void {
    localStorage.removeItem('token');
  },
  
  /**
   * Check if a user is logged in
   */
  isLoggedIn(): boolean {
    return !!localStorage.getItem('token');
  }
};