// /shared/src/schemas/user.ts
import { z } from 'zod';

// User schema
export const UserSchema = z.object({
  id: z.string().uuid().optional(),
  email: z.string().email(),
  password_hash: z.string().optional(), // Only used in backend
  created_at: z.date().optional(),
  updated_at: z.date().optional()
});

// Schema for creating a new user
export const RegisterUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters long")
});

// Schema for user login
export const LoginUserSchema = z.object({
  email: z.string().email(),
  password: z.string()
});

// Schema for user response (excludes sensitive info)
export const UserResponseSchema = UserSchema.omit({ 
  password_hash: true 
});

// Schema for auth response
export const AuthResponseSchema = z.object({
  user: UserResponseSchema,
  token: z.string()
});

// Derived TypeScript types
export type User = z.infer<typeof UserSchema>;
export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginUserInput = z.infer<typeof LoginUserSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;
export type AuthResponse = z.infer<typeof AuthResponseSchema>;