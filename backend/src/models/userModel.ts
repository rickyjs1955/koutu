// /backend/src/models/userModel.ts
import { query } from './db';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../utils/ApiError';

/**
 * Interface representing a user in the database
 */
export interface User {
  id: string;
  email: string;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
}

/**
 * Input for creating a new user
 */
export interface CreateUserInput {
  email: string;
  password: string;
}

/**
 * Output for user data (excludes sensitive information)
 */
export interface UserOutput {
  id: string;
  email: string;
  created_at: Date;
}

export interface CreateOAuthUserInput {
  email: string;
  name?: string;
  avatar_url?: string;
  oauth_provider: string;
  oauth_id: string;
}

/**
 * User model with database operations
 */
export const userModel = {
  /**
   * Create a new user
   */
  async create(data: CreateUserInput): Promise<UserOutput> {
    const { email, password } = data;
    
    // Check if user with email already exists
    const existingUser = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      throw ApiError.conflict('User with this email already exists', 'EMAIL_IN_USE');
    }
    
    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    // Generate UUID
    const id = uuidv4();
    
    // Insert user
    const result = await query(
      'INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, email, created_at',
      [id, email, passwordHash]
    );
    
    return result.rows[0];
  },
  
  /**
   * Find a user by ID
   */
  async findById(id: string): Promise<UserOutput | null> {
    const result = await query(
      'SELECT id, email, created_at FROM users WHERE id = $1',
      [id]
    );
    
    return result.rows[0] || null;
  },
  
  /**
   * Find a user by email
   */
  async findByEmail(email: string): Promise<User | null> {
    const result = await query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    return result.rows[0] || null;
  },
  
  /**
   * Validate user password
   */
  async validatePassword(user: User, password: string): Promise<boolean> {
    return bcrypt.compare(password, user.password_hash);
  },
  
  /**
   * Update user email
   */
  async updateEmail(id: string, email: string): Promise<UserOutput | null> {
    // Check if email is already in use
    const existingUser = await query('SELECT * FROM users WHERE email = $1 AND id != $2', [email, id]);
    if (existingUser.rows.length > 0) {
      throw ApiError.conflict('Email is already in use', 'EMAIL_IN_USE');
    }
    
    const result = await query(
      'UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, created_at',
      [email, id]
    );
    
    return result.rows[0] || null;
  },
  
  /**
   * Update user password
   */
  async updatePassword(id: string, newPassword: string): Promise<boolean> {
    // Hash new password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);
    
    const result = await query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [passwordHash, id]
    );
    
    return (result.rowCount ?? 0) > 0;
  },
  
  /**
   * Delete a user
   */
  async delete(id: string): Promise<boolean> {
    const result = await query(
      'DELETE FROM users WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  },
  
  /**
   * Get user statistics
   */
  async getUserStats(id: string): Promise<any> {
    // Get count of images, garments, and wardrobes
    const imageCountResult = await query(
      'SELECT COUNT(*) as image_count FROM original_images WHERE user_id = $1',
      [id]
    );
    
    const garmentCountResult = await query(
      'SELECT COUNT(*) as garment_count FROM garment_items WHERE user_id = $1',
      [id]
    );
    
    const wardrobeCountResult = await query(
      'SELECT COUNT(*) as wardrobe_count FROM wardrobes WHERE user_id = $1',
      [id]
    );
    
    return {
      imageCount: parseInt(imageCountResult.rows[0].image_count, 10),
      garmentCount: parseInt(garmentCountResult.rows[0].garment_count, 10),
      wardrobeCount: parseInt(wardrobeCountResult.rows[0].wardrobe_count, 10)
    };
  },

  /**
   * Find user by OAuth provider and ID (using only user_oauth_providers table)
   */
  async findByOAuth(provider: string, providerId: string): Promise<User | null> {
    // Only check the user_oauth_providers table for linked accounts
    const result = await query(
      `SELECT u.* FROM users u
       JOIN user_oauth_providers p ON u.id = p.user_id
       WHERE p.provider = $1 AND p.provider_id = $2`,
      [provider, providerId]
    );
  
    return result.rows[0] || null;
  },
  
  /**
   * Create OAuth user (creates user without password and links OAuth provider)
   */
  async createOAuthUser(data: CreateOAuthUserInput): Promise<UserOutput> {
    const { email, oauth_provider, oauth_id } = data;
    
    // Check if user with email already exists
    const existingUser = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      throw ApiError.conflict('User with this email already exists', 'EMAIL_IN_USE');
    }
    
    // Generate UUID
    const id = uuidv4();
    
    try {
      // Start transaction
      await query('BEGIN');
      
      // Insert user without password (OAuth users don't need passwords)
      const userResult = await query(
        `INSERT INTO users 
        (id, email, created_at, updated_at) 
        VALUES ($1, $2, NOW(), NOW()) 
        RETURNING id, email, created_at`,
        [id, email]
      );
      
      // Insert OAuth provider info
      await query(
        `INSERT INTO user_oauth_providers 
        (user_id, provider, provider_id, created_at) 
        VALUES ($1, $2, $3, NOW())`,
        [id, oauth_provider, oauth_id]
      );
      
      // Commit transaction
      await query('COMMIT');
      
      return userResult.rows[0];
    } catch (error) {
      // Rollback transaction on error
      await query('ROLLBACK');
      throw error;
    }
  },
  
  /**
   * Get user with OAuth providers (modified to work without schema changes)
   */
  async getUserWithOAuthProviders(id: string): Promise<any> {
    const userResult = await query(
      'SELECT id, email, created_at FROM users WHERE id = $1',
      [id]
    );
    
    if (userResult.rows.length === 0) {
      return null;
    }
    
    const user = userResult.rows[0];
    
    // Get linked OAuth providers
    const providersResult = await query(
      'SELECT provider FROM user_oauth_providers WHERE user_id = $1',
      [id]
    );
    
    const linkedProviders = providersResult.rows.map(row => row.provider);
    
    return {
      ...user,
      linkedProviders,
      // Add placeholder fields for compatibility
      name: null,
      avatar_url: null,
      oauth_provider: null
    };
  },

  /**
   * Link OAuth provider to existing user
   */
  async linkOAuthProvider(userId: string, provider: string, providerId: string): Promise<boolean> {
    try {
      await query(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id, created_at) VALUES ($1, $2, $3, NOW())',
        [userId, provider, providerId]
      );
      return true;
    } catch (error) {
      // Handle duplicate key error gracefully
      return false;
    }
  },

  /**
   * Unlink OAuth provider from user
   */
  async unlinkOAuthProvider(userId: string, provider: string): Promise<boolean> {
    const result = await query(
      'DELETE FROM user_oauth_providers WHERE user_id = $1 AND provider = $2',
      [userId, provider]
    );
    
    return (result.rowCount ?? 0) > 0;
  },

  /**
   * Check if user has password (for OAuth-only users)
   */
  async hasPassword(userId: string): Promise<boolean> {
    const result = await query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId]
    );
    
    return result.rows[0]?.password_hash != null;
  }
};