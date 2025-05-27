// /backend/src/models/testUserModel.ts

import { TestDatabaseConnection } from '../utils/testDatabaseConnection';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../utils/ApiError';

// Helper function to validate UUID format
const isValidUUID = (uuid: string): boolean => {
    if (!uuid || typeof uuid !== 'string') return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
};

export const testUserModel = {
    async create(data: any) {
        const { email, password } = data;
        
        // Validate required fields
        if (!email || !password) {
            throw new Error('Email and password are required');
        }
        
        // Check if user with email already exists
        const existingUser = await TestDatabaseConnection.query(
            'SELECT * FROM users WHERE email = $1', 
            [email]
        );
        if (existingUser.rows.length > 0) {
            throw ApiError.conflict('User with this email already exists', 'EMAIL_IN_USE');
        }
        
        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Generate UUID
        const id = uuidv4();
        
        // Insert user
        const result = await TestDatabaseConnection.query(
            'INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, email, created_at',
            [id, email, passwordHash]
        );
        
        return result.rows[0];
    },

    async findById(id: string) {
        // Handle malformed UUIDs gracefully
        if (!id || !isValidUUID(id)) {
            return null;
        }
        
        try {
                const result = await TestDatabaseConnection.query(
                'SELECT id, email, created_at FROM users WHERE id = $1',
                [id]
            );
            return result.rows[0] || null;
        } catch (error) {
            // If it's a UUID format error, return null instead of throwing
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return null;
            }
            throw error;
        }
    },

    async findByEmail(email: string) {
        if (!email) {
            return null;
        }
        
        const result = await TestDatabaseConnection.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );
        return result.rows[0] || null;
    },

    async validatePassword(user: any, password: string) {
        if (!user || !user.password_hash || !password) {
            return false;
        }
        return bcrypt.compare(password, user.password_hash);
    },

    async updateEmail(id: string, email: string) {
        if (!id || !isValidUUID(id) || !email) {
            return null;
        }
        
        try {
            // Check if email is already in use
            const existingUser = await TestDatabaseConnection.query(
            'SELECT * FROM users WHERE email = $1 AND id != $2', 
            [email, id]
            );
            if (existingUser.rows.length > 0) {
            throw ApiError.conflict('Email is already in use', 'EMAIL_IN_USE');
            }
            
            const result = await TestDatabaseConnection.query(
            'UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, created_at',
            [email, id]
            );
            return result.rows[0] || null;
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return null;
            }
            throw error;
        }
    },

    async updatePassword(id: string, newPassword: string) {
        if (!id || !isValidUUID(id) || !newPassword) {
            return false;
        }
        
        try {
            const saltRounds = 10;
            const passwordHash = await bcrypt.hash(newPassword, saltRounds);
            
            const result = await TestDatabaseConnection.query(
            'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
            [passwordHash, id]
            );
            return (result.rowCount ?? 0) > 0;
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return false;
            }
            throw error;
        }
    },

    async delete(id: string) {
        if (!id || !isValidUUID(id)) {
            return false;
        }
        
        try {
            const result = await TestDatabaseConnection.query(
            'DELETE FROM users WHERE id = $1',
            [id]
            );
            return (result.rowCount ?? 0) > 0;
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return false;
            }
            throw error;
        }
    },

    async getUserStats(id: string) {
        if (!id || !isValidUUID(id)) {
            return {
            imageCount: 0,
            garmentCount: 0,
            wardrobeCount: 0
            };
        }
        
        try {
            const [imageResult, garmentResult, wardrobeResult] = await Promise.all([
            TestDatabaseConnection.query(
                'SELECT COUNT(*) as image_count FROM original_images WHERE user_id = $1',
                [id]
            ),
            TestDatabaseConnection.query(
                'SELECT COUNT(*) as garment_count FROM garment_items WHERE user_id = $1',
                [id]
            ),
            TestDatabaseConnection.query(
                'SELECT COUNT(*) as wardrobe_count FROM wardrobes WHERE user_id = $1',
                [id]
            )
            ]);
            
            return {
            imageCount: parseInt(imageResult.rows[0].image_count, 10),
            garmentCount: parseInt(garmentResult.rows[0].garment_count, 10),
            wardrobeCount: parseInt(wardrobeResult.rows[0].wardrobe_count, 10)
            };
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return {
                    imageCount: 0,
                    garmentCount: 0,
                    wardrobeCount: 0
                };
            }
            throw error;
        }
    },

    async findByOAuth(provider: string, providerId: string) {
        if (!provider || !providerId) {
            return null;
        }
        
        // First, check the user_oauth_providers table for linked accounts
        const linkedResult = await TestDatabaseConnection.query(
            `SELECT u.* FROM users u
            JOIN user_oauth_providers p ON u.id = p.user_id
            WHERE p.provider = $1 AND p.provider_id = $2`,
            [provider, providerId]
        );
    
        if (linkedResult.rows.length > 0) {
            return linkedResult.rows[0];
        }
    
        // Then check the users table for direct OAuth accounts
        const result = await TestDatabaseConnection.query(
            'SELECT * FROM users WHERE oauth_provider = $1 AND oauth_id = $2',
            [provider, providerId]
        );
        return result.rows[0] || null;
    },

    async createOAuthUser(data: any) {
        const { email, name, avatar_url, oauth_provider, oauth_id } = data;
        
        // Validate required fields
        if (!email || !oauth_provider || !oauth_id) {
        throw new Error('Email, oauth_provider, and oauth_id are required');
        }
        
        // Check if user with email already exists
        const existingUser = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
        );
        if (existingUser.rows.length > 0) {
        throw ApiError.conflict('User with this email already exists', 'EMAIL_IN_USE');
        }
        
        // Generate UUID
        const id = uuidv4();
        
        // Insert user
        const result = await TestDatabaseConnection.query(
        `INSERT INTO users 
        (id, email, name, avatar_url, oauth_provider, oauth_id, created_at, updated_at) 
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) 
        RETURNING id, email, name, avatar_url, created_at`,
        [id, email, name || null, avatar_url || null, oauth_provider, oauth_id]
        );
        return result.rows[0];
    },

    async getUserWithOAuthProviders(id: string) {
        if (!id || !isValidUUID(id)) {
            return null;
        }
        
        try {
            const userResult = await TestDatabaseConnection.query(
            'SELECT id, email, name, avatar_url, oauth_provider, created_at FROM users WHERE id = $1',
            [id]
            );
            
            if (userResult.rows.length === 0) {
            return null;
            }
            
            const user = userResult.rows[0];
            
            const providersResult = await TestDatabaseConnection.query(
            'SELECT provider FROM user_oauth_providers WHERE user_id = $1',
            [id]
            );
            
            const linkedProviders = providersResult.rows.map((row: any) => row.provider);
            
            if (user.oauth_provider) {
            linkedProviders.push(user.oauth_provider);
            }
            
            return {
            ...user,
            linkedProviders
            };
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return null;
            }
            throw error;
        }
    }
};