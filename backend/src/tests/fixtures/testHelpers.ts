// /backend/src/tests/fixtures/testHelpers.ts
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';

interface CreateUserOptions {
    email?: string;
    username?: string;
    profilePicture?: string;
    provider?: string;
    providerId?: string;
}

interface CreateImageOptions {
    userId?: string;
    fileName?: string;
    filePath?: string;
    status?: 'new' | 'processed' | 'labeled' | 'error';
    metadata?: Record<string, any>;
}

interface CreateUserWithImageOptions extends CreateUserOptions {
    imageStatus?: 'new' | 'processed' | 'labeled' | 'error';
    imageMetadata?: Record<string, any>;
}

export class TestHelpers {
    /**
     * Create a test user
     */
    static async createUser(options: CreateUserOptions = {}): Promise<{ userId: string; email: string }> {
        const userId = uuidv4();
        const email = options.email || `test-${userId}@example.com`;
        const provider = options.provider || 'local';
        const providerId = options.providerId || userId;

        // Hash a default password for local users
        const passwordHash = provider === 'local' 
            ? await bcrypt.hash('testpassword123', 10)
            : null;

        await TestDatabaseConnection.query(
            `INSERT INTO users (
                id, email, password_hash, 
                created_at, updated_at
            ) VALUES ($1, $2, $3, NOW(), NOW())`,
            [
                userId, email, passwordHash
            ]
        );

        return { userId, email };
    }

    /**
     * Create a test image
     */
    static async createImage(userId: string, options: CreateImageOptions = {}): Promise<string> {
        const imageId = uuidv4();
        const fileName = options.fileName || `test-image-${imageId}.jpg`;
        const filePath = options.filePath || `images/${imageId}.jpg`;
        const status = options.status || 'new';
        const originalMetadata = options.metadata || {
            width: 1000,
            height: 800,
            size: 50000,
            format: 'jpeg'
        };

        await TestDatabaseConnection.query(
            `INSERT INTO original_images (
                id, user_id, original_filename, file_path, 
                status, original_metadata, upload_date, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW())`,
            [
                imageId, userId, fileName, filePath,
                status, JSON.stringify(originalMetadata)
            ]
        );

        return imageId;
    }

    /**
     * Create a user with an image (common test scenario)
     */
    static async createUserWithImage(options: CreateUserWithImageOptions = {}): Promise<{
        userId: string;
        email: string;
        imageId: string;
    }> {
        const { userId, email } = await this.createUser(options);
        const imageId = await this.createImage(userId, {
            status: options.imageStatus,
            metadata: options.imageMetadata
        });

        return { userId, email, imageId };
    }

    /**
     * Create a test polygon
     */
    static async createPolygon(
        userId: string,
        imageId: string,
        points: Array<{ x: number; y: number }>,
        label?: string,
        metadata?: Record<string, any>
    ): Promise<string> {
        const polygonId = uuidv4();

        await TestDatabaseConnection.query(
            `INSERT INTO polygons (
                id, user_id, original_image_id, points, 
                label, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
            [
                polygonId, userId, imageId, 
                JSON.stringify(points), label || null, 
                JSON.stringify(metadata || {})
            ]
        );

        return polygonId;
    }

    /**
     * Create a test garment
     */
    static async createGarment(
        userId: string,
        polygonId: string,
        options: {
            name?: string;
            type?: string;
            brand?: string;
            color?: string;
            pattern?: string;
            material?: string;
            size?: string;
            tags?: string[];
            metadata?: Record<string, any>;
        } = {}
    ): Promise<string> {
        const garmentId = uuidv4();
        const name = options.name || `Test Garment ${garmentId.slice(0, 8)}`;
        const type = options.type || 'shirt';

        await TestDatabaseConnection.query(
            `INSERT INTO garments (
                id, user_id, polygon_id, name, type,
                brand, color, pattern, material, size,
                tags, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())`,
            [
                garmentId, userId, polygonId, name, type,
                options.brand || null, options.color || null,
                options.pattern || null, options.material || null,
                options.size || null, JSON.stringify(options.tags || []),
                JSON.stringify(options.metadata || {})
            ]
        );

        return garmentId;
    }

    /**
     * Create a test wardrobe
     */
    static async createWardrobe(
        userId: string,
        options: {
            name?: string;
            description?: string;
            isPublic?: boolean;
        } = {}
    ): Promise<string> {
        const wardrobeId = uuidv4();
        const name = options.name || `Test Wardrobe ${wardrobeId.slice(0, 8)}`;

        await TestDatabaseConnection.query(
            `INSERT INTO wardrobes (
                id, user_id, name, description, 
                is_public, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
            [
                wardrobeId, userId, name,
                options.description || null,
                options.isPublic || false
            ]
        );

        return wardrobeId;
    }

    /**
     * Add a garment to a wardrobe
     */
    static async addGarmentToWardrobe(
        wardrobeId: string,
        garmentId: string,
        position?: number
    ): Promise<void> {
        await TestDatabaseConnection.query(
            `INSERT INTO wardrobe_items (
                wardrobe_id, garment_id, position, added_at
            ) VALUES ($1, $2, $3, NOW())`,
            [wardrobeId, garmentId, position || 0]
        );
    }

    /**
     * Wait for a condition to be true
     */
    static async waitFor(
        condition: () => boolean | Promise<boolean>,
        timeout: number = 5000,
        interval: number = 100
    ): Promise<void> {
        const startTime = Date.now();
        while (Date.now() - startTime < timeout) {
            if (await condition()) {
                return;
            }
            await new Promise(resolve => setTimeout(resolve, interval));
        }
        throw new Error(`Condition not met within ${timeout}ms`);
    }

    /**
     * Generate random points for a polygon
     */
    static generateRandomPolygonPoints(
        count: number = 4,
        maxX: number = 1000,
        maxY: number = 800
    ): Array<{ x: number; y: number }> {
        const points: Array<{ x: number; y: number }> = [];
        const centerX = maxX / 2;
        const centerY = maxY / 2;
        const radius = Math.min(maxX, maxY) / 3;

        for (let i = 0; i < count; i++) {
            const angle = (i / count) * 2 * Math.PI;
            const r = radius * (0.7 + Math.random() * 0.3); // Some variation
            points.push({
                x: Math.round(centerX + r * Math.cos(angle)),
                y: Math.round(centerY + r * Math.sin(angle))
            });
        }

        return points;
    }
}

// Export as singleton for convenience
export const testHelpers = TestHelpers;