// /backend/src/utils/sanitize.ts
import { ApiError } from './ApiError';
import { Request, Response, NextFunction } from 'express';

export const sanitization = {
    /**
     * Creates a sanitized API error from any error
     */
    handleError(error: any, message: string, next: NextFunction): void {
        console.error('Original error:', error); // Log for debugging but don't expose
        const sanitizedError = ApiError.internal(message);
        next(sanitizedError);
    },

    // ==================== INPUT SANITIZATION (Gatekeeper Level) ====================

    /**
     * Sanitizes file names to prevent directory traversal and other attacks
     */
    sanitizeFileName(filename: string): string {
        if (typeof filename !== 'string') {
            return 'unknown_file';
        }

        return filename
            // Remove dangerous characters
            .replace(/[<>:"|?*\x00-\x1f]/g, '_')
            // Remove path separators
            .replace(/[/\\]/g, '_')
            // Remove leading dots (hidden files)
            .replace(/^\.+/, '')
            // Limit length
            .substring(0, 255)
            // Ensure not empty
            || 'sanitized_file';
    },

    /**
     * Sanitizes user input strings for XSS prevention
     */
    sanitizeUserInput(input: string): string {
        if (typeof input !== 'string') {
            return '';
        }

        return input
            // Remove HTML tags
            .replace(/<[^>]*>/g, '')
            // Remove script content
            .replace(/javascript:/gi, '')
            .replace(/data:/gi, '')
            // Remove potential XSS vectors
            .replace(/on\w+\s*=/gi, '')
            // Normalize whitespace
            .replace(/\s+/g, ' ')
            .trim();
    },

    /**
     * Sanitizes request headers
     */
    sanitizeHeaders(headers: Record<string, any>): Record<string, string> {
        const sanitized: Record<string, string> = {};
        const allowedHeaders = [
            'user-agent', 'accept', 'accept-language', 'accept-encoding',
            'content-type', 'content-length', 'authorization'
        ];

        Object.entries(headers).forEach(([key, value]) => {
            const lowerKey = key.toLowerCase();
            if (allowedHeaders.includes(lowerKey) && typeof value === 'string') {
                sanitized[lowerKey] = this.sanitizeUserInput(value).substring(0, 500);
            }
        });

        return sanitized;
    },

    /**
     * Sanitizes upload context for logging and processing
     */
    sanitizeUploadContext(req: Request): Record<string, any> {
        return {
            method: req.method,
            path: req.path,
            userAgent: this.sanitizeUserInput(req.get('User-Agent') || ''),
            contentType: this.sanitizeUserInput(req.get('Content-Type') || ''),
            contentLength: req.get('Content-Length'),
            userId: req.user?.id,
            timestamp: new Date().toISOString()
        };
    },

    // ==================== PATH SANITIZATION ====================

    /**
     * Sanitizes file paths to API routes
     */
    sanitizePath(resourceType: string, resourceId: string, pathType: string): string {
        const sanitizedResourceType = this.sanitizePathComponent(resourceType);
        const sanitizedResourceId = this.sanitizePathComponent(resourceId);
        const sanitizedPathType = this.sanitizePathComponent(pathType);
        
        return `/api/v1/${sanitizedResourceType}/${sanitizedResourceId}/${sanitizedPathType}`;
    },

    /**
     * Sanitizes individual path components
     */
    sanitizePathComponent(component: string): string {
        if (typeof component !== 'string') {
            return 'unknown';
        }

        return component
            .replace(/[^a-zA-Z0-9\-_]/g, '')
            .toLowerCase()
            .substring(0, 50) || 'unknown';
    },

    // ==================== ENTITY-SPECIFIC SANITIZATION ====================

    /**
     * Sanitizes image data for response
     */
    sanitizeImageForResponse(image: any): any {
        const allowedFields = [
            'id',
            'status', 
            'upload_date',
            'created_at',
            'updated_at'
        ];

        const pathFields = {
            file_path: { resourceType: 'images', pathType: 'file' }
        };

        const sanitized = this.createSanitizedResponse(image, allowedFields, pathFields);
        
        // Add sanitized metadata
        if (image.original_metadata) {
            sanitized.metadata = this.sanitizeImageMetadata(image.original_metadata);
        }

        return sanitized;
    },

    /**
     * Sanitizes image metadata
     */
    sanitizeImageMetadata(metadata: Record<string, any>): Record<string, any> {
        const allowedFields = [
            'filename', 'width', 'height', 'format', 'size', 
            'mimetype', 'uploadedAt', 'density', 'channels', 'space'
        ];

        const sanitized: Record<string, any> = {};
        
        allowedFields.forEach(field => {
            if (metadata[field] !== undefined) {
                // Sanitize string values
                if (typeof metadata[field] === 'string') {
                    sanitized[field] = this.sanitizeUserInput(metadata[field]);
                } else if (typeof metadata[field] === 'number') {
                    sanitized[field] = metadata[field];
                } else if (field === 'uploadedAt' && metadata[field]) {
                    sanitized[field] = metadata[field];
                }
            }
        });

        return sanitized;
    },

    /**
     * Sanitizes polygon data for response
     */
    sanitizePolygonForResponse(polygon: any): any {
        const allowedFields = [
            'id',
            'original_image_id',
            'label',
            'created_at',
            'updated_at'
        ];

        const sanitized = this.createSanitizedResponse(polygon, allowedFields);
        
        // Sanitize points array
        if (Array.isArray(polygon.points)) {
            sanitized.points = polygon.points.map((point: any) => ({
                x: typeof point.x === 'number' ? point.x : 0,
                y: typeof point.y === 'number' ? point.y : 0
            }));
        }

        // Sanitize metadata
        if (polygon.metadata) {
            sanitized.metadata = this.sanitizePolygonMetadata(polygon.metadata);
        }

        return sanitized;
    },

    /**
     * Sanitizes polygon metadata
     */
    sanitizePolygonMetadata(metadata: Record<string, any>): Record<string, any> {
        const allowedFields = ['label', 'confidence', 'source', 'notes'];
        const sanitized: Record<string, any> = {};
        
        allowedFields.forEach(field => {
            if (metadata[field] !== undefined) {
                if (typeof metadata[field] === 'string') {
                    sanitized[field] = this.sanitizeUserInput(metadata[field]).substring(0, 500);
                } else if (typeof metadata[field] === 'number') {
                    sanitized[field] = Math.max(0, Math.min(1, metadata[field])); // Clamp confidence to 0-1
                }
            }
        });

        return sanitized;
    },

    /**
     * Sanitizes garment metadata to only include allowed fields
     */
    sanitizeGarmentMetadata(metadata: Record<string, any>): Record<string, any> {
        const sanitized: Record<string, any> = {};

        // Define allowed fields with their validation rules
        const allowedFields = {
            type: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 50) : undefined,
            color: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 30) : undefined,
            pattern: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 50) : undefined,
            season: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 20) : undefined,
            brand: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 50) : undefined,
            size: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 20) : undefined,
            material: (value: any) => typeof value === 'string' ? this.sanitizeUserInput(value).substring(0, 100) : undefined,
            tags: (value: any) => Array.isArray(value) ? 
                value.slice(0, 10).map(tag => 
                    typeof tag === 'string' ? this.sanitizeUserInput(tag).substring(0, 30) : ''
                ).filter(tag => tag.length > 0) : []
        };

        // Apply sanitization to each allowed field
        Object.entries(allowedFields).forEach(([field, sanitizer]) => {
            if (metadata[field] !== undefined) {
                const sanitizedValue = sanitizer(metadata[field]);
                if (sanitizedValue !== undefined) {
                    sanitized[field] = sanitizedValue;
                }
            }
        });

        return sanitized;
    },

    /**
     * Creates a sanitized garment response object
     */
    sanitizeGarmentForResponse(garment: any): any {
        const allowedFields = [
            'id',
            'original_image_id',
            'created_at',
            'updated_at',
            'data_version'
        ];

        const pathFields = {
            file_path: { resourceType: 'garments', pathType: 'image' },
            mask_path: { resourceType: 'garments', pathType: 'mask' }
        };

        const sanitized = this.createSanitizedResponse(garment, allowedFields, pathFields);
        
        // Add sanitized metadata
        sanitized.metadata = this.sanitizeGarmentMetadata(garment.metadata || {});
        
        return sanitized;
    },

    /**
     * Sanitizes wardrobe data for response
     */
    sanitizeWardrobeForResponse(wardrobe: any): any {
        const allowedFields = [
            'id',
            'name',
            'description',
            'created_at',
            'updated_at'
        ];

        const sanitized = this.createSanitizedResponse(wardrobe, allowedFields);
        
        // Sanitize text fields
        if (sanitized.name) {
            sanitized.name = this.sanitizeUserInput(sanitized.name).substring(0, 100);
        }
        
        if (sanitized.description) {
            sanitized.description = this.sanitizeUserInput(sanitized.description).substring(0, 1000);
        }

        // Sanitize garments array if present
        if (Array.isArray(wardrobe.garments)) {
            sanitized.garments = wardrobe.garments.map((garment: any) => 
                this.sanitizeGarmentForResponse(garment)
            );
        }

        return sanitized;
    },

    // ==================== UNIVERSAL RESPONSE SANITIZATION ====================

    /**
     * Creates a sanitized response object
     */
    createSanitizedResponse<T extends Record<string, any>>(
        object: T, 
        allowedFields: (keyof T)[],
        pathFields?: {[key: string]: {resourceType: string, pathType: string}}
    ): Partial<T> {
        // Create a new object with only allowed fields
        const sanitized: Partial<T> = {};
        
        allowedFields.forEach(field => {
            if (object[field] !== undefined) {
                sanitized[field] = object[field];
            }
        });
        
        // Sanitize any paths
        if (pathFields && sanitized.id) {
            Object.entries(pathFields).forEach(([field, config]) => {
                if (field in object) {
                    sanitized[field as keyof T] = this.sanitizePath(
                        config.resourceType, 
                        sanitized.id as string, 
                        config.pathType
                    ) as unknown as T[keyof T];
                }
            });
        }
        
        return sanitized;
    },

    /**
     * Universal security sanitization for any data
     */
    sanitizeForSecurity(data: any): any {
        if (data === null || data === undefined) {
            return data;
        }

        if (typeof data === 'string') {
            return this.sanitizeUserInput(data);
        }

        if (Array.isArray(data)) {
            return data.map(item => this.sanitizeForSecurity(item));
        }

        if (typeof data === 'object') {
            const sanitized: any = {};
            Object.entries(data).forEach(([key, value]) => {
                const sanitizedKey = this.sanitizeUserInput(key);
                sanitized[sanitizedKey] = this.sanitizeForSecurity(value);
            });
            return sanitized;
        }

        return data;
    },

    // ==================== CONTROLLER WRAPPERS ====================

    /**
     * Wraps controller methods with standardized try/catch sanitization
     */
    wrapController(
        controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>, 
        entityType: string,
        operation: string
    ) {
        return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
            try {
                await controllerFn(req, res, next);
            } catch (error) {
                this.handleError(error, `An error occurred while ${operation} the ${entityType}`, next);
            }
        };
    },

    /**
     * Specialized wrapper for garment controller methods
     */
    wrapGarmentController(
        controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
        operation: string
    ) {
        return this.wrapController(controllerFn, 'garment', operation);
    },

    /**
     * Specialized wrapper for image controller methods
     */
    wrapImageController(
        controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
        operation: string
    ) {
        return this.wrapController(controllerFn, 'image', operation);
    },

    /**
     * Specialized wrapper for polygon controller methods
     */
    wrapPolygonController(
        controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
        operation: string
    ) {
        return this.wrapController(controllerFn, 'polygon', operation);
    },

    /**
     * Specialized wrapper for wardrobe controller methods
     */
    wrapWardrobeController(
        controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
        operation: string
    ) {
        return this.wrapController(controllerFn, 'wardrobe', operation);
    }
};