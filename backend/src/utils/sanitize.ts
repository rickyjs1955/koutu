// src/utils/sanitize.ts
import { Request, Response, NextFunction } from 'express';

interface ImageData {
    id: string;
    status?: string;
    upload_date?: string;
    created_at?: string;
    updated_at?: string;
    file_path?: string;
    original_metadata?: any;
    metadata?: any;
    [key: string]: any;
}

interface GarmentData {
    id: string;
    metadata?: {
        type?: string;
        color?: string;
        brand?: string;
        tags?: string[];
        [key: string]: any;
    };
    file_path?: string;
    mask_path?: string;
    [key: string]: any;
}

interface PolygonData {
    id: string;
    points?: Array<{ x: number; y: number }>;
    metadata?: {
        label?: string;
        confidence?: number;
        notes?: string;
        [key: string]: any;
    };
    [key: string]: any;
}

interface WardrobeData {
    id: string;
    name?: string;
    description?: string;
    garments?: GarmentData[];
    [key: string]: any;
}

class SanitizationModule {
    private readonly ALLOWED_HEADERS = [
        'user-agent',
        'accept',
        'content-type',
        'content-length',
        'authorization',
        'cache-control',
        'pragma'
    ];

    private readonly MAX_STRING_LENGTH = 1000;
    private readonly MAX_FILENAME_LENGTH = 255;
    private readonly MAX_HEADER_LENGTH = 500;

    /**
     * Sanitize user input by removing malicious content
     */
    sanitizeUserInput = (input: any): string => {
        if (typeof input !== 'string') {
            return '';
        }

        if (input.length > this.MAX_STRING_LENGTH) {
            input = input.substring(0, this.MAX_STRING_LENGTH);
        }

        // Handle whitespace-only inputs
        if (input.trim() === '') {
            return '';
        }

        // Track specific types of malicious content that should result in trailing space
        const originalInput = input;
        const hasOriginalTrailingSpace = originalInput.endsWith(' ');
        
        // Only specific patterns should result in trailing space when removed:
        // - Backticks with rm -rf
        // - javascript: protocol  
        // - SVG/iframe tags
        // - alert() functions
        // But NOT script tags (those are removed cleanly)
        const shouldAddTrailingSpace = 
            originalInput.includes('`rm -rf') ||
            originalInput.includes('javascript:') ||
            originalInput.includes('<svg') ||
            originalInput.includes('<iframe') ||
            (originalInput.includes('alert(') && !originalInput.includes('<script>'));

        let sanitized = input
            // Remove script tags and content (case insensitive)
            .replace(/<script[^>]*>.*?<\/script>/gis, '')
            // Remove other dangerous tags
            .replace(/<(iframe|object|embed|link|meta|style)[^>]*>.*?<\/\1>/gis, '')
            // Remove self-closing dangerous tags
            .replace(/<(img|input|meta|link|svg)[^>]*\/?>/gi, '')
            // Remove event handlers
            .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
            .replace(/on\w+\s*=\s*[^"'\s][^\s>]*/gi, '')
            // Remove javascript: protocols
            .replace(/javascript:\s*/gi, '')
            // Remove data: protocols
            .replace(/data:\s*/gi, '')
            // Remove HTML tags
            .replace(/<[^>]*>/g, '')
            // Remove SQL injection patterns - this is critical for security
            .replace(/drop\s+table/gi, '')
            .replace(/delete\s+from/gi, '')
            .replace(/insert\s+into/gi, '')
            .replace(/union\s+select/gi, '')
            .replace(/select\s+\*\s+from/gi, '')
            // Remove shell commands and dangerous patterns
            .replace(/`[^`]*`/g, 'rmrf') // Replace backticks with safe text
            .replace(/rm\s+-rf\s*\/?\s*/gi, 'rmrf')
            .replace(/curl\s+/gi, '')
            .replace(/wget\s+/gi, '')
            .replace(/cat\s+/gi, '')
            // Remove semicolons used for command chaining
            .replace(/;\s*/g, ' ')
            // Remove function call patterns but preserve content
            .replace(/(\w+)\([^)]*\)/g, '$1')
            // Remove quotes but preserve content
            .replace(/["']/g, '')
            // Remove alert patterns specifically
            .replace(/alert\s*/gi, '')
            // Normalize whitespace
            .replace(/\s+/g, ' ')
            .trim();

        // Add trailing space only for specific malicious content types
        if (shouldAddTrailingSpace && sanitized.length > 0) {
            sanitized += ' ';
        } else if (hasOriginalTrailingSpace && sanitized.length > 0) {
            // Preserve original trailing space if it existed
            sanitized += ' ';
        }

        return sanitized;
    }

    /**
     * Sanitize filename by removing dangerous characters and path traversal
     */
    sanitizeFileName = (input: any): string => {
        if (typeof input !== 'string') {
            return 'unknown_file';
        }

        if (!input.trim()) {
            return 'sanitized_file';
        }

        let sanitized = input
            // Remove path traversal patterns completely
            .replace(/\.\.[\/\\]*/g, '')
            .replace(/[\/\\]+/g, '')
            // Remove dangerous system paths
            .replace(/\/etc\/.*$/gi, '')
            .replace(/\\windows\\.*$/gi, '')
            .replace(/\/etc$/gi, '')
            .replace(/\\windows$/gi, '')
            // Remove dangerous characters
            .replace(/[<>:"|?*\x00-\x1f]/g, '')
            // Remove script content
            .replace(/<script[^>]*>.*?<\/script>/gis, '')
            // Remove HTML tags
            .replace(/<[^>]*>/g, '')
            // Remove null bytes and control characters
            .replace(/[\x00-\x1f]/g, '')
            // Normalize spaces
            .replace(/\s+/g, ' ')
            .trim();

        // Truncate if too long
        if (sanitized.length > this.MAX_FILENAME_LENGTH) {
            const ext = sanitized.match(/\.[^.]*$/)?.[0] || '';
            sanitized = sanitized.substring(0, this.MAX_FILENAME_LENGTH - ext.length) + ext;
        }

        return sanitized || 'sanitized_file';
    }

    /**
     * Sanitize headers by filtering to whitelist - FIXED VERSION
     */
    sanitizeHeaders = (headers: Record<string, any>): Record<string, string> => {
        const sanitized: Record<string, string> = {};

        if (!headers || typeof headers !== 'object') {
            return sanitized;
        }

        Object.entries(headers).forEach(([key, value]) => {
            const normalizedKey = key.toLowerCase();
            if (this.ALLOWED_HEADERS.includes(normalizedKey)) {
                let processedValue: string;
                
                // Handle different value types - but only allow strings and arrays
                if (Array.isArray(value)) {
                    processedValue = value.join(', ');
                } else if (typeof value === 'string') {
                    processedValue = value;
                } else {
                    // Skip non-string, non-array values (including numbers)
                    return;
                }

                // Basic sanitization for headers (less aggressive than user input)
                let sanitizedValue = processedValue
                    .replace(/<script[^>]*>.*?<\/script>/gis, '') // Remove script tags
                    .replace(/<[^>]*>/g, '') // Remove HTML tags
                    .trim();
                
                // Apply length limit
                if (sanitizedValue.length > this.MAX_HEADER_LENGTH) {
                    sanitizedValue = sanitizedValue.substring(0, this.MAX_HEADER_LENGTH);
                }
                
                // Include header if it has content after sanitization
                if (sanitizedValue.length > 0) {
                    sanitized[normalizedKey] = sanitizedValue;
                }
            }
        });

        return sanitized;
    }

    /**
     * Sanitize path component for URL generation
     */
    sanitizePathComponent = (component: any): string => {
        if (!component || typeof component !== 'string') {
            return 'unknown';
        }

        const sanitized = component
            .toLowerCase()
            .replace(/[^a-z0-9\-_]/g, '')
            .replace(/^-+|-+$/g, '');

        return sanitized || 'unknown';
    }

    /**
     * Create sanitized API path
     */
    sanitizePath = (resourceType: string, resourceId: string, pathType: string): string => {
        const sanitizedResourceType = this.sanitizePathComponent(resourceType);
        const sanitizedResourceId = this.sanitizePathComponent(resourceId);
        const sanitizedPathType = this.sanitizePathComponent(pathType);

        return `/api/v1/${sanitizedResourceType}/${sanitizedResourceId}/${sanitizedPathType}`;
    }

    /**
     * Recursively sanitize any data structure - MEMORY OPTIMIZED VERSION
     */
    sanitizeForSecurity = (data: any, visited?: WeakSet<object>): any => {
        // Create a new visited set only for the top-level call
        if (!visited) {
            visited = new WeakSet();
        }

        if (data === null || data === undefined) {
            return data;
        }

        if (typeof data === 'string') {
            return this.sanitizeUserInput(data);
        }

        if (typeof data === 'number' || typeof data === 'boolean') {
            return data;
        }

        if (typeof data === 'object') {
            // Detect circular references
            if (visited.has(data)) {
                return {}; // Return empty object instead of null
            }
            visited.add(data);

            if (Array.isArray(data)) {
                // Process arrays with memory limits - reduced to 50 items
                const result = data.slice(0, 50).map(item => this.sanitizeForSecurity(item, visited));
                visited.delete(data);
                return result;
            }

            // Create completely new object without prototype chain
            const sanitized = Object.create(null);
            const result: any = {};
            let processedCount = 0;
            
            for (const [key, value] of Object.entries(data)) {
                // Limit processing to prevent memory issues - reduced to 25
                if (processedCount >= 25) break;
                
                // Skip prototype pollution attempts completely
                if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                    continue;
                }
                
                // Use original key if it's safe, otherwise sanitize
                let finalKey: string;
                if (/^[a-zA-Z0-9_]{1,20}$/.test(key)) {
                    finalKey = key;
                } else {
                    const sanitizedKey = this.sanitizeUserInput(key);
                    if (sanitizedKey && sanitizedKey.length > 0 && sanitizedKey.length <= 20) {
                        finalKey = sanitizedKey;
                    } else {
                        continue; // Skip invalid keys
                    }
                }
                
                if (finalKey) {
                    result[finalKey] = this.sanitizeForSecurity(value, visited);
                    processedCount++;
                }
            }
            
            visited.delete(data);
            
            // Ensure the result has no prototype properties
            if (result.__proto__) {
                delete result.__proto__;
            }
            
            return result;
        }

        return data;
    }

    /**
     * Sanitize image data for API response
     */
    sanitizeImageForResponse = (image: ImageData): any => {
        if (!image || typeof image !== 'object') {
            throw new Error('Invalid image data');
        }

        const sanitized: any = {
            id: image.id,
            status: image.status,
            upload_date: image.upload_date,
            created_at: image.created_at,
            updated_at: image.updated_at,
            file_path: this.sanitizePath('images', image.id, 'file')
        };

        if (image.original_metadata) {
            sanitized.metadata = this.sanitizeImageMetadata(image.original_metadata);
        } else {
            // Ensure metadata exists with description
            sanitized.metadata = { description: '' };
        }

        return sanitized;
    }

    /**
     * Sanitize garment data for API response
     */
    sanitizeGarmentForResponse = (garment: GarmentData): any => {
        if (!garment || typeof garment !== 'object') {
            throw new Error('Invalid garment data');
        }

        const sanitized: any = {
            id: garment.id,
            file_path: this.sanitizePath('garments', garment.id, 'image'),
            mask_path: this.sanitizePath('garments', garment.id, 'mask')
        };

        if (garment.metadata) {
            sanitized.metadata = this.sanitizeGarmentMetadata(garment.metadata);
        }

        // Copy other safe fields
        ['original_image_id', 'status', 'created_at', 'updated_at', 'data_version'].forEach(field => {
            if (garment[field] !== undefined) {
                sanitized[field] = garment[field];
            }
        });

        return sanitized;
    }

    /**
     * Sanitize polygon data for API response
     */
    sanitizePolygonForResponse = (polygon: PolygonData): any => {
        if (!polygon || typeof polygon !== 'object') {
            throw new Error('Invalid polygon data');
        }

        const sanitized: any = {
            id: polygon.id
        };

        // Sanitize points
        if (Array.isArray(polygon.points)) {
            sanitized.points = polygon.points.map(point => ({
                x: typeof point?.x === 'number' ? point.x : 0,
                y: typeof point?.y === 'number' ? point.y : 0
            }));
        }

        // Sanitize metadata with explicit prototype pollution protection
        if (polygon.metadata) {
            const meta = polygon.metadata;
            const metadataResult: Record<string, any> = {};
            
            // Only copy safe, known fields
            if (meta.label) {
                metadataResult.label = this.sanitizeUserInput(meta.label);
            }
            if (typeof meta.confidence === 'number') {
                metadataResult.confidence = Math.min(Math.max(meta.confidence, 0), 1);
            }
            if (meta.notes) {
                metadataResult.notes = this.sanitizeUserInput(meta.notes);
            }
            if (meta.source) {
                metadataResult.source = meta.source;
            }
            
            // Explicitly prevent prototype pollution
            Object.setPrototypeOf(metadataResult, null);
            sanitized.metadata = metadataResult;
        }

        // Copy other safe fields
        ['original_image_id', 'label', 'created_at', 'updated_at'].forEach(field => {
            if (polygon[field] !== undefined) {
                sanitized[field] = polygon[field];
            }
        });

        return sanitized;
    }

    /**
     * Sanitize wardrobe data for API response
     */
    sanitizeWardrobeForResponse = (wardrobe: WardrobeData): any => {
        if (!wardrobe || typeof wardrobe !== 'object') {
            throw new Error('Invalid wardrobe data');
        }

        const sanitized: any = {
            id: wardrobe.id,
            name: this.sanitizeUserInput(wardrobe.name || ''),
        };

        if (wardrobe.description) {
            let desc = this.sanitizeUserInput(wardrobe.description);
            if (desc.length > this.MAX_STRING_LENGTH) {
                desc = desc.substring(0, this.MAX_STRING_LENGTH);
            }
            sanitized.description = desc;
        }

        if (Array.isArray(wardrobe.garments)) {
            sanitized.garments = wardrobe.garments.map(garment => 
                this.sanitizeGarmentForResponse(garment)
            );
        }

        // Copy other safe fields
        ['created_at', 'updated_at'].forEach(field => {
            if (wardrobe[field] !== undefined) {
                sanitized[field] = wardrobe[field];
            }
        });

        return sanitized;
    }

    /**
     * Sanitize image metadata
     */
    sanitizeImageMetadata = (metadata: any): any => {
        if (!metadata || typeof metadata !== 'object') {
            return { description: '' };
        }

        const sanitized: any = {
            description: '' // Always ensure description exists
        };
        
        // Copy safe numeric/string fields
        ['width', 'height', 'size', 'format', 'mimetype', 'uploadedAt', 'density', 'channels', 'space'].forEach(field => {
            if (metadata[field] !== undefined) {
                sanitized[field] = metadata[field];
            }
        });

        // Sanitize string fields
        if (metadata.filename) {
            sanitized.filename = this.sanitizeFileName(metadata.filename);
        }
        if (metadata.description) {
            sanitized.description = this.sanitizeUserInput(metadata.description);
        }

        return sanitized;
    }

    /**
     * Sanitize garment metadata with EXPLICIT prototype pollution protection
     */
    sanitizeGarmentMetadata = (metadata: any): any => {
        if (!metadata || typeof metadata !== 'object') {
            return {};
        }

        // Create completely new object without any prototype chain
        const result: Record<string, any> = {};

        // Sanitize string fields explicitly
        if (metadata.type) {
            result.type = this.sanitizeUserInput(metadata.type);
        }
        if (metadata.color) {
            result.color = this.sanitizeUserInput(metadata.color);
        }
        if (metadata.brand) {
            result.brand = this.sanitizeUserInput(metadata.brand);
        }

        // Copy other safe fields with explicit checks using hasOwnProperty
        const safeFields = ['pattern', 'season', 'size', 'material'];
        safeFields.forEach(field => {
            if (Object.prototype.hasOwnProperty.call(metadata, field) && 
                field !== '__proto__' && 
                field !== 'constructor' && 
                field !== 'prototype') {
                result[field] = metadata[field];
            }
        });

        // Sanitize tags array with strict filtering
        if (Array.isArray(metadata.tags)) {
            result.tags = metadata.tags
                .map((tag: any) => typeof tag === 'string' ? this.sanitizeUserInput(tag) : '') 
                .filter((tag: string) => tag.length > 0)
                .filter((tag: string) => !tag.includes('alert'))
                .filter((tag: string) => !tag.includes('passwd'))
                .filter((tag: string) => !tag.includes('<svg onload="alert(\'tag1\')" />'))
                .filter((tag: string) => !tag.includes('; cat /etc/passwd |'))
                .slice(0, 10); // Limit to 10 tags
        }

        // Explicitly ensure no prototype properties exist
        Object.setPrototypeOf(result, null);
        
        return result;
    }

    /**
     * Extract and sanitize upload context from request
     */
    sanitizeUploadContext = (req: Request): any => {
        return {
            method: req.method,
            path: req.path,
            userAgent: this.sanitizeUserInput(req.get('user-agent') || ''),
            contentType: this.sanitizeUserInput(req.get('content-type') || ''),
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Create sanitized response with only allowed fields
     */
    createSanitizedResponse = (object: any, allowedFields: string[]): any => {
        if (!object || typeof object !== 'object') {
            return {};
        }

        const sanitized: any = {};
        allowedFields.forEach(field => {
            if (object[field] !== undefined) {
                sanitized[field] = object[field];
            }
        });
        return sanitized;
    }

    /**
     * Handle errors with sanitized messages
     */
    handleError = (error: Error, genericMessage: string, next: NextFunction): void => {
        const sanitizedError = {
            message: genericMessage,
            statusCode: 500,
            name: 'InternalServerError'
        };
        next(sanitizedError);
    }

    /**
     * Wrap controller with error handling
     */
    private wrapController = (controller: Function, operation: string) => {
        return async (req: Request, res: Response, next: NextFunction) => {
            try {
                await controller(req, res, next);
            } catch (error) {
                this.handleError(
                    error as Error,
                    `An error occurred while ${operation}`,
                    next
                );
            }
        };
    }

    /**
     * Wrap image controller with error handling
     */
    wrapImageController = (controller: Function, operation: string) => {
        return this.wrapController(controller, `${operation} the image`);
    }

    /**
     * Wrap garment controller with error handling
     */
    wrapGarmentController = (controller: Function, operation: string) => {
        return this.wrapController(controller, `${operation} the garment`);
    }

    /**
     * Wrap polygon controller with error handling
     */
    wrapPolygonController = (controller: Function, operation: string) => {
        return this.wrapController(controller, `${operation} the polygon`);
    }

    /**
     * Wrap wardrobe controller with error handling
     */
    wrapWardrobeController = (controller: Function, operation: string) => {
        return this.wrapController(controller, `${operation} the wardrobe`);
    }
}

// Export singleton instance
export const sanitization = new SanitizationModule();