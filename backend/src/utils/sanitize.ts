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
    
    /**
     * Sanitizes file paths to API routes
     */
    sanitizePath(resourceType: string, resourceId: string, pathType: string): string {
        return `/api/${resourceType}/${resourceId}/${pathType}`;
    },
    
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
     * Wraps controller methods with standardized try/catch sanitization
     */
    wrapController(controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>, errorMessage: string) {
        return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            await controllerFn(req, res, next);
        } catch (error) {
            this.handleError(error, errorMessage, next);
        }
        };
    },

    /**
     * Sanitizes garment metadata to only include allowed fields
     */
    sanitizeGarmentMetadata(metadata: Record<string, any>): Record<string, any> {
        return {
        type: metadata?.type,
        color: metadata?.color,
        pattern: metadata?.pattern,
        season: metadata?.season,
        brand: metadata?.brand,
        tags: Array.isArray(metadata?.tags) ? metadata.tags : []
        };
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
     * Specialized wrapper for garment controller methods
     */
    wrapGarmentController(
        controllerFn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
        operation: string
    ) {
        return this.wrapController(
        controllerFn, 
        `An error occurred while ${operation} the garment`
        );
    }
};