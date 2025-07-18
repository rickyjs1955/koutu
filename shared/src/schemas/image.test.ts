// /shared/src/schemas/image.test.ts
import { describe, test, expect } from '@jest/globals';
import {
  ImageSchema,
  ImageVariantSchema,
  EnhancedImageMetadataSchema,
  MobileImageFieldsSchema,
  MobileImageUploadSchema,
  ImageChunkUploadSchema,
  ImageResponseSchema,
  MobileImageListItemSchema,
  ImageListResponseSchema,
  ImageFilterSchema,
  BatchImageOperationSchema
} from './image';

describe('Image Schema Tests', () => {
  describe('ImageVariantSchema', () => {
    test('should validate complete image variants', () => {
      const validVariants = {
        thumbnail: {
          url: 'https://cdn.example.com/thumbs/img_123_thumb.jpg',
          width: 150,
          height: 150,
          size: 12345
        },
        preview: {
          url: 'https://cdn.example.com/preview/img_123_preview.jpg',
          width: 500,
          height: 500,
          size: 45678
        },
        full: {
          url: 'https://cdn.example.com/full/img_123.jpg',
          width: 2048,
          height: 1536,
          size: 2097152
        },
        webp: {
          url: 'https://cdn.example.com/webp/img_123.webp',
          width: 2048,
          height: 1536,
          size: 1048576
        }
      };

      const result = ImageVariantSchema.safeParse(validVariants);
      expect(result.success).toBe(true);
    });

    test('should validate partial variants', () => {
      const partialVariants = {
        thumbnail: {
          url: 'https://cdn.example.com/t/123.jpg',
          width: 100,
          height: 100,
          size: 5000
        }
        // Other variants are optional
      };

      const result = ImageVariantSchema.safeParse(partialVariants);
      expect(result.success).toBe(true);
    });

    test('should validate empty variants', () => {
      const emptyVariants = {};
      const result = ImageVariantSchema.safeParse(emptyVariants);
      expect(result.success).toBe(true);
    });

    test('should enforce integer dimensions', () => {
      const floatDimensions = {
        thumbnail: {
          url: 'https://example.com/t.jpg',
          width: 150.5, // Should be integer
          height: 150,
          size: 12345
        }
      };

      const result = ImageVariantSchema.safeParse(floatDimensions);
      expect(result.success).toBe(false);
    });
  });

  describe('EnhancedImageMetadataSchema', () => {
    test('should validate complete metadata', () => {
      const completeMetadata = {
        filename: 'IMG_20240120_143022.jpg',
        original_filename: 'Vacation Photo.jpg',
        mimetype: 'image/jpeg',
        size: 3145728, // 3MB
        width: 4032,
        height: 3024,
        format: 'jpeg',
        orientation: 1,
        has_transparency: false,
        color_space: 'srgb',
        dpi: 72,
        capture_date: new Date('2024-01-20T14:30:22Z'),
        camera_make: 'Apple',
        camera_model: 'iPhone 14 Pro',
        gps_location: {
          latitude: 37.7749,
          longitude: -122.4194
        },
        hash: 'sha256:abcdef1234567890'
      };

      const result = EnhancedImageMetadataSchema.safeParse(completeMetadata);
      expect(result.success).toBe(true);
    });

    test('should validate minimal metadata', () => {
      const minimalMetadata = {
        filename: 'image.png',
        mimetype: 'image/png',
        size: 1024,
        width: 100,
        height: 100,
        format: 'png'
      };

      const result = EnhancedImageMetadataSchema.safeParse(minimalMetadata);
      expect(result.success).toBe(true);
    });

    test('should validate image formats', () => {
      const validFormats = ['jpeg', 'jpg', 'png', 'webp', 'gif', 'heic', 'heif'];
      
      validFormats.forEach(format => {
        const result = EnhancedImageMetadataSchema.safeParse({
          filename: `test.${format}`,
          mimetype: `image/${format}`,
          size: 1024,
          width: 100,
          height: 100,
          format
        });
        expect(result.success).toBe(true);
      });
    });

    test('should validate EXIF orientation values', () => {
      // Valid orientations: 1-8
      for (let i = 1; i <= 8; i++) {
        const result = EnhancedImageMetadataSchema.safeParse({
          filename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          width: 100,
          height: 100,
          format: 'jpeg',
          orientation: i
        });
        expect(result.success).toBe(true);
      }

      // Invalid orientations
      [0, 9, -1].forEach(orientation => {
        const result = EnhancedImageMetadataSchema.safeParse({
          filename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          width: 100,
          height: 100,
          format: 'jpeg',
          orientation
        });
        expect(result.success).toBe(false);
      });
    });

    test('should enforce filename length limit', () => {
      const longFilename = {
        filename: 'x'.repeat(256), // Too long
        mimetype: 'image/jpeg',
        size: 1024,
        width: 100,
        height: 100,
        format: 'jpeg'
      };

      const result = EnhancedImageMetadataSchema.safeParse(longFilename);
      expect(result.success).toBe(false);
    });
  });

  describe('MobileImageFieldsSchema', () => {
    test('should validate mobile-specific fields', () => {
      const mobileFields = {
        variants: {
          thumbnail: {
            url: 'https://cdn.example.com/t/123.jpg',
            width: 150,
            height: 150,
            size: 10000
          }
        },
        processing_status: 'complete',
        processing_progress: 100,
        local_path: 'file:///storage/emulated/0/DCIM/img_123.jpg',
        cached_at: new Date(),
        sync_status: 'synced',
        upload_progress: 100,
        retry_count: 0,
        is_favorite: true,
        tags: ['vacation', 'beach', 'sunset']
      };

      const result = MobileImageFieldsSchema.safeParse(mobileFields);
      expect(result.success).toBe(true);
    });

    test('should validate processing status values', () => {
      const validStatuses = ['pending', 'processing', 'complete', 'failed'];
      
      validStatuses.forEach(status => {
        const result = MobileImageFieldsSchema.safeParse({
          processing_status: status
        });
        expect(result.success).toBe(true);
      });
    });

    test('should validate sync status values', () => {
      const validStatuses = ['synced', 'pending', 'conflict'];
      
      validStatuses.forEach(status => {
        const result = MobileImageFieldsSchema.safeParse({
          sync_status: status
        });
        expect(result.success).toBe(true);
      });
    });

    test('should enforce progress constraints', () => {
      // Valid progress values
      [0, 50, 100].forEach(progress => {
        const result = MobileImageFieldsSchema.safeParse({
          processing_progress: progress,
          upload_progress: progress
        });
        expect(result.success).toBe(true);
      });

      // Invalid progress values
      [-1, 101, 150].forEach(progress => {
        const result = MobileImageFieldsSchema.safeParse({
          processing_progress: progress
        });
        expect(result.success).toBe(false);
      });
    });

    test('should handle default values', () => {
      const minimal = {};
      const result = MobileImageFieldsSchema.safeParse(minimal);
      
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.processing_status).toBe('pending');
        expect(result.data.sync_status).toBe('synced');
        expect(result.data.retry_count).toBe(0);
        expect(result.data.is_favorite).toBe(false);
      }
    });

    test('should enforce tag constraints', () => {
      // Maximum 100 tags
      const tooManyTags = Array(101).fill('tag');
      
      const result = MobileImageFieldsSchema.safeParse({
        tags: tooManyTags
      });
      
      expect(result.success).toBe(false);
    });
  });

  describe('ImageSchema', () => {
    test('should validate complete image with mobile fields', () => {
      const completeImage = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        file_path: '/uploads/images/IMG_123.jpg',
        metadata: {
          filename: 'IMG_123.jpg',
          mimetype: 'image/jpeg',
          size: 2097152,
          width: 3024,
          height: 4032,
          format: 'jpeg',
          orientation: 6,
          capture_date: new Date('2024-01-20')
        },
        variants: {
          thumbnail: {
            url: 'https://cdn.example.com/t/123.jpg',
            width: 150,
            height: 200,
            size: 15000
          },
          preview: {
            url: 'https://cdn.example.com/p/123.jpg',
            width: 600,
            height: 800,
            size: 80000
          }
        },
        processing_status: 'complete',
        sync_status: 'synced',
        is_favorite: true,
        tags: ['portrait', 'outdoor'],
        created_at: new Date(),
        updated_at: new Date()
      };

      const result = ImageSchema.safeParse(completeImage);
      expect(result.success).toBe(true);
    });

    test('should require essential fields', () => {
      const missingRequired = {
        // Missing user_id, file_path, metadata
        id: '123e4567-e89b-12d3-a456-426614174000'
      };

      const result = ImageSchema.safeParse(missingRequired);
      expect(result.success).toBe(false);
    });

    test('should validate UUID formats', () => {
      const invalidUUIDs = {
        id: 'not-a-uuid',
        user_id: '123',
        file_path: '/test.jpg',
        metadata: {
          filename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          width: 100,
          height: 100,
          format: 'jpeg'
        }
      };

      const result = ImageSchema.safeParse(invalidUUIDs);
      expect(result.success).toBe(false);
    });
  });

  describe('MobileImageUploadSchema', () => {
    test('should validate mobile upload data', () => {
      const uploadData = {
        filename: 'IMG_20240120_143022.jpg',
        mimetype: 'image/jpeg',
        size: 2097152,
        device_id: 'iPhone14Pro-ABC123',
        capture_metadata: {
          timestamp: new Date().toISOString(),
          location: {
            latitude: 37.7749,
            longitude: -122.4194,
            accuracy: 10
          },
          device_info: {
            model: 'iPhone 14 Pro',
            os_version: 'iOS 17.2',
            app_version: '1.2.3'
          }
        },
        processing_options: {
          generate_thumbnail: true,
          thumbnail_size: 200,
          generate_preview: true,
          preview_size: 800,
          optimize_for_web: true,
          preserve_metadata: false
        },
        chunk_info: {
          total_chunks: 3,
          chunk_size: 1048576
        }
      };

      const result = MobileImageUploadSchema.safeParse(uploadData);
      expect(result.success).toBe(true);
    });

    test('should validate file size limits', () => {
      const tooLarge = {
        filename: 'large.jpg',
        mimetype: 'image/jpeg',
        size: 6 * 1024 * 1024, // 6MB, exceeds MAX_MOBILE_FILE_SIZE
        device_id: 'device123'
      };

      const result = MobileImageUploadSchema.safeParse(tooLarge);
      expect(result.success).toBe(false);
    });
  });

  describe('ImageChunkUploadSchema', () => {
    test('should validate image chunk data', () => {
      const validChunk = {
        upload_id: '123e4567-e89b-12d3-a456-426614174000',
        chunk_index: 0,
        total_chunks: 3,
        chunk_data: 'base64encodeddata...',
        checksum: 'sha256:abcdef1234567890'
      };

      const result = ImageChunkUploadSchema.safeParse(validChunk);
      expect(result.success).toBe(true);
    });

    test('should validate chunk constraints', () => {
      // Negative chunk index
      const negativeIndex = {
        upload_id: '123e4567-e89b-12d3-a456-426614174000',
        chunk_index: -1,
        total_chunks: 3,
        chunk_data: 'data'
      };
      expect(ImageChunkUploadSchema.safeParse(negativeIndex).success).toBe(false);

      // Chunk index >= total chunks
      const invalidIndex = {
        upload_id: '123e4567-e89b-12d3-a456-426614174000',
        chunk_index: 3,
        total_chunks: 3,
        chunk_data: 'data'
      };
      expect(ImageChunkUploadSchema.safeParse(invalidIndex).success).toBe(false);
    });
  });

  describe('BatchImageOperationSchema', () => {
    test('should validate batch operations', () => {
      const batchOp = {
        operation: 'delete',
        image_ids: [
          '123e4567-e89b-12d3-a456-426614174000',
          '223e4567-e89b-12d3-a456-426614174000'
        ],
        device_id: 'iPhone14Pro-ABC123'
      };

      const result = BatchImageOperationSchema.safeParse(batchOp);
      expect(result.success).toBe(true);
    });

    test('should validate operation types', () => {
      const validOps = ['delete', 'archive', 'favorite', 'unfavorite', 'tag'];
      
      validOps.forEach(operation => {
        const result = BatchImageOperationSchema.safeParse({
          operation,
          image_ids: ['123e4567-e89b-12d3-a456-426614174000']
        });
        expect(result.success).toBe(true);
      });
    });

    test('should enforce batch size limit', () => {
      const tooManyIds = Array(21).fill('123e4567-e89b-12d3-a456-426614174000');
      
      const result = BatchImageOperationSchema.safeParse({
        operation: 'delete',
        image_ids: tooManyIds
      });
      
      expect(result.success).toBe(false);
    });

    test('should validate tag operations', () => {
      const tagOp = {
        operation: 'tag',
        image_ids: ['123e4567-e89b-12d3-a456-426614174000'],
        data: {
          tags: ['vacation', 'beach', 'summer'],
          action: 'add' // or 'remove', 'replace'
        }
      };

      const result = BatchImageOperationSchema.safeParse(tagOp);
      expect(result.success).toBe(true);
    });
  });

  describe('ImageFilterSchema', () => {
    test('should validate filter options', () => {
      const completeFilter = {
        formats: ['jpeg', 'png'],
        min_size: 1024,
        max_size: 5242880,
        min_width: 100,
        max_width: 4000,
        min_height: 100,
        max_height: 4000,
        is_favorite: true,
        has_location: true,
        tags: ['vacation', 'outdoor'],
        uploaded_after: new Date('2024-01-01'),
        uploaded_before: new Date('2024-12-31'),
        processing_status: ['complete'],
        sync_status: ['synced', 'pending']
      };

      const result = ImageFilterSchema.safeParse(completeFilter);
      expect(result.success).toBe(true);
    });

    test('should allow partial filters', () => {
      const partialFilter = {
        formats: ['jpeg'],
        is_favorite: true
      };

      const result = ImageFilterSchema.safeParse(partialFilter);
      expect(result.success).toBe(true);
    });
  });

  describe('ImageResponseSchema', () => {
    test('should omit user_id from response', () => {
      const imageData = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        file_path: '/uploads/images/IMG_123.jpg',
        metadata: {
          filename: 'IMG_123.jpg',
          mimetype: 'image/jpeg',
          size: 2097152,
          width: 3024,
          height: 4032,
          format: 'jpeg'
        },
        variants: {
          thumbnail: {
            url: 'https://cdn.example.com/t/123.jpg',
            width: 150,
            height: 200,
            size: 15000
          }
        },
        processing_status: 'complete',
        created_at: new Date(),
        updated_at: new Date()
      };

      const result = ImageResponseSchema.safeParse(imageData);
      expect(result.success).toBe(true);
    });
  });

  describe('MobileImageListItemSchema', () => {
    test('should validate mobile list item', () => {
      const listItem = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        thumbnail_url: 'https://cdn.example.com/t/123.jpg',
        preview_url: 'https://cdn.example.com/p/123.jpg',
        metadata: {
          filename: 'IMG_123.jpg',
          width: 3024,
          height: 4032,
          size: 2097152
        },
        upload_date: new Date(),
        status: 'processed',
        is_favorite: true,
        tags: ['vacation', 'beach']
      };

      const result = MobileImageListItemSchema.safeParse(listItem);
      expect(result.success).toBe(true);
    });
  });

  describe('ImageListResponseSchema', () => {
    test('should validate image list response', () => {
      const listResponse = {
        images: [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            thumbnail_url: 'https://cdn.example.com/t/123.jpg',
            metadata: {
              filename: 'IMG_123.jpg',
              width: 3024,
              height: 4032,
              size: 2097152
            },
            upload_date: new Date(),
            status: 'processed',
            is_favorite: true,
            tags: ['jpeg']
          }
        ],
        pagination: {
          page: 1,
          limit: 20,
          total: 95,
          has_more: true
        },
        sync_info: {
          last_sync: new Date(),
          pending_uploads: 0,
          pending_downloads: 0
        }
      };

      const result = ImageListResponseSchema.safeParse(listResponse);
      expect(result.success).toBe(true);
    });
  });

  describe('Cross-platform compatibility', () => {
    test('should handle date serialization', () => {
      const imageWithDates = {
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        file_path: '/test.jpg',
        metadata: {
          filename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          width: 100,
          height: 100,
          format: 'jpeg',
          capture_date: new Date().toISOString()
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        cached_at: new Date().toISOString()
      };

      const result = ImageSchema.safeParse({
        ...imageWithDates,
        metadata: {
          ...imageWithDates.metadata,
          capture_date: new Date(imageWithDates.metadata.capture_date)
        },
        created_at: new Date(imageWithDates.created_at),
        updated_at: new Date(imageWithDates.updated_at),
        cached_at: new Date(imageWithDates.cached_at)
      });

      expect(result.success).toBe(true);
    });

    test('should handle offline paths', () => {
      const offlineImage = {
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        file_path: 'file:///storage/emulated/0/DCIM/IMG_123.jpg',
        metadata: {
          filename: 'IMG_123.jpg',
          mimetype: 'image/jpeg',
          size: 2097152,
          width: 3024,
          height: 4032,
          format: 'jpeg'
        },
        local_path: 'file:///storage/emulated/0/DCIM/IMG_123.jpg',
        sync_status: 'pending'
      };

      const result = ImageSchema.safeParse(offlineImage);
      expect(result.success).toBe(true);
    });

    test('should handle iOS/Android specific paths', () => {
      const iosPaths = [
        'file:///var/mobile/Containers/Data/Application/.../Documents/IMG_123.jpg',
        'assets-library://asset/asset.JPG?id=...',
        'ph://ED7AC36B-...'
      ];

      const androidPaths = [
        'file:///storage/emulated/0/DCIM/Camera/IMG_123.jpg',
        'content://media/external/images/media/123',
        'file:///android_asset/images/sample.jpg'
      ];

      [...iosPaths, ...androidPaths].forEach(path => {
        const result = ImageSchema.safeParse({
          user_id: '123e4567-e89b-12d3-a456-426614174001',
          file_path: path,
          metadata: {
            filename: 'test.jpg',
            mimetype: 'image/jpeg',
            size: 1024,
            width: 100,
            height: 100,
            format: 'jpeg'
          },
          local_path: path
        });
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Performance considerations', () => {
    test('should handle batch uploads efficiently', () => {
      const chunks = Array(3).fill(0).map((_, index) => ({
        upload_id: '123e4567-e89b-12d3-a456-426614174000',
        chunk_index: index,
        total_chunks: 3,
        chunk_data: 'x'.repeat(1000), // Simulated chunk data
        checksum: `sha256:${index}`
      }));

      chunks.forEach(chunk => {
        const result = ImageChunkUploadSchema.safeParse(chunk);
        expect(result.success).toBe(true);
      });
    });

    test('should validate within mobile constraints', () => {
      const mobileOptimized = {
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        file_path: '/imgs/123.jpg',
        metadata: {
          filename: '123.jpg',
          mimetype: 'image/jpeg',
          size: 1048576, // 1MB
          width: 1024,
          height: 768,
          format: 'jpeg'
        },
        variants: {
          thumbnail: {
            url: 'https://cdn.example.com/t/123.jpg',
            width: 150,
            height: 113,
            size: 8192
          }
        },
        processing_status: 'complete',
        sync_status: 'synced'
      };

      const result = ImageSchema.safeParse(mobileOptimized);
      expect(result.success).toBe(true);
    });
  });
});