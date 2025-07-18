import 'dart:typed_data';
import 'package:dartz/dartz.dart';
import '../failures/failures.dart';

abstract class IImageRepository {
  /// Uploads an image and returns the URL
  Future<Either<Failure, String>> uploadImage({
    required Uint8List imageData,
    required String fileName,
    required ImageType type,
    String? wardrobeId,
    String? garmentId,
  });

  /// Uploads an image from file path
  Future<Either<Failure, String>> uploadImageFromPath({
    required String filePath,
    required ImageType type,
    String? wardrobeId,
    String? garmentId,
  });

  /// Deletes an image from storage
  Future<Either<Failure, Unit>> deleteImage(String imageUrl);

  /// Gets a signed URL for secure image access
  Future<Either<Failure, String>> getImageUrl({
    required String imagePath,
    Duration expiration = const Duration(hours: 1),
  });

  /// Processes an image for background removal
  Future<Either<Failure, ProcessedImage>> processImage({
    required Uint8List imageData,
    required BackgroundRemovalQuality quality,
  });

  /// Processes an image from URL for background removal
  Future<Either<Failure, ProcessedImage>> processImageFromUrl({
    required String imageUrl,
    required BackgroundRemovalQuality quality,
  });

  /// Generates thumbnails for an image
  Future<Either<Failure, ThumbnailSet>> generateThumbnails({
    required Uint8List imageData,
    required String originalUrl,
  });

  /// Batch upload multiple images
  Future<Either<Failure, List<String>>> uploadImagesBatch({
    required List<ImageUploadData> images,
    String? wardrobeId,
  });

  /// Batch delete multiple images
  Future<Either<Failure, Unit>> deleteImagesBatch(List<String> imageUrls);

  /// Compresses an image to reduce size
  Future<Either<Failure, Uint8List>> compressImage({
    required Uint8List imageData,
    required CompressionQuality quality,
  });

  /// Gets image metadata
  Future<Either<Failure, ImageMetadata>> getImageMetadata(String imageUrl);

  /// Validates image before upload
  Future<Either<Failure, ImageValidation>> validateImage(Uint8List imageData);

  /// Gets storage usage statistics
  Future<Either<Failure, StorageStats>> getStorageStats();
}

/// Types of images in the system
enum ImageType {
  garment,
  profile,
  outfit,
  wardrobe,
}

/// Quality levels for background removal
enum BackgroundRemovalQuality {
  fast,     // Lower quality, faster processing
  balanced, // Balanced quality and speed
  best,     // Best quality, slower processing
}

/// Compression quality levels
enum CompressionQuality {
  low,      // 60% quality
  medium,   // 80% quality
  high,     // 90% quality
  original, // No compression
}

/// Result of image processing
class ProcessedImage {
  final Uint8List processedData;
  final Uint8List? maskData;
  final String? processedUrl;
  final double confidence;
  final Duration processingTime;

  const ProcessedImage({
    required this.processedData,
    this.maskData,
    this.processedUrl,
    required this.confidence,
    required this.processingTime,
  });
}

/// Set of thumbnails for an image
class ThumbnailSet {
  final String small;    // 150x150
  final String medium;   // 300x300
  final String large;    // 600x600
  final String? webp;    // WebP format for web

  const ThumbnailSet({
    required this.small,
    required this.medium,
    required this.large,
    this.webp,
  });
}

/// Data for batch image upload
class ImageUploadData {
  final Uint8List data;
  final String fileName;
  final ImageType type;
  final String? garmentId;

  const ImageUploadData({
    required this.data,
    required this.fileName,
    required this.type,
    this.garmentId,
  });
}

/// Image metadata information
class ImageMetadata {
  final int width;
  final int height;
  final int sizeInBytes;
  final String format;
  final DateTime? createdAt;
  final DateTime? modifiedAt;
  final Map<String, dynamic>? exifData;

  const ImageMetadata({
    required this.width,
    required this.height,
    required this.sizeInBytes,
    required this.format,
    this.createdAt,
    this.modifiedAt,
    this.exifData,
  });
}

/// Image validation result
class ImageValidation {
  final bool isValid;
  final String? error;
  final ImageFormat format;
  final int width;
  final int height;
  final int sizeInBytes;
  final bool isWithinSizeLimit;
  final bool isWithinDimensionLimit;

  const ImageValidation({
    required this.isValid,
    this.error,
    required this.format,
    required this.width,
    required this.height,
    required this.sizeInBytes,
    required this.isWithinSizeLimit,
    required this.isWithinDimensionLimit,
  });
}

/// Supported image formats
enum ImageFormat {
  jpeg,
  png,
  webp,
  heic,
  unknown,
}

/// Storage usage statistics
class StorageStats {
  final int totalImages;
  final int totalSizeInBytes;
  final int usedQuota;
  final int totalQuota;
  final Map<ImageType, int> imagesByType;
  final DateTime calculatedAt;

  const StorageStats({
    required this.totalImages,
    required this.totalSizeInBytes,
    required this.usedQuota,
    required this.totalQuota,
    required this.imagesByType,
    required this.calculatedAt,
  });

  double get usagePercentage => (usedQuota / totalQuota) * 100;
  bool get isNearLimit => usagePercentage > 80;
}