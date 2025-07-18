import 'dart:io';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/utils/logger.dart';
import 'package:koutu/data/local/cache/app_cache_manager.dart';
import 'package:koutu/data/models/image/image_model.dart';
import 'package:koutu/services/image/image_processor.dart';
import 'package:koutu/services/image/background_removal_service.dart';
import 'package:koutu/services/image/image_upload_service.dart';
import 'package:koutu/services/image/color_extraction_service.dart';
import 'package:path/path.dart' as path;

@lazySingleton
class ImageManager {
  final ImageProcessor _imageProcessor;
  final BackgroundRemovalService _backgroundRemovalService;
  final ImageUploadService _imageUploadService;
  final ColorExtractionService _colorExtractionService;
  final GarmentImageCacheManager _cacheManager;

  ImageManager(
    this._imageProcessor,
    this._backgroundRemovalService,
    this._imageUploadService,
    this._colorExtractionService,
    this._cacheManager,
  );

  /// Process and upload image
  Future<ImageModel> processAndUploadImage(
    File imageFile, {
    required String userId,
    String? garmentId,
    String? wardrobeId,
    bool removeBackground = false,
    bool extractColors = true,
    bool generateThumbnail = true,
  }) async {
    try {
      Logger.info('Processing image: ${imageFile.path}');

      // Step 1: Process image (compress and generate thumbnail)
      final processedImage = await _imageProcessor.processForUpload(imageFile);
      
      Logger.info('Image compressed: ${processedImage.savedPercentage.toStringAsFixed(1)}% saved');

      // Step 2: Remove background if requested
      File? backgroundRemovedFile;
      if (removeBackground) {
        try {
          backgroundRemovedFile = await _backgroundRemovalService.removeBackground(
            processedImage.compressedFile,
          );
          Logger.info('Background removed successfully');
        } catch (e) {
          Logger.error('Background removal failed, continuing without it', error: e);
        }
      }

      // Step 3: Extract colors if requested
      List<String>? colorPalette;
      String? dominantColor;
      if (extractColors) {
        try {
          final colors = await _colorExtractionService.extractColors(
            backgroundRemovedFile ?? processedImage.compressedFile,
          );
          colorPalette = colors.palette;
          dominantColor = colors.dominantColor;
          Logger.info('Colors extracted: ${colorPalette.length} colors found');
        } catch (e) {
          Logger.error('Color extraction failed, continuing without it', error: e);
        }
      }

      // Step 4: Upload all images
      final uploadResult = await _imageUploadService.uploadImages(
        originalFile: processedImage.compressedFile,
        thumbnailFile: generateThumbnail ? processedImage.thumbnailFile : null,
        backgroundRemovedFile: backgroundRemovedFile,
      );

      // Step 5: Cache images locally
      if (uploadResult.originalUrl != null) {
        await _cacheManager.instance.downloadFile(uploadResult.originalUrl!);
      }
      if (uploadResult.thumbnailUrl != null) {
        await _cacheManager.instance.downloadFile(uploadResult.thumbnailUrl!);
      }

      // Step 6: Create image model
      final imageModel = ImageModel(
        id: uploadResult.imageId,
        userId: userId,
        garmentId: garmentId,
        wardrobeId: wardrobeId,
        originalUrl: uploadResult.originalUrl!,
        thumbnailUrl: uploadResult.thumbnailUrl,
        processedUrl: uploadResult.processedUrl,
        backgroundRemovedUrl: uploadResult.backgroundRemovedUrl,
        filename: path.basename(imageFile.path),
        mimeType: 'image/jpeg',
        fileSize: processedImage.compressedFileSize,
        width: processedImage.originalSize.width.toInt(),
        height: processedImage.originalSize.height.toInt(),
        isPrimary: false,
        isProcessed: true,
        isBackgroundRemoved: backgroundRemovedFile != null,
        colorPalette: colorPalette,
        dominantColor: dominantColor,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      // Clean up temporary files
      await _cleanupTempFiles([
        processedImage.compressedFile,
        processedImage.thumbnailFile,
        if (backgroundRemovedFile != null) backgroundRemovedFile,
      ]);

      Logger.info('Image processing completed: ${imageModel.id}');
      return imageModel;
    } catch (e) {
      Logger.error('Image processing failed', error: e);
      rethrow;
    }
  }

  /// Process multiple images in batch
  Future<List<ImageModel>> processAndUploadBatch(
    List<File> imageFiles, {
    required String userId,
    String? garmentId,
    String? wardrobeId,
    bool removeBackground = false,
    bool extractColors = true,
    bool generateThumbnail = true,
  }) async {
    final results = <ImageModel>[];

    for (final imageFile in imageFiles) {
      try {
        final imageModel = await processAndUploadImage(
          imageFile,
          userId: userId,
          garmentId: garmentId,
          wardrobeId: wardrobeId,
          removeBackground: removeBackground,
          extractColors: extractColors,
          generateThumbnail: generateThumbnail,
        );
        results.add(imageModel);
      } catch (e) {
        Logger.error('Failed to process image: ${imageFile.path}', error: e);
        // Continue with other images
      }
    }

    return results;
  }

  /// Download and cache image
  Future<File?> getCachedImage(String imageUrl) async {
    try {
      final fileInfo = await _cacheManager.instance.getSingleFile(imageUrl);
      return fileInfo.file;
    } catch (e) {
      Logger.error('Failed to get cached image', error: e);
      return null;
    }
  }

  /// Delete image from cache
  Future<void> removeFromCache(String imageUrl) async {
    try {
      await _cacheManager.instance.removeFile(imageUrl);
    } catch (e) {
      Logger.error('Failed to remove image from cache', error: e);
    }
  }

  /// Clear all cached images
  Future<void> clearImageCache() async {
    try {
      await _cacheManager.instance.emptyCache();
      Logger.info('Image cache cleared');
    } catch (e) {
      Logger.error('Failed to clear image cache', error: e);
    }
  }

  /// Get cache size
  Future<int> getCacheSize() async {
    try {
      return await _cacheManager.instance.getCacheSize();
    } catch (e) {
      Logger.error('Failed to get cache size', error: e);
      return 0;
    }
  }

  /// Clean up temporary files
  Future<void> _cleanupTempFiles(List<File> files) async {
    for (final file in files) {
      try {
        if (await file.exists()) {
          await file.delete();
        }
      } catch (e) {
        Logger.error('Failed to delete temp file: ${file.path}', error: e);
      }
    }
  }

  /// Process image for AI analysis
  Future<ImageAnalysisResult> analyzeImage(File imageFile) async {
    try {
      // Extract colors
      final colors = await _colorExtractionService.extractColors(imageFile);
      
      // TODO: Implement AI tagging service
      final aiTags = <String>[];
      
      // Get image dimensions
      final dimensions = await _imageProcessor.getImageDimensions(imageFile);
      
      return ImageAnalysisResult(
        colorPalette: colors.palette,
        dominantColor: colors.dominantColor,
        aiTags: aiTags,
        width: dimensions.width.toInt(),
        height: dimensions.height.toInt(),
      );
    } catch (e) {
      Logger.error('Image analysis failed', error: e);
      rethrow;
    }
  }
}

class ImageAnalysisResult {
  final List<String> colorPalette;
  final String dominantColor;
  final List<String> aiTags;
  final int width;
  final int height;

  ImageAnalysisResult({
    required this.colorPalette,
    required this.dominantColor,
    required this.aiTags,
    required this.width,
    required this.height,
  });
}