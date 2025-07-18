import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter_image_compress/flutter_image_compress.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as path;
import 'package:injectable/injectable.dart';
import 'package:koutu/core/utils/logger.dart';

@lazySingleton
class ImageProcessor {
  /// Compress image file
  Future<File> compressImage(
    File imageFile, {
    int quality = 85,
    int? minWidth,
    int? minHeight,
    CompressFormat format = CompressFormat.jpeg,
  }) async {
    try {
      final String targetPath = await _generateTempPath(
        imageFile.path,
        suffix: '_compressed',
      );

      final XFile? result = await FlutterImageCompress.compressAndGetFile(
        imageFile.absolute.path,
        targetPath,
        quality: quality,
        minWidth: minWidth ?? 1024,
        minHeight: minHeight ?? 1024,
        format: format,
      );

      if (result == null) {
        throw Exception('Image compression failed');
      }

      return File(result.path);
    } catch (e) {
      Logger.error('Image compression failed', error: e);
      rethrow;
    }
  }

  /// Compress image bytes
  Future<Uint8List> compressImageBytes(
    Uint8List imageBytes, {
    int quality = 85,
    int? minWidth,
    int? minHeight,
    CompressFormat format = CompressFormat.jpeg,
  }) async {
    try {
      final Uint8List? result = await FlutterImageCompress.compressWithList(
        imageBytes,
        quality: quality,
        minWidth: minWidth ?? 1024,
        minHeight: minHeight ?? 1024,
        format: format,
      );

      if (result == null) {
        throw Exception('Image compression failed');
      }

      return result;
    } catch (e) {
      Logger.error('Image bytes compression failed', error: e);
      rethrow;
    }
  }

  /// Generate thumbnail
  Future<File> generateThumbnail(
    File imageFile, {
    int width = 200,
    int height = 200,
    int quality = 70,
  }) async {
    try {
      final String targetPath = await _generateTempPath(
        imageFile.path,
        suffix: '_thumb',
      );

      final XFile? result = await FlutterImageCompress.compressAndGetFile(
        imageFile.absolute.path,
        targetPath,
        minWidth: width,
        minHeight: height,
        quality: quality,
      );

      if (result == null) {
        throw Exception('Thumbnail generation failed');
      }

      return File(result.path);
    } catch (e) {
      Logger.error('Thumbnail generation failed', error: e);
      rethrow;
    }
  }

  /// Crop image
  Future<File> cropImage(
    File imageFile,
    Rect cropRect,
    Size imageSize,
  ) async {
    try {
      final bytes = await imageFile.readAsBytes();
      final codec = await ui.instantiateImageCodec(bytes);
      final frame = await codec.getNextFrame();
      final image = frame.image;

      // Calculate actual crop area in pixels
      final cropArea = Rect.fromLTWH(
        cropRect.left * image.width,
        cropRect.top * image.height,
        cropRect.width * image.width,
        cropRect.height * image.height,
      );

      // Create picture recorder
      final recorder = ui.PictureRecorder();
      final canvas = Canvas(
        recorder,
        Rect.fromLTWH(0, 0, cropArea.width, cropArea.height),
      );

      // Draw cropped portion
      canvas.drawImageRect(
        image,
        cropArea,
        Rect.fromLTWH(0, 0, cropArea.width, cropArea.height),
        Paint(),
      );

      // Convert to image
      final picture = recorder.endRecording();
      final croppedImage = await picture.toImage(
        cropArea.width.toInt(),
        cropArea.height.toInt(),
      );

      // Convert to bytes
      final byteData = await croppedImage.toByteData(
        format: ui.ImageByteFormat.png,
      );

      if (byteData == null) {
        throw Exception('Failed to convert cropped image to bytes');
      }

      // Save to file
      final targetPath = await _generateTempPath(
        imageFile.path,
        suffix: '_cropped',
      );

      final file = File(targetPath);
      await file.writeAsBytes(byteData.buffer.asUint8List());

      return file;
    } catch (e) {
      Logger.error('Image cropping failed', error: e);
      rethrow;
    }
  }

  /// Rotate image
  Future<File> rotateImage(
    File imageFile,
    int degrees,
  ) async {
    try {
      if (degrees % 90 != 0) {
        throw ArgumentError('Rotation must be a multiple of 90 degrees');
      }

      final String targetPath = await _generateTempPath(
        imageFile.path,
        suffix: '_rotated',
      );

      final XFile? result = await FlutterImageCompress.compressAndGetFile(
        imageFile.absolute.path,
        targetPath,
        rotate: degrees,
        quality: 100,
      );

      if (result == null) {
        throw Exception('Image rotation failed');
      }

      return File(result.path);
    } catch (e) {
      Logger.error('Image rotation failed', error: e);
      rethrow;
    }
  }

  /// Get image dimensions
  Future<Size> getImageDimensions(File imageFile) async {
    try {
      final bytes = await imageFile.readAsBytes();
      final codec = await ui.instantiateImageCodec(bytes);
      final frame = await codec.getNextFrame();
      final image = frame.image;

      return Size(
        image.width.toDouble(),
        image.height.toDouble(),
      );
    } catch (e) {
      Logger.error('Failed to get image dimensions', error: e);
      rethrow;
    }
  }

  /// Process image for upload (compress and generate thumbnail)
  Future<ProcessedImage> processForUpload(
    File imageFile, {
    int quality = 85,
    int maxWidth = 2048,
    int maxHeight = 2048,
    int thumbWidth = 400,
    int thumbHeight = 400,
  }) async {
    try {
      // Get original dimensions
      final originalSize = await getImageDimensions(imageFile);

      // Compress main image
      final compressedFile = await compressImage(
        imageFile,
        quality: quality,
        minWidth: maxWidth,
        minHeight: maxHeight,
      );

      // Generate thumbnail
      final thumbnailFile = await generateThumbnail(
        imageFile,
        width: thumbWidth,
        height: thumbHeight,
      );

      // Get file sizes
      final originalFileSize = await imageFile.length();
      final compressedFileSize = await compressedFile.length();
      final thumbnailFileSize = await thumbnailFile.length();

      return ProcessedImage(
        originalFile: imageFile,
        compressedFile: compressedFile,
        thumbnailFile: thumbnailFile,
        originalSize: originalSize,
        originalFileSize: originalFileSize,
        compressedFileSize: compressedFileSize,
        thumbnailFileSize: thumbnailFileSize,
      );
    } catch (e) {
      Logger.error('Image processing for upload failed', error: e);
      rethrow;
    }
  }

  /// Generate temporary file path
  Future<String> _generateTempPath(
    String originalPath, {
    String suffix = '',
  }) async {
    final tempDir = await getTemporaryDirectory();
    final filename = path.basenameWithoutExtension(originalPath);
    final extension = path.extension(originalPath);
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    
    return path.join(
      tempDir.path,
      '${filename}${suffix}_$timestamp$extension',
    );
  }

  /// Clean up temporary files
  Future<void> cleanupTempFiles() async {
    try {
      final tempDir = await getTemporaryDirectory();
      final files = tempDir.listSync();
      
      for (final file in files) {
        if (file is File && _isTempImageFile(file.path)) {
          await file.delete();
        }
      }
    } catch (e) {
      Logger.error('Failed to cleanup temp files', error: e);
    }
  }

  bool _isTempImageFile(String filePath) {
    final filename = path.basename(filePath);
    return filename.contains('_compressed_') ||
        filename.contains('_thumb_') ||
        filename.contains('_cropped_') ||
        filename.contains('_rotated_');
  }
}

class ProcessedImage {
  final File originalFile;
  final File compressedFile;
  final File thumbnailFile;
  final Size originalSize;
  final int originalFileSize;
  final int compressedFileSize;
  final int thumbnailFileSize;

  ProcessedImage({
    required this.originalFile,
    required this.compressedFile,
    required this.thumbnailFile,
    required this.originalSize,
    required this.originalFileSize,
    required this.compressedFileSize,
    required this.thumbnailFileSize,
  });

  double get compressionRatio => compressedFileSize / originalFileSize;
  
  int get savedBytes => originalFileSize - compressedFileSize;
  
  double get savedPercentage => (savedBytes / originalFileSize) * 100;
}