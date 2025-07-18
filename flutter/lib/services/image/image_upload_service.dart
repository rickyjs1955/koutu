import 'dart:io';
import 'package:dio/dio.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/utils/logger.dart';
import 'package:koutu/data/network/api_client.dart';
import 'package:path/path.dart' as path;
import 'package:uuid/uuid.dart';

@lazySingleton
class ImageUploadService {
  final ApiClient _apiClient;
  static const _uuid = Uuid();

  ImageUploadService(this._apiClient);

  /// Upload images to server
  Future<ImageUploadResult> uploadImages({
    required File originalFile,
    File? thumbnailFile,
    File? backgroundRemovedFile,
  }) async {
    try {
      final imageId = _uuid.v4();
      Logger.info('Uploading images with ID: $imageId');

      // Prepare form data
      final formData = FormData();
      
      // Add original image
      formData.files.add(
        MapEntry(
          'original',
          await MultipartFile.fromFile(
            originalFile.path,
            filename: 'original_${path.basename(originalFile.path)}',
          ),
        ),
      );

      // Add thumbnail if available
      if (thumbnailFile != null) {
        formData.files.add(
          MapEntry(
            'thumbnail',
            await MultipartFile.fromFile(
              thumbnailFile.path,
              filename: 'thumb_${path.basename(thumbnailFile.path)}',
            ),
          ),
        );
      }

      // Add background removed image if available
      if (backgroundRemovedFile != null) {
        formData.files.add(
          MapEntry(
            'backgroundRemoved',
            await MultipartFile.fromFile(
              backgroundRemovedFile.path,
              filename: 'nobg_${path.basename(backgroundRemovedFile.path)}',
            ),
          ),
        );
      }

      // Add metadata
      formData.fields.add(MapEntry('imageId', imageId));

      // Upload to server
      final response = await _apiClient.post(
        '/images/upload',
        data: formData,
        options: Options(
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        ),
        onSendProgress: (sent, total) {
          final progress = (sent / total * 100).toStringAsFixed(0);
          Logger.debug('Upload progress: $progress%');
        },
      );

      Logger.info('Images uploaded successfully');

      return ImageUploadResult(
        imageId: imageId,
        originalUrl: response.data['originalUrl'] as String?,
        thumbnailUrl: response.data['thumbnailUrl'] as String?,
        processedUrl: response.data['processedUrl'] as String?,
        backgroundRemovedUrl: response.data['backgroundRemovedUrl'] as String?,
      );
    } catch (e) {
      Logger.error('Image upload failed', error: e);
      rethrow;
    }
  }

  /// Upload single image
  Future<String> uploadSingleImage(
    File imageFile, {
    String? folder,
  }) async {
    try {
      Logger.info('Uploading single image: ${imageFile.path}');

      final formData = FormData.fromMap({
        'image': await MultipartFile.fromFile(
          imageFile.path,
          filename: path.basename(imageFile.path),
        ),
        if (folder != null) 'folder': folder,
      });

      final response = await _apiClient.post(
        '/images/upload-single',
        data: formData,
        options: Options(
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        ),
      );

      final imageUrl = response.data['url'] as String;
      Logger.info('Image uploaded: $imageUrl');

      return imageUrl;
    } catch (e) {
      Logger.error('Single image upload failed', error: e);
      rethrow;
    }
  }

  /// Delete image from server
  Future<void> deleteImage(String imageId) async {
    try {
      Logger.info('Deleting image: $imageId');
      
      await _apiClient.delete('/images/$imageId');
      
      Logger.info('Image deleted successfully');
    } catch (e) {
      Logger.error('Image deletion failed', error: e);
      rethrow;
    }
  }

  /// Delete multiple images
  Future<void> deleteImages(List<String> imageIds) async {
    try {
      Logger.info('Deleting ${imageIds.length} images');
      
      await _apiClient.post('/images/delete-batch', data: {
        'imageIds': imageIds,
      });
      
      Logger.info('Images deleted successfully');
    } catch (e) {
      Logger.error('Batch image deletion failed', error: e);
      rethrow;
    }
  }
}

class ImageUploadResult {
  final String imageId;
  final String? originalUrl;
  final String? thumbnailUrl;
  final String? processedUrl;
  final String? backgroundRemovedUrl;

  ImageUploadResult({
    required this.imageId,
    this.originalUrl,
    this.thumbnailUrl,
    this.processedUrl,
    this.backgroundRemovedUrl,
  });
}