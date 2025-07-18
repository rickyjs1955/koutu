import 'dart:io';
import 'dart:typed_data';
import 'package:dio/dio.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/utils/logger.dart';
import 'package:koutu/data/network/api_client.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as path;

@lazySingleton
class BackgroundRemovalService {
  final ApiClient _apiClient;
  final Dio _dio;

  BackgroundRemovalService(this._apiClient, this._dio);

  /// Remove background from image using API
  Future<File> removeBackground(File imageFile) async {
    try {
      Logger.info('Starting background removal for: ${imageFile.path}');

      // Prepare multipart file
      final fileName = path.basename(imageFile.path);
      final formData = FormData.fromMap({
        'image': await MultipartFile.fromFile(
          imageFile.path,
          filename: fileName,
        ),
      });

      // Upload image for background removal
      final response = await _apiClient.post(
        '/images/remove-background',
        data: formData,
        options: Options(
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        ),
      );

      // Get processed image URL
      final processedUrl = response.data['processedUrl'] as String;
      
      // Download processed image
      final processedFile = await _downloadProcessedImage(processedUrl, fileName);
      
      Logger.info('Background removal completed');
      return processedFile;
    } catch (e) {
      Logger.error('Background removal failed', error: e);
      rethrow;
    }
  }

  /// Remove background from multiple images
  Future<List<BackgroundRemovalResult>> removeBackgroundBatch(
    List<File> imageFiles,
  ) async {
    final results = <BackgroundRemovalResult>[];

    for (final imageFile in imageFiles) {
      try {
        final processedFile = await removeBackground(imageFile);
        results.add(BackgroundRemovalResult(
          originalFile: imageFile,
          processedFile: processedFile,
          success: true,
        ));
      } catch (e) {
        results.add(BackgroundRemovalResult(
          originalFile: imageFile,
          processedFile: null,
          success: false,
          error: e.toString(),
        ));
      }
    }

    return results;
  }

  /// Check background removal status
  Future<BackgroundRemovalStatus> checkStatus(String jobId) async {
    try {
      final response = await _apiClient.get('/images/background-removal-status/$jobId');
      
      return BackgroundRemovalStatus(
        jobId: jobId,
        status: response.data['status'] as String,
        progress: response.data['progress'] as int?,
        processedUrl: response.data['processedUrl'] as String?,
        error: response.data['error'] as String?,
      );
    } catch (e) {
      Logger.error('Failed to check background removal status', error: e);
      rethrow;
    }
  }

  /// Process image locally using ML model (fallback)
  Future<File> removeBackgroundLocally(File imageFile) async {
    try {
      Logger.info('Starting local background removal');
      
      // TODO: Implement local ML model for background removal
      // This would use a TensorFlow Lite model or similar
      // For now, return the original file
      
      Logger.warning('Local background removal not implemented, returning original');
      return imageFile;
    } catch (e) {
      Logger.error('Local background removal failed', error: e);
      rethrow;
    }
  }

  /// Download processed image from URL
  Future<File> _downloadProcessedImage(String url, String originalFileName) async {
    try {
      final response = await _dio.get(
        url,
        options: Options(responseType: ResponseType.bytes),
      );

      final tempDir = await getTemporaryDirectory();
      final fileName = '${path.basenameWithoutExtension(originalFileName)}_no_bg.png';
      final filePath = path.join(tempDir.path, fileName);
      
      final file = File(filePath);
      await file.writeAsBytes(response.data as Uint8List);
      
      return file;
    } catch (e) {
      Logger.error('Failed to download processed image', error: e);
      rethrow;
    }
  }
}

class BackgroundRemovalResult {
  final File originalFile;
  final File? processedFile;
  final bool success;
  final String? error;

  BackgroundRemovalResult({
    required this.originalFile,
    required this.processedFile,
    required this.success,
    this.error,
  });
}

class BackgroundRemovalStatus {
  final String jobId;
  final String status; // pending, processing, completed, failed
  final int? progress; // 0-100
  final String? processedUrl;
  final String? error;

  BackgroundRemovalStatus({
    required this.jobId,
    required this.status,
    this.progress,
    this.processedUrl,
    this.error,
  });

  bool get isCompleted => status == 'completed';
  bool get isFailed => status == 'failed';
  bool get isProcessing => status == 'processing';
  bool get isPending => status == 'pending';
}