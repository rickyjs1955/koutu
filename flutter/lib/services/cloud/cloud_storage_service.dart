import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:dio/dio.dart';
import 'package:path/path.dart' as path;
import 'package:koutu/core/config/environment.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:dartz/dartz.dart';
import 'package:image/image.dart' as img;
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:mime/mime.dart';

/// Service for cloud storage operations
class CloudStorageService {
  final Dio _dio;
  final AuthService _authService;
  
  // Upload progress tracking
  final Map<String, UploadProgress> _uploadProgress = {};
  final Map<String, CancelToken> _uploadCancelTokens = {};
  
  // Download cache
  final Map<String, Uint8List> _downloadCache = {};
  static const int _maxCacheSize = 100 * 1024 * 1024; // 100MB
  int _currentCacheSize = 0;
  
  CloudStorageService({
    required Dio dio,
    required AuthService authService,
  })  : _dio = dio,
        _authService = authService;
  
  /// Upload image to cloud storage
  Future<Either<Failure, CloudImage>> uploadImage({
    required File imageFile,
    required String folder,
    String? customName,
    ImageProcessingOptions? processingOptions,
    Function(double)? onProgress,
  }) async {
    try {
      // Generate unique filename
      final fileName = customName ?? _generateFileName(imageFile);
      final uploadPath = '$folder/$fileName';
      
      // Process image if options provided
      Uint8List imageData;
      if (processingOptions != null) {
        imageData = await _processImage(imageFile, processingOptions);
      } else {
        imageData = await imageFile.readAsBytes();
      }
      
      // Create upload request
      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(
          imageData,
          filename: fileName,
          contentType: DioMediaType.parse(
            lookupMimeType(imageFile.path) ?? 'image/jpeg',
          ),
        ),
        'path': uploadPath,
        'metadata': json.encode({
          'originalName': path.basename(imageFile.path),
          'size': imageData.length,
          'uploadedAt': DateTime.now().toIso8601String(),
        }),
      });
      
      // Create cancel token
      final cancelToken = CancelToken();
      final uploadId = DateTime.now().millisecondsSinceEpoch.toString();
      _uploadCancelTokens[uploadId] = cancelToken;
      
      // Track progress
      _uploadProgress[uploadId] = UploadProgress(
        id: uploadId,
        fileName: fileName,
        totalBytes: imageData.length,
        uploadedBytes: 0,
        status: UploadStatus.uploading,
      );
      
      // Get auth token
      final authToken = await _authService.getAuthToken();
      
      // Upload file
      final response = await _dio.post(
        '${Environment.apiUrl}/storage/upload',
        data: formData,
        cancelToken: cancelToken,
        options: Options(
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
        onSendProgress: (sent, total) {
          final progress = sent / total;
          _updateUploadProgress(uploadId, sent, total);
          onProgress?.call(progress);
        },
      );
      
      if (response.statusCode == 200) {
        final cloudImage = CloudImage.fromJson(response.data);
        
        // Update progress to completed
        _updateUploadProgress(
          uploadId,
          imageData.length,
          imageData.length,
          status: UploadStatus.completed,
        );
        
        // Clean up
        _uploadCancelTokens.remove(uploadId);
        
        return Right(cloudImage);
      } else {
        throw Exception('Upload failed with status: ${response.statusCode}');
      }
    } catch (e) {
      if (e is DioException && e.type == DioExceptionType.cancel) {
        return Left(ServerFailure('Upload cancelled'));
      }
      return Left(ServerFailure('Failed to upload image: $e'));
    }
  }
  
  /// Upload multiple images in batch
  Future<Either<Failure, List<CloudImage>>> uploadImages({
    required List<File> imageFiles,
    required String folder,
    ImageProcessingOptions? processingOptions,
    Function(int, int, double)? onProgress, // current, total, progress
  }) async {
    final results = <CloudImage>[];
    final errors = <String>[];
    
    for (var i = 0; i < imageFiles.length; i++) {
      final result = await uploadImage(
        imageFile: imageFiles[i],
        folder: folder,
        processingOptions: processingOptions,
        onProgress: (progress) {
          onProgress?.call(i + 1, imageFiles.length, progress);
        },
      );
      
      result.fold(
        (failure) => errors.add(failure.message),
        (cloudImage) => results.add(cloudImage),
      );
    }
    
    if (errors.isNotEmpty) {
      return Left(ServerFailure('Failed to upload ${errors.length} images'));
    }
    
    return Right(results);
  }
  
  /// Download image from cloud storage
  Future<Either<Failure, Uint8List>> downloadImage({
    required String imageUrl,
    bool useCache = true,
  }) async {
    try {
      // Check cache
      if (useCache && _downloadCache.containsKey(imageUrl)) {
        return Right(_downloadCache[imageUrl]!);
      }
      
      // Get auth token
      final authToken = await _authService.getAuthToken();
      
      // Download image
      final response = await _dio.get<List<int>>(
        imageUrl,
        options: Options(
          responseType: ResponseType.bytes,
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
      );
      
      if (response.statusCode == 200 && response.data != null) {
        final imageData = Uint8List.fromList(response.data!);
        
        // Add to cache
        if (useCache) {
          _addToCache(imageUrl, imageData);
        }
        
        return Right(imageData);
      } else {
        throw Exception('Download failed with status: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to download image: $e'));
    }
  }
  
  /// Delete image from cloud storage
  Future<Either<Failure, void>> deleteImage({
    required String imageUrl,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.delete(
        imageUrl,
        options: Options(
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
      );
      
      if (response.statusCode == 200) {
        // Remove from cache
        _removeFromCache(imageUrl);
        return const Right(null);
      } else {
        throw Exception('Delete failed with status: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to delete image: $e'));
    }
  }
  
  /// Create backup of user data
  Future<Either<Failure, CloudBackup>> createBackup({
    required BackupData backupData,
    Function(double)? onProgress,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      // Compress backup data
      final compressedData = await _compressBackupData(backupData);
      
      // Create multipart upload
      final formData = FormData.fromMap({
        'backup': MultipartFile.fromBytes(
          compressedData,
          filename: 'backup_${DateTime.now().millisecondsSinceEpoch}.zip',
        ),
        'metadata': json.encode({
          'version': backupData.version,
          'createdAt': DateTime.now().toIso8601String(),
          'itemCount': backupData.totalItems,
          'checksum': _calculateChecksum(compressedData),
        }),
      });
      
      // Upload backup
      final response = await _dio.post(
        '${Environment.apiUrl}/backup/create',
        data: formData,
        options: Options(
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
        onSendProgress: (sent, total) {
          onProgress?.call(sent / total);
        },
      );
      
      if (response.statusCode == 200) {
        return Right(CloudBackup.fromJson(response.data));
      } else {
        throw Exception('Backup failed with status: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to create backup: $e'));
    }
  }
  
  /// Restore backup from cloud
  Future<Either<Failure, BackupData>> restoreBackup({
    required String backupId,
    Function(double)? onProgress,
  }) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      // Download backup
      final response = await _dio.get<List<int>>(
        '${Environment.apiUrl}/backup/$backupId',
        options: Options(
          responseType: ResponseType.bytes,
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
        onReceiveProgress: (received, total) {
          if (total != -1) {
            onProgress?.call(received / total);
          }
        },
      );
      
      if (response.statusCode == 200 && response.data != null) {
        // Decompress and parse backup data
        final backupData = await _decompressBackupData(
          Uint8List.fromList(response.data!),
        );
        
        return Right(backupData);
      } else {
        throw Exception('Restore failed with status: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to restore backup: $e'));
    }
  }
  
  /// List available backups
  Future<Either<Failure, List<CloudBackup>>> listBackups() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.get(
        '${Environment.apiUrl}/backup/list',
        options: Options(
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
      );
      
      if (response.statusCode == 200) {
        final backups = (response.data['backups'] as List)
            .map((json) => CloudBackup.fromJson(json))
            .toList();
        
        return Right(backups);
      } else {
        throw Exception('Failed to list backups: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to list backups: $e'));
    }
  }
  
  /// Get storage statistics
  Future<Either<Failure, StorageStatistics>> getStorageStatistics() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.get(
        '${Environment.apiUrl}/storage/stats',
        options: Options(
          headers: {
            'Authorization': 'Bearer $authToken',
          },
        ),
      );
      
      if (response.statusCode == 200) {
        return Right(StorageStatistics.fromJson(response.data));
      } else {
        throw Exception('Failed to get statistics: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get storage statistics: $e'));
    }
  }
  
  /// Cancel upload
  void cancelUpload(String uploadId) {
    _uploadCancelTokens[uploadId]?.cancel('User cancelled');
    _uploadCancelTokens.remove(uploadId);
    _updateUploadProgress(
      uploadId,
      0,
      0,
      status: UploadStatus.cancelled,
    );
  }
  
  /// Get upload progress
  UploadProgress? getUploadProgress(String uploadId) {
    return _uploadProgress[uploadId];
  }
  
  /// Clear download cache
  void clearCache() {
    _downloadCache.clear();
    _currentCacheSize = 0;
  }
  
  // Private methods
  
  String _generateFileName(File file) {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final extension = path.extension(file.path);
    final hash = md5.convert(file.readAsBytesSync()).toString().substring(0, 8);
    return '${timestamp}_$hash$extension';
  }
  
  Future<Uint8List> _processImage(
    File imageFile,
    ImageProcessingOptions options,
  ) async {
    return await compute(_processImageIsolate, {
      'data': await imageFile.readAsBytes(),
      'options': options.toJson(),
    });
  }
  
  static Uint8List _processImageIsolate(Map<String, dynamic> params) {
    final imageData = params['data'] as Uint8List;
    final options = ImageProcessingOptions.fromJson(params['options']);
    
    var image = img.decodeImage(imageData);
    if (image == null) return imageData;
    
    // Resize if needed
    if (options.maxWidth != null || options.maxHeight != null) {
      image = img.copyResize(
        image,
        width: options.maxWidth,
        height: options.maxHeight,
        maintainAspect: true,
      );
    }
    
    // Compress
    final quality = options.quality ?? 85;
    
    if (options.format == ImageFormat.jpeg) {
      return Uint8List.fromList(img.encodeJpg(image, quality: quality));
    } else if (options.format == ImageFormat.png) {
      return Uint8List.fromList(img.encodePng(image, level: 6));
    } else if (options.format == ImageFormat.webp) {
      return Uint8List.fromList(img.encodeJpg(image, quality: quality));
    }
    
    return imageData;
  }
  
  void _updateUploadProgress(
    String uploadId,
    int uploaded,
    int total, {
    UploadStatus? status,
  }) {
    _uploadProgress[uploadId] = UploadProgress(
      id: uploadId,
      fileName: _uploadProgress[uploadId]?.fileName ?? '',
      totalBytes: total,
      uploadedBytes: uploaded,
      status: status ?? _uploadProgress[uploadId]?.status ?? UploadStatus.uploading,
    );
  }
  
  void _addToCache(String key, Uint8List data) {
    // Remove oldest items if cache is full
    while (_currentCacheSize + data.length > _maxCacheSize && 
           _downloadCache.isNotEmpty) {
      final oldestKey = _downloadCache.keys.first;
      final oldestData = _downloadCache.remove(oldestKey);
      if (oldestData != null) {
        _currentCacheSize -= oldestData.length;
      }
    }
    
    _downloadCache[key] = data;
    _currentCacheSize += data.length;
  }
  
  void _removeFromCache(String key) {
    final data = _downloadCache.remove(key);
    if (data != null) {
      _currentCacheSize -= data.length;
    }
  }
  
  Future<Uint8List> _compressBackupData(BackupData data) async {
    // In real implementation, this would use a compression library
    final jsonData = json.encode(data.toJson());
    return Uint8List.fromList(utf8.encode(jsonData));
  }
  
  Future<BackupData> _decompressBackupData(Uint8List compressedData) async {
    // In real implementation, this would use a compression library
    final jsonData = utf8.decode(compressedData);
    return BackupData.fromJson(json.decode(jsonData));
  }
  
  String _calculateChecksum(Uint8List data) {
    return md5.convert(data).toString();
  }
}

/// Cloud image model
class CloudImage {
  final String id;
  final String url;
  final String thumbnailUrl;
  final int size;
  final String contentType;
  final Map<String, dynamic> metadata;
  final DateTime createdAt;
  
  const CloudImage({
    required this.id,
    required this.url,
    required this.thumbnailUrl,
    required this.size,
    required this.contentType,
    required this.metadata,
    required this.createdAt,
  });
  
  factory CloudImage.fromJson(Map<String, dynamic> json) {
    return CloudImage(
      id: json['id'],
      url: json['url'],
      thumbnailUrl: json['thumbnailUrl'],
      size: json['size'],
      contentType: json['contentType'],
      metadata: json['metadata'] ?? {},
      createdAt: DateTime.parse(json['createdAt']),
    );
  }
}

/// Upload progress
class UploadProgress {
  final String id;
  final String fileName;
  final int totalBytes;
  final int uploadedBytes;
  final UploadStatus status;
  
  const UploadProgress({
    required this.id,
    required this.fileName,
    required this.totalBytes,
    required this.uploadedBytes,
    required this.status,
  });
  
  double get progress => totalBytes > 0 ? uploadedBytes / totalBytes : 0;
}

/// Upload status
enum UploadStatus {
  preparing,
  uploading,
  completed,
  failed,
  cancelled,
}

/// Image processing options
class ImageProcessingOptions {
  final int? maxWidth;
  final int? maxHeight;
  final int? quality;
  final ImageFormat format;
  final bool removeMetadata;
  
  const ImageProcessingOptions({
    this.maxWidth,
    this.maxHeight,
    this.quality,
    this.format = ImageFormat.jpeg,
    this.removeMetadata = true,
  });
  
  Map<String, dynamic> toJson() => {
    'maxWidth': maxWidth,
    'maxHeight': maxHeight,
    'quality': quality,
    'format': format.name,
    'removeMetadata': removeMetadata,
  };
  
  factory ImageProcessingOptions.fromJson(Map<String, dynamic> json) {
    return ImageProcessingOptions(
      maxWidth: json['maxWidth'],
      maxHeight: json['maxHeight'],
      quality: json['quality'],
      format: ImageFormat.values.firstWhere(
        (f) => f.name == json['format'],
        orElse: () => ImageFormat.jpeg,
      ),
      removeMetadata: json['removeMetadata'] ?? true,
    );
  }
}

/// Image format
enum ImageFormat {
  jpeg,
  png,
  webp,
}

/// Backup data model
class BackupData {
  final String version;
  final DateTime createdAt;
  final int totalItems;
  final Map<String, dynamic> data;
  
  const BackupData({
    required this.version,
    required this.createdAt,
    required this.totalItems,
    required this.data,
  });
  
  Map<String, dynamic> toJson() => {
    'version': version,
    'createdAt': createdAt.toIso8601String(),
    'totalItems': totalItems,
    'data': data,
  };
  
  factory BackupData.fromJson(Map<String, dynamic> json) {
    return BackupData(
      version: json['version'],
      createdAt: DateTime.parse(json['createdAt']),
      totalItems: json['totalItems'],
      data: json['data'],
    );
  }
}

/// Cloud backup model
class CloudBackup {
  final String id;
  final String userId;
  final String url;
  final int size;
  final String version;
  final DateTime createdAt;
  final Map<String, dynamic> metadata;
  
  const CloudBackup({
    required this.id,
    required this.userId,
    required this.url,
    required this.size,
    required this.version,
    required this.createdAt,
    required this.metadata,
  });
  
  factory CloudBackup.fromJson(Map<String, dynamic> json) {
    return CloudBackup(
      id: json['id'],
      userId: json['userId'],
      url: json['url'],
      size: json['size'],
      version: json['version'],
      createdAt: DateTime.parse(json['createdAt']),
      metadata: json['metadata'] ?? {},
    );
  }
}

/// Storage statistics
class StorageStatistics {
  final int totalStorage;
  final int usedStorage;
  final int imageCount;
  final int backupCount;
  final Map<String, int> breakdown;
  
  const StorageStatistics({
    required this.totalStorage,
    required this.usedStorage,
    required this.imageCount,
    required this.backupCount,
    required this.breakdown,
  });
  
  double get usagePercentage => totalStorage > 0 ? usedStorage / totalStorage : 0;
  int get availableStorage => totalStorage - usedStorage;
  
  factory StorageStatistics.fromJson(Map<String, dynamic> json) {
    return StorageStatistics(
      totalStorage: json['totalStorage'],
      usedStorage: json['usedStorage'],
      imageCount: json['imageCount'],
      backupCount: json['backupCount'],
      breakdown: Map<String, int>.from(json['breakdown'] ?? {}),
    );
  }
}