import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:dio/dio.dart';
import 'package:image/image.dart' as img;
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

/// Advanced image caching service with multiple strategies
class ImageCacheService {
  static const String _cacheDirectoryName = 'koutu_image_cache';
  static const int _maxCacheSize = 500 * 1024 * 1024; // 500MB
  static const int _maxMemoryCacheSize = 50 * 1024 * 1024; // 50MB
  static const Duration _defaultCacheDuration = Duration(days: 30);
  
  // In-memory cache for frequently accessed images
  static final Map<String, Uint8List> _memoryCache = {};
  static int _memoryCacheSize = 0;
  
  // Cache metadata
  static final Map<String, CacheMetadata> _cacheMetadata = {};
  static bool _isInitialized = false;
  
  final Dio _dio = Dio();
  
  /// Initialize the cache service
  static Future<void> initialize() async {
    if (_isInitialized) return;
    
    await _loadCacheMetadata();
    await _cleanupExpiredCache();
    _isInitialized = true;
  }
  
  /// Get cached image with multiple fallback strategies
  Future<Uint8List?> getCachedImage(
    String imageUrl, {
    ImageCacheStrategy strategy = ImageCacheStrategy.balanced,
    Size? targetSize,
    int? quality,
    bool forceRefresh = false,
  }) async {
    await initialize();
    
    final cacheKey = _generateCacheKey(imageUrl, targetSize, quality);
    
    // Check if refresh is forced
    if (forceRefresh) {
      await _removeFromCache(cacheKey);
    }
    
    // Strategy 1: Check memory cache
    if (_memoryCache.containsKey(cacheKey)) {
      _updateAccessTime(cacheKey);
      return _memoryCache[cacheKey];
    }
    
    // Strategy 2: Check disk cache
    final diskImage = await _loadFromDisk(cacheKey);
    if (diskImage != null) {
      _updateAccessTime(cacheKey);
      
      // Add to memory cache based on strategy
      if (strategy.shouldCacheInMemory) {
        await _addToMemoryCache(cacheKey, diskImage);
      }
      
      return diskImage;
    }
    
    // Strategy 3: Download and cache
    try {
      final imageData = await _downloadImage(imageUrl);
      
      if (imageData != null) {
        // Process image based on requirements
        final processedImage = await _processImage(
          imageData,
          targetSize: targetSize,
          quality: quality,
        );
        
        // Cache based on strategy
        await _cacheImage(cacheKey, processedImage, imageUrl, strategy);
        
        return processedImage;
      }
    } catch (e) {
      debugPrint('Error downloading image: $e');
    }
    
    return null;
  }
  
  /// Preload images for better performance
  Future<void> preloadImages(
    List<String> imageUrls, {
    ImageCacheStrategy strategy = ImageCacheStrategy.aggressive,
    Size? targetSize,
    int? quality,
  }) async {
    await initialize();
    
    // Use parallel loading for better performance
    final futures = imageUrls.map((url) => getCachedImage(
      url,
      strategy: strategy,
      targetSize: targetSize,
      quality: quality,
    ));
    
    await Future.wait(futures);
  }
  
  /// Get cache statistics
  static Future<CacheStatistics> getCacheStatistics() async {
    await initialize();
    
    final directory = await _getCacheDirectory();
    final files = directory.listSync();
    
    int totalSize = 0;
    int fileCount = 0;
    
    for (final file in files) {
      if (file is File) {
        totalSize += await file.length();
        fileCount++;
      }
    }
    
    return CacheStatistics(
      totalSize: totalSize,
      memoryCacheSize: _memoryCacheSize,
      fileCount: fileCount,
      memoryItemCount: _memoryCache.length,
      metadataCount: _cacheMetadata.length,
    );
  }
  
  /// Clear cache based on strategy
  static Future<void> clearCache({
    CacheClearStrategy strategy = CacheClearStrategy.all,
    DateTime? olderThan,
  }) async {
    await initialize();
    
    switch (strategy) {
      case CacheClearStrategy.all:
        await _clearAllCache();
        break;
      case CacheClearStrategy.memory:
        _clearMemoryCache();
        break;
      case CacheClearStrategy.disk:
        await _clearDiskCache();
        break;
      case CacheClearStrategy.expired:
        await _cleanupExpiredCache();
        break;
      case CacheClearStrategy.leastRecentlyUsed:
        await _clearLRUCache();
        break;
      case CacheClearStrategy.olderThan:
        if (olderThan != null) {
          await _clearCacheOlderThan(olderThan);
        }
        break;
    }
    
    await _saveCacheMetadata();
  }
  
  /// Optimize cache for better performance
  static Future<void> optimizeCache() async {
    await initialize();
    
    // Remove expired items
    await _cleanupExpiredCache();
    
    // Remove least recently used items if cache is too large
    final stats = await getCacheStatistics();
    if (stats.totalSize > _maxCacheSize) {
      await _clearLRUCache(targetSize: _maxCacheSize * 0.8);
    }
    
    // Optimize memory cache
    if (_memoryCacheSize > _maxMemoryCacheSize) {
      _optimizeMemoryCache();
    }
    
    await _saveCacheMetadata();
  }
  
  // Private helper methods
  
  static String _generateCacheKey(String url, Size? size, int? quality) {
    final keyData = '$url${size?.width ?? ''}${size?.height ?? ''}${quality ?? ''}';
    final bytes = utf8.encode(keyData);
    final digest = md5.convert(bytes);
    return digest.toString();
  }
  
  static Future<Directory> _getCacheDirectory() async {
    final directory = await getApplicationDocumentsDirectory();
    final cacheDir = Directory('${directory.path}/$_cacheDirectoryName');
    
    if (!await cacheDir.exists()) {
      await cacheDir.create(recursive: true);
    }
    
    return cacheDir;
  }
  
  Future<Uint8List?> _downloadImage(String url) async {
    try {
      final response = await _dio.get<List<int>>(
        url,
        options: Options(
          responseType: ResponseType.bytes,
          receiveTimeout: const Duration(seconds: 30),
        ),
      );
      
      if (response.statusCode == 200 && response.data != null) {
        return Uint8List.fromList(response.data!);
      }
    } catch (e) {
      debugPrint('Error downloading image from $url: $e');
    }
    
    return null;
  }
  
  Future<Uint8List> _processImage(
    Uint8List imageData, {
    Size? targetSize,
    int? quality,
  }) async {
    if (targetSize == null && quality == null) {
      return imageData;
    }
    
    return await compute(_processImageIsolate, {
      'data': imageData,
      'width': targetSize?.width.toInt(),
      'height': targetSize?.height.toInt(),
      'quality': quality,
    });
  }
  
  static Uint8List _processImageIsolate(Map<String, dynamic> params) {
    final imageData = params['data'] as Uint8List;
    final width = params['width'] as int?;
    final height = params['height'] as int?;
    final quality = params['quality'] as int?;
    
    var image = img.decodeImage(imageData);
    if (image == null) return imageData;
    
    // Resize if needed
    if (width != null || height != null) {
      image = img.copyResize(
        image,
        width: width,
        height: height,
        interpolation: img.Interpolation.linear,
      );
    }
    
    // Encode with quality
    if (image.format == img.Format.jpg || image.format == img.Format.jpeg) {
      return Uint8List.fromList(
        img.encodeJpg(image, quality: quality ?? 85),
      );
    } else {
      return Uint8List.fromList(
        img.encodePng(image, level: quality ?? 6),
      );
    }
  }
  
  Future<void> _cacheImage(
    String cacheKey,
    Uint8List imageData,
    String originalUrl,
    ImageCacheStrategy strategy,
  ) async {
    // Save to disk
    await _saveToDisk(cacheKey, imageData);
    
    // Update metadata
    _cacheMetadata[cacheKey] = CacheMetadata(
      key: cacheKey,
      url: originalUrl,
      size: imageData.length,
      createdAt: DateTime.now(),
      lastAccessedAt: DateTime.now(),
      accessCount: 1,
      strategy: strategy,
    );
    
    // Add to memory cache based on strategy
    if (strategy.shouldCacheInMemory) {
      await _addToMemoryCache(cacheKey, imageData);
    }
    
    await _saveCacheMetadata();
  }
  
  static Future<void> _addToMemoryCache(String key, Uint8List data) async {
    // Check if we need to make space
    if (_memoryCacheSize + data.length > _maxMemoryCacheSize) {
      _optimizeMemoryCache(requiredSpace: data.length);
    }
    
    _memoryCache[key] = data;
    _memoryCacheSize += data.length;
  }
  
  static void _optimizeMemoryCache({int requiredSpace = 0}) {
    if (_memoryCache.isEmpty) return;
    
    // Sort by last access time
    final sortedEntries = _cacheMetadata.entries
        .where((entry) => _memoryCache.containsKey(entry.key))
        .toList()
      ..sort((a, b) => a.value.lastAccessedAt.compareTo(b.value.lastAccessedAt));
    
    // Remove least recently used items
    while (_memoryCacheSize + requiredSpace > _maxMemoryCacheSize && 
           sortedEntries.isNotEmpty) {
      final entry = sortedEntries.removeAt(0);
      final data = _memoryCache.remove(entry.key);
      if (data != null) {
        _memoryCacheSize -= data.length;
      }
    }
  }
  
  static Future<Uint8List?> _loadFromDisk(String cacheKey) async {
    try {
      final cacheDir = await _getCacheDirectory();
      final file = File('${cacheDir.path}/$cacheKey');
      
      if (await file.exists()) {
        return await file.readAsBytes();
      }
    } catch (e) {
      debugPrint('Error loading from disk: $e');
    }
    
    return null;
  }
  
  static Future<void> _saveToDisk(String cacheKey, Uint8List data) async {
    try {
      final cacheDir = await _getCacheDirectory();
      final file = File('${cacheDir.path}/$cacheKey');
      await file.writeAsBytes(data);
    } catch (e) {
      debugPrint('Error saving to disk: $e');
    }
  }
  
  static void _updateAccessTime(String cacheKey) {
    if (_cacheMetadata.containsKey(cacheKey)) {
      _cacheMetadata[cacheKey] = _cacheMetadata[cacheKey]!.copyWith(
        lastAccessedAt: DateTime.now(),
        accessCount: _cacheMetadata[cacheKey]!.accessCount + 1,
      );
    }
  }
  
  static Future<void> _removeFromCache(String cacheKey) async {
    // Remove from memory
    final memoryData = _memoryCache.remove(cacheKey);
    if (memoryData != null) {
      _memoryCacheSize -= memoryData.length;
    }
    
    // Remove from disk
    try {
      final cacheDir = await _getCacheDirectory();
      final file = File('${cacheDir.path}/$cacheKey');
      if (await file.exists()) {
        await file.delete();
      }
    } catch (e) {
      debugPrint('Error removing from cache: $e');
    }
    
    // Remove metadata
    _cacheMetadata.remove(cacheKey);
  }
  
  static Future<void> _clearAllCache() async {
    _clearMemoryCache();
    await _clearDiskCache();
    _cacheMetadata.clear();
  }
  
  static void _clearMemoryCache() {
    _memoryCache.clear();
    _memoryCacheSize = 0;
  }
  
  static Future<void> _clearDiskCache() async {
    try {
      final cacheDir = await _getCacheDirectory();
      if (await cacheDir.exists()) {
        await cacheDir.delete(recursive: true);
      }
    } catch (e) {
      debugPrint('Error clearing disk cache: $e');
    }
  }
  
  static Future<void> _cleanupExpiredCache() async {
    final now = DateTime.now();
    final expiredKeys = <String>[];
    
    _cacheMetadata.forEach((key, metadata) {
      if (now.difference(metadata.createdAt) > _defaultCacheDuration) {
        expiredKeys.add(key);
      }
    });
    
    for (final key in expiredKeys) {
      await _removeFromCache(key);
    }
  }
  
  static Future<void> _clearLRUCache({int? targetSize}) async {
    final sortedEntries = _cacheMetadata.entries.toList()
      ..sort((a, b) => a.value.lastAccessedAt.compareTo(b.value.lastAccessedAt));
    
    int currentSize = 0;
    for (final entry in _cacheMetadata.values) {
      currentSize += entry.size;
    }
    
    final target = targetSize ?? (_maxCacheSize * 0.8).toInt();
    
    while (currentSize > target && sortedEntries.isNotEmpty) {
      final entry = sortedEntries.removeAt(0);
      await _removeFromCache(entry.key);
      currentSize -= entry.value.size;
    }
  }
  
  static Future<void> _clearCacheOlderThan(DateTime date) async {
    final keysToRemove = <String>[];
    
    _cacheMetadata.forEach((key, metadata) {
      if (metadata.createdAt.isBefore(date)) {
        keysToRemove.add(key);
      }
    });
    
    for (final key in keysToRemove) {
      await _removeFromCache(key);
    }
  }
  
  static Future<void> _loadCacheMetadata() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final metadataJson = prefs.getString('image_cache_metadata');
      
      if (metadataJson != null) {
        final Map<String, dynamic> data = json.decode(metadataJson);
        data.forEach((key, value) {
          _cacheMetadata[key] = CacheMetadata.fromJson(value);
        });
      }
    } catch (e) {
      debugPrint('Error loading cache metadata: $e');
    }
  }
  
  static Future<void> _saveCacheMetadata() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final data = <String, dynamic>{};
      
      _cacheMetadata.forEach((key, metadata) {
        data[key] = metadata.toJson();
      });
      
      await prefs.setString('image_cache_metadata', json.encode(data));
    } catch (e) {
      debugPrint('Error saving cache metadata: $e');
    }
  }
}

/// Image cache strategies
enum ImageCacheStrategy {
  /// Aggressive caching - stores in memory and disk
  aggressive(shouldCacheInMemory: true, priority: 3),
  
  /// Balanced caching - stores in disk, memory for frequently used
  balanced(shouldCacheInMemory: false, priority: 2),
  
  /// Conservative caching - disk only for space efficiency
  conservative(shouldCacheInMemory: false, priority: 1);
  
  final bool shouldCacheInMemory;
  final int priority;
  
  const ImageCacheStrategy({
    required this.shouldCacheInMemory,
    required this.priority,
  });
}

/// Cache clear strategies
enum CacheClearStrategy {
  all,
  memory,
  disk,
  expired,
  leastRecentlyUsed,
  olderThan,
}

/// Cache metadata
class CacheMetadata {
  final String key;
  final String url;
  final int size;
  final DateTime createdAt;
  final DateTime lastAccessedAt;
  final int accessCount;
  final ImageCacheStrategy strategy;
  
  CacheMetadata({
    required this.key,
    required this.url,
    required this.size,
    required this.createdAt,
    required this.lastAccessedAt,
    required this.accessCount,
    required this.strategy,
  });
  
  CacheMetadata copyWith({
    DateTime? lastAccessedAt,
    int? accessCount,
  }) {
    return CacheMetadata(
      key: key,
      url: url,
      size: size,
      createdAt: createdAt,
      lastAccessedAt: lastAccessedAt ?? this.lastAccessedAt,
      accessCount: accessCount ?? this.accessCount,
      strategy: strategy,
    );
  }
  
  Map<String, dynamic> toJson() => {
    'key': key,
    'url': url,
    'size': size,
    'createdAt': createdAt.toIso8601String(),
    'lastAccessedAt': lastAccessedAt.toIso8601String(),
    'accessCount': accessCount,
    'strategy': strategy.index,
  };
  
  factory CacheMetadata.fromJson(Map<String, dynamic> json) => CacheMetadata(
    key: json['key'],
    url: json['url'],
    size: json['size'],
    createdAt: DateTime.parse(json['createdAt']),
    lastAccessedAt: DateTime.parse(json['lastAccessedAt']),
    accessCount: json['accessCount'],
    strategy: ImageCacheStrategy.values[json['strategy']],
  );
}

/// Cache statistics
class CacheStatistics {
  final int totalSize;
  final int memoryCacheSize;
  final int fileCount;
  final int memoryItemCount;
  final int metadataCount;
  
  CacheStatistics({
    required this.totalSize,
    required this.memoryCacheSize,
    required this.fileCount,
    required this.memoryItemCount,
    required this.metadataCount,
  });
  
  int get diskCacheSize => totalSize - memoryCacheSize;
  double get averageFileSize => fileCount > 0 ? totalSize / fileCount : 0;
  String get formattedTotalSize => _formatBytes(totalSize);
  String get formattedMemorySize => _formatBytes(memoryCacheSize);
  String get formattedDiskSize => _formatBytes(diskCacheSize);
  
  static String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / 1024 / 1024).toStringAsFixed(1)} MB';
    return '${(bytes / 1024 / 1024 / 1024).toStringAsFixed(1)} GB';
  }
}