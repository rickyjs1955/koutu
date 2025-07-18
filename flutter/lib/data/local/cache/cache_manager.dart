import 'dart:typed_data';

import 'package:flutter_cache_manager/flutter_cache_manager.dart';
import 'package:injectable/injectable.dart';

@lazySingleton
class AppCacheManager {
  static const key = 'koutu_cache';
  
  late final CacheManager _cacheManager;

  AppCacheManager() {
    _cacheManager = CacheManager(
      Config(
        key,
        stalePeriod: const Duration(days: 7),
        maxNrOfCacheObjects: 500,
        repo: JsonCacheInfoRepository(databaseName: key),
        fileService: HttpFileService(),
      ),
    );
  }

  /// Get the cache manager instance
  CacheManager get instance => _cacheManager;

  /// Download and cache a file
  Future<FileInfo> downloadFile(String url, {String? key}) async {
    return await _cacheManager.downloadFile(url, key: key);
  }

  /// Get a file from cache
  Future<FileInfo?> getFileFromCache(String key) async {
    return await _cacheManager.getFileFromCache(key);
  }

  /// Get a file from cache or download if not exists
  Future<FileInfo> getSingleFile(String url, {String? key}) async {
    return await _cacheManager.getSingleFile(url, key: key);
  }

  /// Put a file in cache
  Future<void> putFile(String url, Uint8List fileBytes, {String? key}) async {
    await _cacheManager.putFile(url, fileBytes, key: key);
  }

  /// Remove a file from cache
  Future<void> removeFile(String key) async {
    await _cacheManager.removeFile(key);
  }

  /// Clear all cache
  Future<void> clearCache() async {
    await _cacheManager.emptyCache();
  }

  /// Get cache size
  Future<int> getCacheSize() async {
    final cacheInfo = await _cacheManager.getDownloadedFileCount();
    return cacheInfo ?? 0;
  }

  /// Create a custom cache manager for specific purposes
  static CacheManager createCustomCacheManager({
    required String key,
    Duration stalePeriod = const Duration(days: 7),
    int maxNrOfCacheObjects = 200,
  }) {
    return CacheManager(
      Config(
        key,
        stalePeriod: stalePeriod,
        maxNrOfCacheObjects: maxNrOfCacheObjects,
        repo: JsonCacheInfoRepository(databaseName: key),
        fileService: HttpFileService(),
      ),
    );
  }
}

/// Cache manager for user profile images
@lazySingleton
class ProfileImageCacheManager {
  static const key = 'profile_images';
  
  late final CacheManager _cacheManager;

  ProfileImageCacheManager() {
    _cacheManager = AppCacheManager.createCustomCacheManager(
      key: key,
      stalePeriod: const Duration(days: 30),
      maxNrOfCacheObjects: 100,
    );
  }

  CacheManager get instance => _cacheManager;
}

/// Cache manager for garment images with longer cache period
@lazySingleton
class GarmentImageCacheManager {
  static const key = 'garment_images';
  
  late final CacheManager _cacheManager;

  GarmentImageCacheManager() {
    _cacheManager = AppCacheManager.createCustomCacheManager(
      key: key,
      stalePeriod: const Duration(days: 90),
      maxNrOfCacheObjects: 1000,
    );
  }

  CacheManager get instance => _cacheManager;
}